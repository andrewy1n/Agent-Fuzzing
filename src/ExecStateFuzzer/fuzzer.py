import yaml
import time
import json
from pathlib import Path
from typing import List
import random
from datetime import datetime

from .models import CrashResult, ExecutionResult, ExecutionStateSet, ExecutionOutcome, FuzzerResult, OperatorEffectivenessData, SessionData, TokenUsage
from .models import OperatorEffectivenessSummary
from .ql_emulation import execute_with_qiling
from .corpus_stat_tracker import CorpusStatTracker
from .mutation_engines.operator_client import Mutator
from .coverage_plateau_flow import CoveragePlateauFlow

class SeedQueue:
    def __init__(self):
        self.queue = []

    def add_seed(self, seed: bytes):
        self.queue.append(seed)

    def pop_seed(self) -> bytes:
        return self.queue.pop()

    def is_empty(self) -> bool:
        return len(self.queue) == 0

class Fuzzer:
    def __init__(self):
        self.run_config = yaml.safe_load(open('config.yaml'))
        self.seed_queue = SeedQueue()
        self.corpus_stat_tracker = CorpusStatTracker(MAP_SIZE=(1 << 16), config=self.run_config['corpus_stat_tracker'])
        output_cfg = self.run_config['output']

        output_root = output_cfg['dir']

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = Path(output_root) / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._popped_seeds: List[bytes] = []
        self.all_mutations: List[str] = []
        fcfg = self.run_config['fuzzer'] 
        self.seed_inputs = fcfg['seed_inputs']
        self.mutator = Mutator(config=fcfg['mutations'])
        self.coverage_plateau_flow = CoveragePlateauFlow(config=self.run_config['coverage_plateau_flow'], challenge_name=self.run_config['target']['cgc_binary'])

    def run(self):
        corpus_results: List[ExecutionResult] = []
        corpus_strings: set[str] = set[str]()
        session_mutations: List[str] = []
        session_results: List[ExecutionResult] = []
        crashes = []
        start_time = time.time()
        execution_count = 0
        execution_time = 0
        initial_seed_count = 0
        state_set: ExecutionStateSet = set()
        operator_effectiveness_data: List[OperatorEffectivenessData] = []

        for seed_value in self.seed_inputs:
            self.seed_queue.add_seed(seed_value)
        
        for initial_seed in self.seed_queue.queue:
            result = execute_with_qiling(initial_seed.encode('utf-8'), self.run_config)
            corpus_results.append(result)
            corpus_strings.add(initial_seed)
            if result.execution_outcome == ExecutionOutcome.CRASH:
                crashes.append(CrashResult(
                    iteration=execution_count,
                    input_data=initial_seed,
                    crash_info=result.crash_info,
                    execution_time=result.execution_time
                ))
            
            state_set.add(result.execution_state)
            execution_count += 1
            execution_time += result.execution_time
            
            self.corpus_stat_tracker.add_sample(result)
            initial_seed_count += 1

        self.corpus_stat_tracker.start_tracking()

        def _under_time_limit() -> bool:
            time_limit = self.run_config['fuzzer']['time_limit']
            if time_limit and time_limit > 0:
                return (time.time() - start_time) < time_limit
            return True

        stop_due_to_time = False
        num_mutations = self.run_config['fuzzer']['mutations']['num_mutations']

        while True:
            if (not _under_time_limit()):
                break
            
            if self.seed_queue.is_empty():
                self.seed_queue.add_seed(random.choice(self._popped_seeds))
            
            seed = self.seed_queue.pop_seed()
            self._popped_seeds.append(seed)
            
            mutations, operator_data = self.mutator.mutate(
                input=seed,
                num_mutations=num_mutations
            )
            
            accepted_results: list[ExecutionResult] = []

            for i, mutation in enumerate(mutations):
                self.all_mutations.append(mutation)

                if mutation in corpus_strings:
                    continue
                
                result = execute_with_qiling(mutation.encode('utf-8'), self.run_config)
                
                op_name = operator_data[i] if i < len(operator_data) else 'unknown'
                new_edge_coverage = False
                new_execution_state = False
                
                if result.execution_outcome == ExecutionOutcome.CRASH:
                    crashes.append(CrashResult(
                        iteration=execution_count,
                        input_data=mutation,
                        crash_info=result.crash_info,
                        execution_time=result.execution_time
                    ))
                
                # if the execution state is new, add it to the state set and the corpus results
                if result.execution_state not in state_set:
                    new_execution_state = True
                    
                    self.seed_queue.add_seed(mutation)
                    state_set.add(result.execution_state)
        
                    corpus_results.append(result)
                    corpus_strings.add(mutation)
                    self.corpus_stat_tracker.add_sample(result)

                    accepted_results.append(result)
     
                op_effectiveness = OperatorEffectivenessData(
                    operator_name=op_name,
                    mutation=mutation,
                    new_edge_coverage=new_edge_coverage,
                    new_execution_state=new_execution_state,
                    execution_time=result.execution_time,
                    iteration=execution_count
                )

                session_mutations.append(mutation)
                session_results.append(result)
                operator_effectiveness_data.append(op_effectiveness)

                execution_count += 1
                execution_time += result.execution_time
       
                if self.corpus_stat_tracker.is_coverage_plateau():
                    print(f"\nCoverage plateau detected after {self.run_config['corpus_stat_tracker']['coverage_plateau_timeout_seconds']} seconds without new coverage.")
                    operator_effectiveness = self.create_operator_effectiveness_summary(operator_effectiveness_data)

                    session_data = SessionData(
                        operator_effectiveness=operator_effectiveness,
                        mutations=session_mutations,
                        mutation_results=session_results,
                        execution_state_set=state_set
                    )

                    session_data_dir = Path(self.run_config['coverage_plateau_flow']['base_dir']) / datetime.now().strftime('%Y%m%d_%H%M%S')
                    
                    print(f"Saving session data to {session_data_dir}")
                    session_data_dir.mkdir(parents=True, exist_ok=True)

                    self.save_session_data(session_data, session_data_dir)
                    self.save_results(session_results, session_data_dir / 'corpus_results.json')
                    
                    self.coverage_plateau_flow.run(session_data_dir)

                    # reload config for any new definitions of state
                    self.run_config = yaml.safe_load(open('config.yaml'))
                    state_set = set()   # reset state

                    for seed_inject in self.run_config['fuzzer'].get('seed_injects', []):
                        if seed_inject in corpus_strings:
                            continue
                        
                        result = execute_with_qiling(seed_inject.encode('utf-8'), self.run_config)
                        corpus_results.append(result)
                        corpus_strings.add(seed_inject)
                        
                        if result.execution_outcome == ExecutionOutcome.CRASH:
                            crashes.append(CrashResult(
                                iteration=execution_count,
                                input_data=seed_inject,
                                crash_info=result.crash_info,
                                execution_time=result.execution_time
                            ))
                        
                        self.seed_queue.add_seed(seed_inject)
                        state_set.add(result.execution_state)
                        execution_count += 1
                        execution_time += result.execution_time
                        
                        self.corpus_stat_tracker.add_sample(result)

                    self.corpus_stat_tracker.reset_time_since_last_coverage()

                    # reset seed injects for next session
                    self.run_config['fuzzer']['seed_injects'] = []
                    yaml.dump(self.run_config, open('config.yaml', 'w'))

                    session_mutations = []
                    session_results = []
                    operator_effectiveness_data = []
                
                if not _under_time_limit():
                    stop_due_to_time = True
                    break
            
            if stop_due_to_time:
                break
        
        self.corpus_stat_tracker.stop()
        self.corpus_stat_tracker.force_snapshot()
        
        fuzzer_result = FuzzerResult(
            total_executions=execution_count,
            inital_seed_count=initial_seed_count,
            generated_corpus_count=len(corpus_strings) - initial_seed_count,
            total_mutations=len(self.all_mutations),
            unique_mutations=len(set(self.all_mutations)),
            crashes_found=len(crashes),
            total_execution_time_seconds=execution_time,
            average_execution_time_seconds=execution_time / execution_count if execution_count > 0 else 0,
            crash_rate=((len(crashes) / execution_count) if execution_count > 0 else 0),
            corpus_stat_result=self.corpus_stat_tracker.get_result(),
            token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0),  # No token usage for operators fuzzer
            coverage_over_time=self.corpus_stat_tracker.get_coverage_snapshots(),
        )

        self.print_summary(fuzzer_result, crashes)
        self.save_summary(fuzzer_result)
        self.save_results(corpus_results, self.output_dir / 'corpus_results.json')
        self.save_crashes(crashes)
        self.save_mutations()
        self.save_coverage_over_time(fuzzer_result.coverage_over_time)
    
    def print_summary(self, fuzzer_result: FuzzerResult, crashes: List[CrashResult]):
        print("\n=== Fuzzing Summary ===")
        print(f"Total executions: {fuzzer_result.total_executions}")
        print(f"Initial seed count: {fuzzer_result.inital_seed_count}")
        print(f"Generated corpus count: {fuzzer_result.generated_corpus_count}")
        print(f"Crashes found: {fuzzer_result.crashes_found}")
        print(f"Total execution time: {fuzzer_result.total_execution_time_seconds:.2f}s")
        print(f"Average execution time: {fuzzer_result.average_execution_time_seconds:.3f}s")
        print(f"Crash rate: {(fuzzer_result.crashes_found/fuzzer_result.total_executions)*100:.2f}%" if fuzzer_result.total_executions > 0 else "N/A")
        print(f"Total basic blocks covered: {fuzzer_result.corpus_stat_result.total_edges}")
        print(f"Total branch sites covered: {fuzzer_result.corpus_stat_result.total_branch_sites}")
        print(f"Unique instructions covered: {fuzzer_result.corpus_stat_result.total_unique_instructions}")
        print(f"Average pathlen blocks: {fuzzer_result.corpus_stat_result.avg_pathlen_blocks:.2f}")
        print(f"Max pathlen blocks: {fuzzer_result.corpus_stat_result.max_pathlen_blocks}")
        print(f"Average call depth: {fuzzer_result.corpus_stat_result.avg_calldepth:.2f}")
        print(f"Max call depth: {fuzzer_result.corpus_stat_result.max_calldepth}")
        
        print(f"Total mutations generated: {fuzzer_result.total_mutations}")
        print(f"Unique mutations generated: {fuzzer_result.unique_mutations}")
        
        if crashes:
            print("\n=== Crashes Found ===")
            for i, crash in enumerate(crashes, 1):
                print(f"Crash {i}:")
                print(f"  Iteration: {crash.iteration}")
                print(f"  Input: {crash.input_data}")
                print(f"  Time: {crash.execution_time:.3f}s")
                print(f"  Info: {crash.crash_info}")
    
    def save_crashes(self, crashes: List[CrashResult]):
        if crashes:
            path = self.output_dir / 'crashes.json'
            serializable = [c.model_dump() for c in crashes]
            with open(path, 'w') as f:
                json.dump(serializable, f, indent=2)
            print(f"\nSaved {len(crashes)} crashes to {path}")

    def _serialize_execution_state(self, execution_state: tuple) -> list:
        def _serialize_bytes(data):
            if isinstance(data, bytearray):
                data = bytes(data)
            try:
                decoded = data.decode('ascii')
                if decoded.isprintable():
                    return decoded
            except (UnicodeDecodeError, AttributeError):
                pass
            import base64
            return {
                '_type': 'bytes',
                '_data': base64.b64encode(data).decode('ascii')
            }
        
        result = []
        for item in execution_state:
            if isinstance(item, bytes):
                result.append(_serialize_bytes(item))
            elif isinstance(item, bytearray):
                result.append(_serialize_bytes(item))
            elif isinstance(item, tuple):
                serialized_tuple = []
                for sub_item in item:
                    if isinstance(sub_item, (bytes, bytearray)):
                        serialized_tuple.append(_serialize_bytes(sub_item))
                    else:
                        serialized_tuple.append(sub_item)
                result.append({
                    '_type': 'tuple',
                    '_data': serialized_tuple
                })
            else:
                result.append(item)
        return result

    def save_results(self, results: List[ExecutionResult], path: Path):
        def serialize_result(r: ExecutionResult) -> dict:
            return {
                'input_data': r.input_data.decode('utf-8', errors='replace'),
                'execution_outcome': r.execution_outcome.value,
                'execution_time': r.execution_time,
                'crash_info': r.crash_info,
                'execution_state': self._serialize_execution_state(r.execution_state),
                'stdout': r.stdout,
                'total_edges': sum(1 for b in r.cov_bitmap if b),
                'total_branch_sites': sum(1 for bt, bf in zip(r.branch_taken_bitmap, r.branch_fallthrough_bitmap) if bt or bf),
                'total_unique_instructions': len(r.instr_address_set),
                'total_instructions': r.total_instructions,
                'pathlen_blocks': r.pathlen_blocks,
                'call_depth': r.call_depth,
                'function_hotspots': [f.model_dump() for f in r.function_hotspots],
            }
        serializable = [serialize_result(r) for r in results]
        with open(path, 'w') as f:
            json.dump(serializable, f, indent=2)
        print(f"Saved {len(results)} results to {path}")

    def save_summary(self, fuzzer_result: FuzzerResult):        
        path = self.output_dir / 'summary.json'
        with open(path, 'w') as f:
            json.dump(fuzzer_result.model_dump(), f, indent=2)
        print(f"Saved summary to {path}")

    def save_mutations(self):
        path = self.output_dir / 'mutations.json'
        mutations_data = {
            'mutations': self.all_mutations
        }
        with open(path, 'w') as f:
            json.dump(mutations_data, f, indent=2)
        print(f"Saved {len(self.all_mutations)} mutations to {path}")

    def save_coverage_over_time(self, coverage_snapshots: List):
        path = self.output_dir / 'coverage_over_time.json'
        serializable = [snapshot.model_dump() for snapshot in coverage_snapshots]
        with open(path, 'w') as f:
            json.dump(serializable, f, indent=2)
        print(f"Saved {len(coverage_snapshots)} coverage snapshots to {path}")
    
    def create_operator_effectiveness_summary(self, operator_effectiveness_data: List[OperatorEffectivenessData]) -> List[OperatorEffectivenessSummary]:
        if not operator_effectiveness_data:
            return []
        
        operator_stats = {}
        
        for op_data in operator_effectiveness_data:
            operator_name = op_data.operator_name
            if operator_name not in operator_stats:
                operator_stats[operator_name] = {
                    'new_edge_coverage': 0,
                    'new_execution_state': 0,
                    'mutations': []
                }
            
            operator_stats[operator_name]['mutations'].append(op_data.mutation)
            if op_data.new_edge_coverage:
                operator_stats[operator_name]['new_edge_coverage'] += 1
            if op_data.new_execution_state:
                operator_stats[operator_name]['new_execution_state'] += 1
        
        operator_effectiveness_summaries = []

        for op_name, stats in operator_stats.items():
            total_mutations = len(stats['mutations'])
            unique_mutations = len(set(stats['mutations']))
            unique_mutation_percentage = (unique_mutations / total_mutations) * 100 if total_mutations > 0 else 0
            edge_coverage_percentage = (stats['new_edge_coverage'] / total_mutations) * 100 if total_mutations > 0 else 0
            execution_state_percentage = (stats['new_execution_state'] / total_mutations) * 100 if total_mutations > 0 else 0
            
            operator_effectiveness_summaries.append(OperatorEffectivenessSummary(
                operator_name=op_name,
                edge_coverage_percentage=edge_coverage_percentage,
                execution_state_percentage=execution_state_percentage,
                unique_mutation_percentage=unique_mutation_percentage,
                total_mutations=total_mutations
            ))
        
        return operator_effectiveness_summaries
    
    def save_session_data(self, session_data: SessionData, session_data_dir: Path):
        path = session_data_dir / 'session_data_summary.json'

        def aggregate_function_hotspots(mutation_results: List[ExecutionResult]) -> List[dict]:
            symbol_counts = {}
            
            for result in mutation_results:
                if not result.function_hotspots:
                    continue
                for hotspot in result.function_hotspots:
                    symbol = hotspot.symbol
                    if symbol not in symbol_counts:
                        symbol_counts[symbol] = 0
                    symbol_counts[symbol] += hotspot.count
            
            if not symbol_counts:
                return []
            
            total_samples = sum(symbol_counts.values())
            aggregated = [
                {
                    'symbol': symbol,
                    'count': count,
                    'percentage': (count / total_samples * 100.0) if total_samples > 0 else 0.0
                }
                for symbol, count in sorted(symbol_counts.items(), key=lambda x: x[1], reverse=True)
            ]
            
            return aggregated

        def serialize_session_data(session_data: SessionData) -> dict:
            return {
                'operator_effectiveness': [o.model_dump() for o in session_data.operator_effectiveness],
                'num_mutations': len(session_data.mutations),
                'unique_mutations': len(set(session_data.mutations)),
                'num_execution_states': len(session_data.execution_state_set),
                'mutations': session_data.mutations,
                'execution_state_set': [self._serialize_execution_state(es) for es in session_data.execution_state_set],
                'overall_function_hotspots': aggregate_function_hotspots(session_data.mutation_results),
            }
        
        serializable = serialize_session_data(session_data)
        with open(path, 'w') as f:
            json.dump(serializable, f, indent=2)
        print(f"Saved session data to {path}")