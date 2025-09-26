import yaml
import time
import json
from pathlib import Path
from typing import List
import random
from datetime import datetime
import codecs

from .models import CrashResult, ExecutionResult, ExecutionStateSet, ExecutionOutcome, FuzzerResult
from .ql_emulation import execute_with_qiling
from .corpus_stat_tracker import CorpusStatTracker
from .mutation_engines.agent_defined.mutate import mutate

class SeedQueue:
    def __init__(self):
        self.queue = []

    def add_seed(self, seed: bytes):
        self.queue.append(seed)

    def pop_seed(self) -> bytes:
        return self.queue.pop()

    def is_empty(self) -> bool:
        return len(self.queue) == 0

class AgentFuzzer:
    def __init__(self):
        self.run_config = yaml.safe_load(open('config.yaml'))
        self.state_set: ExecutionStateSet = set()
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
    
    def run(self):
        corpus_results: List[ExecutionResult] = []
        rejected_results: List[ExecutionResult] = []
        crashes = []
        start_time = time.time()
        execution_count = 0
        execution_time = 0
        initial_seed_count = 0

        for seed_value in self.seed_inputs:
            seed_bytes = codecs.decode(seed_value, 'unicode_escape').encode('utf-8')
            self.seed_queue.add_seed(seed_bytes)
        
        for initial_seed in self.seed_queue.queue:
            result = execute_with_qiling(initial_seed, self.run_config)
            corpus_results.append(result)
            if result.execution_outcome == ExecutionOutcome.CRASH:
                crashes.append(CrashResult(
                    iteration=execution_count,
                    input_data=result.input_data.decode('utf-8', errors='replace'),
                    crash_info=result.crash_info,
                    execution_time=result.execution_time
                ))
            
            self.state_set.add(result.execution_state)
            execution_count += 1
            execution_time += result.execution_time
            self.corpus_stat_tracker.add_sample(result)
            initial_seed_count += 1

        # Start tracking after initial seeds are processed
        self.corpus_stat_tracker.start_tracking()

        def _under_time_limit() -> bool:
            time_limit = self.run_config['fuzzer']['time_limit']
            if time_limit and time_limit > 0:
                return (time.time() - start_time) < time_limit
            return True

        execution_limit = self.run_config['fuzzer']['execution_limit']
        mutations_per_seed = self.run_config['fuzzer']['mutations_per_seed']

        stop_due_to_time = False

        while _under_time_limit() and (execution_limit == 0 or execution_count < execution_limit):
            if self.seed_queue.is_empty():
                self.seed_queue.add_seed(random.choice(self._popped_seeds))
            
            seed = self.seed_queue.pop_seed()
            self._popped_seeds.append(seed)
            
            mutations = mutate(
                input=seed,
                num_mutations=mutations_per_seed
            )
            
            accepted_results: list[ExecutionResult] = []
            rejected_results: list[ExecutionResult] = []

            for mutation in mutations:
                self.all_mutations.append(mutation.decode('utf-8', errors='replace'))
                result = execute_with_qiling(mutation, self.run_config)
                
                if result.execution_outcome == ExecutionOutcome.CRASH:
                    crashes.append(CrashResult(
                        iteration=execution_count,
                        input_data=result.input_data.decode('utf-8', errors='replace'),
                        crash_info=result.crash_info,
                        execution_time=result.execution_time
                    ))

                if result.execution_state not in self.state_set:
                    self.seed_queue.add_seed(mutation)
                    self.state_set.add(result.execution_state)
                    corpus_results.append(result)
                    self.corpus_stat_tracker.add_sample(result)
                    accepted_results.append(result)
                else:
                    rejected_results.append(result)

                execution_count += 1
                execution_time += result.execution_time
                
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
            generated_corpus_count=len(corpus_results) - initial_seed_count,
            total_mutations=len(self.all_mutations),
            unique_mutations=len(set(self.all_mutations)),
            crashes_found=len(crashes),
            total_execution_time_seconds=execution_time,
            average_execution_time_seconds=execution_time / execution_count if execution_count > 0 else 0,
            crash_rate=((len(crashes) / execution_count) if execution_count > 0 else 0),
            corpus_stat_result=self.corpus_stat_tracker.get_result(),
            coverage_over_time=self.corpus_stat_tracker.get_coverage_snapshots(),
        )

        self.print_summary(fuzzer_result, crashes)
        self.save_summary(fuzzer_result)
        self.save_results(corpus_results)
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

    def save_results(self, results: List[ExecutionResult]):
        path = self.output_dir / 'corpus_results.json'

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