import yaml
import time
import json
from pathlib import Path
from typing import List
import random
from datetime import datetime
import requests

from .models import CrashResult, ExecutionResult, ExecutionStateSet, ExecutionOutcome, FuzzerResult, TokenUsage
from .ql_emulation import execute_with_qiling
from .corpus_stat_tracker import CorpusStatTracker
from .mutation_engines.operator_client import Mutator

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
        self.mutator = Mutator(config=fcfg['mutations'])
        
        # Plateau detection tracking
        self.coverage_plateau_timeout = fcfg.get('coverage_plateau_timeout_seconds', 60)
        self.last_coverage_time = time.time()
        self.last_coverage_edges = 0
        self.operator_effectiveness_data = []  # Store operator data for analysis
    
    def run(self):
        corpus_results: List[ExecutionResult] = []
        rejected_results: List[ExecutionResult] = []
        crashes = []
        start_time = time.time()
        execution_count = 0
        execution_time = 0
        initial_seed_count = 0

        for seed_value in self.seed_inputs:
            self.seed_queue.add_seed(seed_value)
        
        for initial_seed in self.seed_queue.queue:
            result = execute_with_qiling(initial_seed.encode('utf-8'), self.run_config)
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
            
            self.update_coverage_tracking(result)

        self.corpus_stat_tracker.start_tracking()

        def _under_time_limit() -> bool:
            time_limit = self.run_config['fuzzer']['time_limit']
            if time_limit and time_limit > 0:
                return (time.time() - start_time) < time_limit
            return True

        execution_limit = self.run_config['fuzzer']['execution_limit']
        num_mutations = self.run_config['fuzzer']['mutations']['num_mutations']

        stop_due_to_time = False

        while _under_time_limit() and (execution_limit == 0 or execution_count < execution_limit):
            if self.seed_queue.is_empty():
                self.seed_queue.add_seed(random.choice(self._popped_seeds))
            
            seed = self.seed_queue.pop_seed()
            self._popped_seeds.append(seed)
            
            mutations, operator_data = self.mutator.mutate(
                input=seed,
                num_mutations=num_mutations
            )
            
            accepted_results: list[ExecutionResult] = []
            rejected_results: list[ExecutionResult] = []

            for i, mutation in enumerate(mutations):
                self.all_mutations.append(mutation)
                result = execute_with_qiling(mutation.encode('utf-8'), self.run_config)
                
                op_name = operator_data[i] if i < len(operator_data) else 'unknown'
                new_edge_coverage = False
                new_execution_state = False
                
                if result.execution_outcome == ExecutionOutcome.CRASH:
                    crashes.append(CrashResult(
                        iteration=execution_count,
                        input_data=result.input_data.decode('utf-8', errors='replace'),
                        crash_info=result.crash_info,
                        execution_time=result.execution_time
                    ))

                if result.execution_state not in self.state_set:
                    new_execution_state = True
                    self.seed_queue.add_seed(mutation)
                    self.state_set.add(result.execution_state)
                    corpus_results.append(result)
                    self.corpus_stat_tracker.add_sample(result)
                    accepted_results.append(result)
                else:
                    rejected_results.append(result)
                
                if result.cov_bitmap:
                    current_edges = sum(1 for b in result.cov_bitmap if b)
                    if current_edges > self.last_coverage_edges:
                        new_edge_coverage = True
                
                self.update_coverage_tracking(result)
                
                op_effectiveness = {
                    'operator': op_name,
                    'new_edge_coverage': new_edge_coverage,
                    'new_execution_states': new_execution_state,
                    'execution_time': result.execution_time,
                    'iteration': execution_count
                }
                self.operator_effectiveness_data.append(op_effectiveness)

                execution_count += 1
                execution_time += result.execution_time
       
                if self.is_coverage_plateau():
                    print(f"\nCoverage plateau detected after {self.coverage_plateau_timeout} seconds without new coverage.")
                    operator_effectiveness = self.calculate_operator_effectiveness()
                    self.call_continue_conversation(operator_effectiveness)

                    self.last_coverage_time = time.time()
                
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
            token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0),  # No token usage for operators fuzzer
            coverage_over_time=self.corpus_stat_tracker.get_coverage_snapshots(),
        )

        self.print_summary(fuzzer_result, crashes)
        self.save_summary(fuzzer_result)
        self.save_results(corpus_results)
        self.save_crashes(crashes)
        self.save_mutations()
        self.save_coverage_over_time(fuzzer_result.coverage_over_time)
        self.save_operator_effectiveness()
    
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
    
    def calculate_operator_effectiveness(self) -> dict:
        if not self.operator_effectiveness_data:
            return {}
        
        operator_stats = {}
        
        for op_data in self.operator_effectiveness_data:
            operator_name = op_data.get('operator', 'unknown')
            if operator_name not in operator_stats:
                operator_stats[operator_name] = {
                    'total_uses': 0,
                    'new_edge_coverage': 0,
                    'new_execution_states': 0
                }
            
            operator_stats[operator_name]['total_uses'] += 1
            if op_data.get('new_edge_coverage', False):
                operator_stats[operator_name]['new_edge_coverage'] += 1
            if op_data.get('new_execution_states', False):
                operator_stats[operator_name]['new_execution_states'] += 1
        
        for op_name, stats in operator_stats.items():
            total_uses = stats['total_uses']
            stats['edge_coverage_percentage'] = (stats['new_edge_coverage'] / total_uses) * 100 if total_uses > 0 else 0
            stats['execution_state_percentage'] = (stats['new_execution_states'] / total_uses) * 100 if total_uses > 0 else 0
        
        return operator_stats
    
    def is_coverage_plateau(self) -> bool:
        current_time = time.time()
        time_since_last_coverage = current_time - self.last_coverage_time
        return time_since_last_coverage >= self.coverage_plateau_timeout
    
    def update_coverage_tracking(self, result: ExecutionResult):
        current_edges = sum(1 for b in result.cov_bitmap if b) if result.cov_bitmap else 0
        
        if current_edges > self.last_coverage_edges:
            self.last_coverage_time = time.time()
            self.last_coverage_edges = current_edges
            return True
        return False
    
    def call_continue_conversation(self, operator_effectiveness: dict):
        
        message = f"""
        Coverage plateau detected after {self.coverage_plateau_timeout} seconds without new coverage.

        Current operator effectiveness:
        """
        
        for op_name, stats in operator_effectiveness.items():
            message += f"- {op_name}: {stats['edge_coverage_percentage']:.1f}% new edge coverage, {stats['execution_state_percentage']:.1f}% new execution states ({stats['total_uses']} total uses)\n"
        
        message += "\nPlease modify the mutation operators to improve coverage effectiveness."
        
        critic_config = self.run_config.get('critic_agent', {})
        server = critic_config.get('server', 'http://localhost:8000')
        
        payload = {
            "thread_id": critic_config.get('thread_id', ''),
            "binary_path": critic_config.get('binary_path', ''),
            "results_dir": str(self.output_dir),
            "prompt": message,
            "recursion_limit": 20
        }
        
        try:
            response = requests.post(
                f"{server}/continue_conversation",
                json=payload,
                headers={"Content-Type": "application/json"},
                stream=True,
                timeout=30
            )
            response.raise_for_status()
            
            full_content = ""
            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        content = line_str[6:]
                        if content.strip() == '[DONE]':
                            break
                        full_content += content
                    elif line_str.strip() and not line_str.strip().startswith('{'):
                        full_content += line_str
            
            print("\n=== Coverage Plateau Detected ===")
            print("Operator effectiveness analysis:")
            for op_name, stats in operator_effectiveness.items():
                print(f"  {op_name}: {stats['edge_coverage_percentage']:.1f}% edge coverage, {stats['execution_state_percentage']:.1f}% execution states")
            print(f"\nCritic response: {full_content.strip()}")
            print("=" * 50)
            
            return full_content.strip()
            
        except requests.exceptions.RequestException as e:
            print(f"Error calling continue-conversation API: {e}")
            return None
    
    def save_operator_effectiveness(self):
        path = self.output_dir / 'operator_effectiveness.json'
        
        effectiveness_stats = self.calculate_operator_effectiveness()
        
        data = {
            'operator_effectiveness': effectiveness_stats,
            'raw_data': self.operator_effectiveness_data
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Saved operator effectiveness data to {path}")