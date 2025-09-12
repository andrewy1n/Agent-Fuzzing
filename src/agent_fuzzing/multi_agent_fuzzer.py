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
from .mutation_engines.multi_agent import MutationSession

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
        self.corpus_stat_tracker = CorpusStatTracker(MAP_SIZE=(1 << 16))
        output_cfg = self.run_config.get('output', {})

        if isinstance(output_cfg, dict):
            output_root = output_cfg.get('dir', 'out')
        else:
            output_root = 'out'

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = Path(output_root) / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._popped_seeds: List[bytes] = []
        self.all_mutations: List[str] = []
        fcfg = self.run_config.get('fuzzer', {})
        self.steps_per_seed = int(fcfg.get('steps_per_seed', 1))
        self.mutations_per_step = int(fcfg.get('mutations_per_step', 10))
        self.round_length = int(fcfg.get('round_length', 5))
        self.seed_inputs = fcfg.get('seed_inputs', [])
    
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

        def _under_time_limit() -> bool:
            time_limit = self.run_config['fuzzer'].get('time_limit', 0)
            if time_limit and time_limit > 0:
                return (time.time() - start_time) < time_limit
            return True

        execution_limit = int(self.run_config['fuzzer'].get('execution_limit', 0))

        self.session = MutationSession(config=self.run_config)

        stop_due_to_time = False
        all_accepted_results: list[ExecutionResult] = []
        all_rejected_results: list[ExecutionResult] = []
        while _under_time_limit() and (execution_limit == 0 or execution_count < execution_limit):       
            for _ in range(self.round_length):
                if self.seed_queue.is_empty():
                    self.seed_queue.add_seed(random.choice(self._popped_seeds))
                
                seed = self.seed_queue.pop_seed()
                self._popped_seeds.append(seed)
                mutations = self.session.propose_mutations(
                    seed_input=seed, 
                    num=self.mutations_per_step
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
                
                if accepted_results or rejected_results:
                    self.session.report_results(accepted_results, rejected_results)
                    all_accepted_results.extend(accepted_results)
                    all_rejected_results.extend(rejected_results)

                if stop_due_to_time:
                    break

            self.session.generate_summary(all_accepted_results, all_rejected_results)

            if stop_due_to_time:
                break
        
        fuzzer_result = FuzzerResult(
            total_executions=execution_count,
            inital_seed_count=initial_seed_count,
            corpus_count=len(corpus_results),
            crashes_found=len(crashes),
            total_execution_time_seconds=execution_time,
            average_execution_time_seconds=execution_time / execution_count if execution_count > 0 else 0,
            crash_rate=((len(crashes) / execution_count) if execution_count > 0 else 0),
            corpus_stat_result=self.corpus_stat_tracker.get_result(),
        )

        self.print_summary(fuzzer_result, crashes)
        self.save_summary(fuzzer_result)
        self.save_results(corpus_results)
        self.save_crashes(crashes)
        self.save_mutations()
        self.save_token_usage()
    
    def print_summary(self, fuzzer_result: FuzzerResult, crashes: List[CrashResult]):
        print("\n=== Fuzzing Summary ===")
        print(f"Total executions: {fuzzer_result.total_executions}")
        print(f"Initial seed count: {fuzzer_result.inital_seed_count}")
        print(f"Generated corpus count: {fuzzer_result.corpus_count - fuzzer_result.inital_seed_count}")
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
        
        # Print token usage
        total_token_usage = self.session.get_token_usage()
        print("\n=== Token Usage ===")
        if total_token_usage.total_tokens > 0:
            print(f"Total input tokens: {total_token_usage.input_tokens}")
            print(f"Total output tokens: {total_token_usage.output_tokens}")
            print(f"Total tokens: {total_token_usage.total_tokens}")
        else:
            print("Token usage information not available from OpenAI API")
        print(f"Total mutations generated: {len(self.all_mutations)}")
        
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

    def save_results(self, results: List[ExecutionResult]):
        path = self.output_dir / 'corpus_results.json'

        def serialize_result(r: ExecutionResult) -> dict:
            return {
                'input_data': r.input_data.decode('utf-8', errors='replace'),
                'execution_outcome': r.execution_outcome.value,
                'execution_time': r.execution_time,
                'crash_info': r.crash_info,
                'execution_state': r.execution_state,
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
        total_executions = fuzzer_result.total_executions
        
        summary = {
            'total_executions': total_executions,
            'inital_seed_count': fuzzer_result.inital_seed_count,
            'generated_corpus_count': fuzzer_result.corpus_count - fuzzer_result.inital_seed_count,
            'crashes_found': fuzzer_result.crashes_found,
            'total_execution_time_seconds': fuzzer_result.total_execution_time_seconds,
            'average_execution_time_seconds': fuzzer_result.average_execution_time_seconds,
            'crash_rate': fuzzer_result.crash_rate,
            'corpus_stat_result': fuzzer_result.corpus_stat_result.model_dump(),
        }

        path = self.output_dir / 'summary.json'
        with open(path, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"Saved summary to {path}")

    def save_mutations(self):
        path = self.output_dir / 'mutations.json'
        mutations_data = {
            'total_mutations': len(self.all_mutations),
            'unique_mutations': len(set(self.all_mutations)),
            'mutations': self.all_mutations
        }
        with open(path, 'w') as f:
            json.dump(mutations_data, f, indent=2)
        print(f"Saved {len(self.all_mutations)} mutations to {path}")

    def save_token_usage(self):
        path = self.output_dir / 'token_usage.json'
        token_usage = self.session.get_token_usage()
        
        token_data = {
            'total_usage': token_usage.model_dump(),
        }
        
        with open(path, 'w') as f:
            json.dump(token_data, f, indent=2)
        
        if token_usage.total_tokens > 0:
            print(f"Saved token usage to {path}")
        else:
            print(f"Saved token usage file to {path} (no usage data available from API)")