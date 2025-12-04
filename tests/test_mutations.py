import yaml
import argparse
import traceback

from ExecStateFuzzer.mutation_engine import MutationEngine, execution_state_tuple_to_dict
from ExecStateFuzzer.ql_emulation import execute_with_qiling

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
args = parser.parse_args()

input_data = args.input

run_config = yaml.safe_load(open("config.yaml"))
mutations_cfg = run_config['fuzzer']['mutations']

engine = MutationEngine(
    operators_file=mutations_cfg['operators_file'],
    strategy_file=mutations_cfg['strategy_file']
)

operators = list(engine.operators.keys())

if not operators:
    print("No operators found")
    exit(1)

print(f"Found {len(operators)} operators: {', '.join(operators)}\n")

print("Running emulation to get execution state...")
input_bytes = input_data.encode('latin-1')
execution_result = execute_with_qiling(input_bytes, run_config)
execution_state = execution_result.execution_state

print(f"Execution state: {execution_state}\n")

state_dict = execution_state_tuple_to_dict(execution_state) if execution_state else {}
rule = engine.select_rule(state_dict)
if rule:
    print(f"Selected rule: {rule.get('name', 'unknown')}")
    print(f"Rule condition: {rule.get('condition', 'null (always)')}")
    print(f"Available operators in rule: {[op[0] for op in rule.get('operators', [])]}\n")
else:
    print("No matching rule found!\n")

print("Generating mutations:\n")

num_mutations = 5
try:
    mutated_results = engine.mutate(
        data=input_bytes,
        state_tuple=execution_state,
        num_mutations=num_mutations
    )
    
    mutations = []
    for i, (mutated_data, selected_op) in enumerate(mutated_results, 1):
        mutated_str = mutated_data.decode('latin-1')
        mutations.append(f"Mutation {i}: Operator={selected_op}, Result={mutated_str!r}")
    
    for mutation in mutations:
        print(mutation)
        
except Exception as e:
    print(f"Error generating mutations: {type(e).__name__}: {e}")
    traceback.print_exc()