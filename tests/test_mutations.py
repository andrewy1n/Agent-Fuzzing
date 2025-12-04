import yaml
import argparse
import traceback

from ExecStateFuzzer.mutation_engine import MutationEngine, execution_state_tuple_to_dict

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
parser.add_argument('--state', type=str, default=None, help='Execution state as comma-separated key=value pairs (e.g., "knight_move_success=0,pawn_white_position_y=5")')
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

execution_state = tuple()
if args.state:
    state_dict = {}
    for pair in args.state.split(','):
        if '=' in pair:
            key, value = pair.split('=', 1)
            try:
                state_dict[key.strip()] = int(value.strip())
            except ValueError:
                state_dict[key.strip()] = value.strip()
    
    state_list = []
    for key, value in state_dict.items():
        state_list.append(f"{key} (value)")
        state_list.append(value)
    execution_state = tuple(state_list)
else:
    execution_state = tuple()

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

input_bytes = input_data.encode('latin-1')

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