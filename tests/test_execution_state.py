import yaml
import argparse
import codecs
from agent_fuzzing.ql_emulation import execute_with_qiling

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
args = parser.parse_args()


input_data = codecs.decode(args.input, 'unicode_escape').encode('utf-8')

run_config = yaml.safe_load(open("config.yaml"))

try:
    result = execute_with_qiling(input_data, run_config)
    execution_state = result.execution_state
    print(f"Execution state: {execution_state}")

    state_names = []
    for state_item in run_config['fuzzer']['execution_state']:
        state_names.append(state_item['name'])
    
    # Count occurrences of each state name in execution_state
    state_counts = {}
    for i in range(0, len(execution_state), 2):  # Names are at even indices
        if i < len(execution_state):
            state_name = execution_state[i]
            state_counts[state_name] = state_counts.get(state_name, 0) + 1
    
    for state_item in run_config['fuzzer']['execution_state']:
        state_name = state_item['name']
        if state_name in state_counts and state_counts[state_name] > 0:
            print(f"{state_name} - FIRED ({state_counts[state_name]} times)")
        else:
            print(f"{state_name} - NOT FIRING (no values)")
    
except Exception as e:
    print(str(e))