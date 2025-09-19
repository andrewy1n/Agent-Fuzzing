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

    print("\nExecution states that are NOT firing:")
    
    execution_state_index = 0
    for state_item in run_config['fuzzer']['execution_state']:
        state_name = state_item['name']
        expected_regs = state_item['regs']

        if execution_state_index < len(execution_state) and execution_state[execution_state_index] == state_name:
            execution_state_index += 1 + len(expected_regs)
            print(f"{state_name} - FIRED (has values)")
        else:
            print(f"{state_name} - NOT FIRING (no values)")
    
except Exception as e:
    print(str(e))