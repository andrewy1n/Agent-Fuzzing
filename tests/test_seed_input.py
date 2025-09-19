import yaml
import codecs
from agent_fuzzing.ql_emulation import execute_with_qiling

run_config = yaml.safe_load(open("config.yaml"))

results = []
for seed_value in run_config['fuzzer']['seed_inputs']:
    input_data = codecs.decode(seed_value, 'unicode_escape').encode('utf-8')

    result = execute_with_qiling(input_data, run_config)

    results.append({'seed': input_data, 'execution_state': result.execution_state})

print(f"Seed input execution states: {results}")