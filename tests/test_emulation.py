import yaml
import argparse
import codecs
from agent_fuzzing.ql_emulation import execute_with_qiling

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
parser.add_argument('--result_attr', type=str, required=False)
args = parser.parse_args()


input_data = codecs.decode(args.input, 'unicode_escape').encode('utf-8')

run_config = yaml.safe_load(open("config.yaml"))

try:
    result = execute_with_qiling(input_data, run_config)
    if args.result_attr:
        print(f"{args.result_attr}: {getattr(result, args.result_attr)}")
    else:
        print(result)
    
except Exception as e:
    print(str(e))