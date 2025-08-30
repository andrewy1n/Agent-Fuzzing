import time
import yaml
import argparse
import codecs
from src.ql_emulation import execute_with_qiling

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
args = parser.parse_args()

start_time = time.time()

input_data = codecs.decode(args.input, 'unicode_escape').encode('utf-8')

run_config = yaml.safe_load(open("config.yaml"))

try:
    result = execute_with_qiling(input_data, run_config)
    print(result)
    
except Exception as e:
    execution_time = time.time() - start_time
    crash_info = f"{type(e).__name__}: {str(e)}"
    
    print(str(e))