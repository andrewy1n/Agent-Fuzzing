from typing import List
import argparse
import time
import yaml
import os
from pathlib import Path
from agent_fuzzing.corpus_stat_tracker import CorpusStatTracker
from agent_fuzzing.ql_emulation import execute_with_qiling

parser = argparse.ArgumentParser()
parser.add_argument('--input_dir', type=str, required=True, help='Directory containing corpus inputs')
parser.add_argument('--debug', action='store_true')
cli_args = parser.parse_args()

start_time = time.time()

run_config = yaml.safe_load(open("config.yaml"))

input_dir = Path(cli_args.input_dir)
input_files: List[Path] = []
if input_dir.is_dir():
    for root, _dirs, files in os.walk(input_dir):
        for fn in files:
            input_files.append(Path(root) / fn)
    input_files.sort()
else:
    print(f"Input directory not found: {cli_args.input_dir}")
    exit(1)

MAP_SIZE = 1 << 16

corpus_stat_tracker = CorpusStatTracker(MAP_SIZE)

for fpath in input_files:
    input_data = fpath.read_bytes()
    result = execute_with_qiling(input_data, run_config)
    corpus_stat_tracker.add_sample(result)

print(corpus_stat_tracker.get_result())