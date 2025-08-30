import argparse
import codecs
import time
from scaffold import mutate

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
args = parser.parse_args()

start_time = time.time()
mutable_state = []

input_data = codecs.decode(args.input, 'unicode_escape').encode('utf-8')

print(f"Mutations from input: {mutate(input_data)}")