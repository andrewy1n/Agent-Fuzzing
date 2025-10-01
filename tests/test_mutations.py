import yaml
import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument('--input', type=str, required=True)
args = parser.parse_args()

input_data = args.input

run_config = yaml.safe_load(open("config.yaml"))
server = run_config['fuzzer']['mutations']['server']

response = requests.get(
    f"{server}/list_operators",
    timeout=5
)
response.raise_for_status()

operators = response.json()['operators']

mutations = []
for operator in operators:
    response = requests.post(
        f"{server}/mutate/{operator['name']}",
        json={"data": input_data},
        timeout=5
    )
    response.raise_for_status()
    mutated_data = response.json()['mutated']
    mutations.append(f"Operator: {operator['name']}, Weight: {operator['weight']}, Mutation: {mutated_data}")

for mutation in mutations:
    print(mutation)