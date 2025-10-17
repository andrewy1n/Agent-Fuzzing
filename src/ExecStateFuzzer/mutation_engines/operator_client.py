import requests
from typing import Tuple, List

class Mutator:
    def __init__(self, config: dict):
        self.server = config['server']      

    def mutate(self, input: str, num_mutations: int) -> Tuple[List[str], List[dict]]:
        response = requests.post(
            f"{self.server}/mutate_random",
            json={"data": input, "num_mutations": num_mutations},
            timeout=5
        )
        response.raise_for_status()

        mutation_list = response.json()['mutations']
        mutations = [m[0] for m in mutation_list]
        operator_data = [m[1] for m in mutation_list]  # Second item contains operator data
        
        return mutations, operator_data