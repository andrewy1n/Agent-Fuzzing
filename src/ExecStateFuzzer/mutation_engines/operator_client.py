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
        if not response.ok:
            error_detail = response.text
            try:
                error_json = response.json()
                error_detail = error_json.get('detail', error_detail)
            except (ValueError, KeyError):
                pass
            raise requests.exceptions.HTTPError(
                f"{response.status_code} Client Error: {response.reason} for url: {response.url}\n"
                f"Server response: {error_detail}"
            )

        mutation_list = response.json()['mutations']
        mutations = [m[0] for m in mutation_list]
        operator_data = [m[1] for m in mutation_list]  # Second item contains operator data
        
        return mutations, operator_data