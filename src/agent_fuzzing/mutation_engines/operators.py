import requests

class Mutator:
    def __init__(self, config: dict):
        self.server = config['server']      

    def mutate(self, input: str, num_mutations: int) -> list[str]:
        response = requests.post(
            f"{self.server}/mutate_random",
            json={"data": input, "num_mutations": num_mutations},
            timeout=5
        )
        response.raise_for_status()

        return response.json()['mutations']