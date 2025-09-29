import requests

class Mutator:
    def __init__(self, config: dict):
        self.server = config['server']      

    def mutate(self, input: bytes, num_mutations: int) -> list[bytes]:
        response = requests.get(
            f"{self.server}/mutate_random",
            params={"data": input.decode('utf-8'), "num_mutations": num_mutations},
            timeout=5
        )
        response.raise_for_status()

        return response.json()['mutations']