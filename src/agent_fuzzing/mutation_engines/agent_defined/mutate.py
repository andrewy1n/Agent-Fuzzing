from .operators import mutation_operators
import random

def mutate(input: bytes, num_mutations: int) -> list[bytes]:
    operators = [op[0] for op in mutation_operators]
    weights = [op[1] for op in mutation_operators]
    mutations = []
    for _ in range(num_mutations):
        operator = random.choices(operators, weights=weights)
        mutations.append(operator(input))

    return [m.encode('utf-8') for m in mutations]