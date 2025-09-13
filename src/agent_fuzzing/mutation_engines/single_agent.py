from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv
import json
from typing import List
from ..models import ExecutionResult, TokenUsage

load_dotenv()

client = OpenAI()

class Mutations(BaseModel):
    mutations: list[str]

class GeneratorAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.system_prompt = config['system_prompt']
        self.goal_prompt = config['goal_prompt']
        self.messages = [
            {
                "role": "system",
                "content": self.system_prompt + self.goal_prompt
            },
        ]

    def run(self, user_prompt: str):
        self.messages.append({"role": "user", "content": user_prompt})
        response = client.responses.parse(
            model=self.model,
            input=self.messages,
            text_format=Mutations
        )
        muts = response.output_parsed.mutations

        self.messages.append({"role": "assistant", "content": json.dumps({"mutations": muts})})
        
        return response
    
class MutationSession:
    def __init__(self, config: dict):
        self.generator_agent = GeneratorAgent(config=config['generator_agent'])
        self.mutations_per_seed = config['fuzzer']['mutations_per_seed']
        self.token_usage = TokenUsage(
            input_tokens=0,
            output_tokens=0,
            total_tokens=0
        )

    def propose_mutations(self, seed_input: bytes) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        user_prompt = f"""
            Seed input: {seed_input_str}

            Generate a list of {self.mutations_per_seed} mutations for the seed input.
        """
        response = self.generator_agent.run(user_prompt)
        muts = response.output_parsed.mutations
        self.token_usage.input_tokens += response.usage.input_tokens
        self.token_usage.output_tokens += response.usage.output_tokens
        self.token_usage.total_tokens += response.usage.total_tokens

        return [m.encode('utf-8') for m in muts]

    def report_results(self, good_results: List["ExecutionResult"], bad_results: List["ExecutionResult"]):
        def fmt_results(header: str, results: List["ExecutionResult"]) -> str:
            if not results:
                return f"{header}\n  (none)"
            lines = [f"  - {result.input_data.decode('utf-8', errors='replace')}" for result in results]
            return f"{header}\n" + "\n".join(lines)

        good_results_str = fmt_results("Increased execution state coverage:", good_results)
        bad_results_str = fmt_results("Did not increase execution state coverage:", bad_results)
        
        self.generator_agent.messages.append({"role": "user", "content": f"Results of previous given mutations: {good_results_str}\n{bad_results_str}"})

    def get_token_usage(self) -> TokenUsage:
        return self.token_usage