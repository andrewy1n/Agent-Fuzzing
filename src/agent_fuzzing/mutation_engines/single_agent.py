from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv
import json
from typing import List
from ..models import ExecutionResult

load_dotenv()

client = OpenAI()

class Mutations(BaseModel):
    mutations: list[str]

class MutationAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": 
                """
                You are a mutation agent for a agent-driven fuzzer.
                Your job: given a seed input and feedback (good/bad examples), produce a diverse list of input mutations that are more like the good examples and less like the bad ones, with the goal of increasing execution state coverage.

                Output format:
                - Return ONLY a JSON object that matches this schema: {"mutations": [string, ...]}.
                - Each element in "mutations" is a single test input as a UTF-8 string (it will be converted to bytes by the harness).
                - Do not include explanations, comments, or code fences.
                """ + config['prompt']
            }
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
        self.mutation_agent = MutationAgent(config=config['mutation_agent'])
        self.steps_per_seed = config['fuzzer']['steps_per_seed']
        self.mutations_per_step = config['fuzzer']['mutations_per_step']
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0

    def _fmt_examples(self, tag: str, exs: List["ExecutionResult"]) -> str:
        lines = [f"{tag} (count={len(exs)}):"]
        for e in exs:
            try:
                inp = e.input_data.decode('utf-8', errors='replace')
            except Exception:
                inp = str(e.input_data)
            eo = e.execution_outcome
            eo_val = eo.value.lower() if eo is not None else ''
            crashed = (eo_val == 'crash')
            out_preview = (e.stdout or '')[:200]
            lines.append(f"- input=<{inp}> | crashed={crashed} | stdout=<{out_preview}>")
        return "\n".join(lines)

    def propose_mutations(self, seed_input: bytes) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        user_prompt = f"""
            Seed input: {seed_input_str}

            Generate a list of {self.mutations_per_step} mutations for the seed input.
        """
        response = self.mutation_agent.run(user_prompt)
        muts = response.output_parsed.mutations
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens

        return [m.encode('utf-8') for m in muts]

    def report_results(self, good_results: List["ExecutionResult"], bad_results: List["ExecutionResult"]):
        def fmt_results(header: str, results: List["ExecutionResult"]) -> str:
            if not results:
                return f"{header}\n  (none)"
            lines = [f"  - {result.input_data.decode('utf-8', errors='replace')}" for result in results]
            return f"{header}\n" + "\n".join(lines)

        good_results_str = fmt_results("Increased execution state coverage:", good_results)
        bad_results_str = fmt_results("Did not increase execution state coverage:", bad_results)
        
        self.mutation_agent.messages.append({"role": "user", "content": f"Results of previous given mutations: {good_results_str}\n{bad_results_str}"})

    def get_token_usage(self) -> dict:
        return {
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'total_tokens': self.total_tokens
        }