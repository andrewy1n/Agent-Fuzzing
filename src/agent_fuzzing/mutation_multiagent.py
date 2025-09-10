from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv
import json
from typing import List
from .models import ExecutionResult

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

                You will be given feedback from a supervisor agent that will guide you toward deeper execution states, make sure to follow the most recent instructions.

                Output format:
                - Return ONLY a JSON object that matches this schema: {"mutations": [string, ...]}.
                - Each element in "mutations" is a single test input as a UTF-8 string (it will be converted to bytes by the harness).
                - Do not include explanations, comments, or code fences.
                """
            }
        ]
        self.initial_prompt = config['prompt']

    def run(self, user_prompt: str):
        self.messages[0]['content'] += self.initial_prompt
        response = client.responses.parse(
            model=self.model,
            input=self.messages + [{"role": "user", "content": user_prompt}],
            text_format=Mutations
        )
        muts = response.output_parsed.mutations

        self.messages.append({"role": "assistant", "content": json.dumps({"mutations": muts})})
        return response
    
    def edit_initial_prompt(self, new_prompt: str):
        self.messages[0]['content'] += new_prompt

class SupervisorAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": config['prompt']
            }
        ]

    def run(self, user_prompt: str):
        self.messages.extend([{"role": "user", "content": user_prompt}])
        response = client.responses.create(
            model=self.model,
            input=self.messages,
        )
        return response

class MutationSession:
    def __init__(self, config: dict):
        self.mutator = MutationAgent(config=config['mutation_agent'])
        self.supervisor = SupervisorAgent(config=config['supervisor_agent'])
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0

    def _fmt_examples(self, tag: str, exs: List["ExecutionResult"]) -> str:
        lines = [f"{tag} (count={len(exs)}):"]
        for e in exs:
            try:
                inp = getattr(e, 'input_data', b'').decode('utf-8', errors='replace')
            except Exception:
                inp = str(getattr(e, 'input_data', ''))
            eo = getattr(e, 'execution_outcome', None)
            eo_val = getattr(eo, 'value', str(eo)).lower() if eo is not None else ''
            crashed = (eo_val == 'crash')
            out_preview = (getattr(e, 'stdout', '') or '')[:200]
            lines.append(f"- input=<{inp}> | crashed={crashed} | stdout=<{out_preview}>")
        return "\n".join(lines)

    def propose_mutations(self, seed_input: bytes, good_examples: List["ExecutionResult"], bad_examples: List["ExecutionResult"], num: int = 5) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        user_prompt = f"""
            Seed input: {seed_input_str}

            Generate a list of {num} mutations for the seed input.
        """
        response = self.mutator.run(user_prompt)
        muts = response.output_parsed.mutations
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens

        return [m.encode('utf-8') for m in muts]

    def report_results(self, results: List["ExecutionResult"]):
        self.mutator.messages.append({"role": "user", "content": self._fmt_examples("Results of previous mutations:", results)})
    
    def report_session_results(self, results: List["ExecutionResult"]):
        response = self.supervisor.run(self._fmt_examples("Results of previous mutation session:", results))
        supervisor_message = response.output_text
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens
        self.mutator.messages.append({"role": "user", "content": supervisor_message})
        print(f"Supervisor message: {supervisor_message}")

    def get_token_usage(self) -> dict:
        return {
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens,
            'total_tokens': self.total_tokens
        }