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

class MutationAgentSession:
    def __init__(self, config: dict):
        self.prompt = config['prompt']
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
                """ + self.prompt
            }
        ]

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
            out_preview = (getattr(e, 'stdout', '') or '')[:120]
            lines.append(f"- input=<{inp}> | crashed={crashed} | stdout=<{out_preview}>")
        return "\n".join(lines)

    def propose_mutations(self, seed_input: bytes, good_examples: List["ExecutionResult"], bad_examples: List["ExecutionResult"], num: int = 5) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        user_prompt = f"""
            Seed input: {seed_input_str}
            {self._fmt_examples('Good examples', good_examples)}
            {self._fmt_examples('Bad examples', bad_examples)}

            Generate a list of {num} mutations for the seed input that are more like the good examples and less like the bad examples.
        """
        convo = self.messages + [{"role": "user", "content": user_prompt}]

        response = client.responses.parse(
            model=self.model,
            input=convo,
            text_format=Mutations
        )
        muts = response.output_parsed.mutations

        try:
            self.messages = convo + [{"role": "assistant", "content": json.dumps({"mutations": muts})}]
        except Exception:
            self.messages = convo + [{"role": "assistant", "content": str({"mutations": muts})}]
        return [m.encode('utf-8') for m in muts]

    def report_results(self, results: List["ExecutionResult"]):
        lines = ["Results of previous mutations:"]
        for e in results:
            try:
                s = getattr(e, 'input_data', b'').decode('utf-8', errors='replace')
            except Exception:
                s = str(getattr(e, 'input_data', ''))
            state = getattr(e, 'execution_state', None)
            out = getattr(e, 'stdout', None)
            try:
                state_repr = list(state) if isinstance(state, (list, tuple)) else state
            except Exception:
                state_repr = state
            out_preview = (out or "")[:200]
            lines.append(f"- input=<{s}> | state={state_repr} | stdout=<{out_preview}>")
        self.messages.append({"role": "user", "content": "\n".join(lines)})