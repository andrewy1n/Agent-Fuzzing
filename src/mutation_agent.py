from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv
import json
from typing import TYPE_CHECKING, List

load_dotenv()

client = OpenAI()

class Mutations(BaseModel):
    mutations: list[str]

class MutationAgentSession:
    def __init__(self):
        self.messages = [
            {
                "role": "system",
                "content": """
                You are a mutation agent for DARPA CGC challenge CROMU_00005.
                Your job: given a seed input and feedback (good/bad examples), produce a diverse list of input mutations that are more like the good examples and less like the bad ones, with the goal of increasing execution state coverage.

                Output format:
                - Return ONLY a JSON object that matches this schema: {"mutations": [string, ...]}.
                - Each element in "mutations" is a single test input as a UTF-8 string (it will be converted to bytes by the harness).
                - Do not include explanations, comments, or code fences.

                CROMU_00005 input grammar and constraints:
                - The program reads newline-delimited chess-like moves from STDIN.
                - Each move line has the exact form: "x1,y1 x2,y2" (one space between the two coordinate pairs).
                - x and y are integers in the inclusive range 0..7.
                - Lines are applied sequentially starting from the initial board position.
                - Only legal moves for the current side are accepted. The implementation models standard piece movement; special moves (castling, en passant, promotion) are not used.
                - Parsing stops on an empty line or a line that is exactly "666". Including a terminating "666" line is optional but valid.
                - Inputs may contain 1 to ~7 moves; a mix of 1-3 move sequences is effective. Some shorter sequences should end with a trailing newline and "666" to signal termination.

                Mutation guidance:
                - Keep coordinates within 0..7 and ensure move legality with respect to the evolving position.
                - Avoid duplicate mutations and avoid non-grammar text.
                - Do not include the seed input in the output.
                - You will also receive stdout and whether a crash occurred for some examples; prioritize patterns that increased coverage or produced interesting stdout without crashing, and avoid patterns associated with crashes unless they appear to explore new states.
                - Consider that moves are applied per team, after white moves, it will be black's turn and only pieces that are black can move. You should use this information to generate valid move patterns considering each team's pieces.
                - If you see a valid move, you should build on it to generate a mutation that appends another valid move for the opposing team.
                """
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
            model="gpt-4.1",
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

if TYPE_CHECKING:
    from fuzzer import ExecutionResult