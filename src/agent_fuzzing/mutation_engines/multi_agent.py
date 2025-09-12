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
    def __init__(self, config: dict, grammar_prompt: str):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": config['system_prompt'] + grammar_prompt
            },
            {
                "role": "user",
                "content": ''
            }
        ]
        self.goal_prompt = config['goal_prompt']

    def run(self, mutation_prompt: str):
        mutation_prompt += self.goal_prompt
        print(self.messages)
        response = client.responses.parse(
            model=self.model,
            input=self.messages + [{"role": "user", "content": mutation_prompt}],
            text_format=Mutations
        )
        muts = response.output_parsed.mutations

        self.messages.append({"role": "assistant", "content": json.dumps({"mutations": muts})})
        return response
    
    def add_mutation_feedback(self, good_mutations: List["ExecutionResult"], bad_mutations: List["ExecutionResult"]):
        self.messages.append({
            "role": "user",
            "content": self.fmt_results("Increased execution state coverage:", good_mutations) + self.fmt_results("Did not increase execution state coverage:", bad_mutations)
        })
    
    def fmt_results(self, header: str, results: List["ExecutionResult"]) -> str:
        if not results:
            return f"{header}\n  (none)"
        lines = [f"  - {result.input_data.decode('utf-8', errors='replace')}" for result in results]
        return f"{header}\n" + "\n".join(lines)
    
    def add_summary(self, summary: str):
        self.messages[1]['content'] = summary
        self.messages = self.messages[:2]

class SummarizerAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": config['system_prompt']
            }
        ]

    def run(self, all_good_mutations: set[str], all_bad_mutations: set[str]):
        summary_prompt = f"""
            All good mutations: {all_good_mutations}
            All bad mutations: {all_bad_mutations}
        """

        response = client.responses.create(
            model=self.model,
            input=self.messages + [{"role": "user", "content": summary_prompt}],
        )
        print(f"Response: {response.output_text}")
        return response

class CriticAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": config['system_prompt']
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
        self.generator = GeneratorAgent(config=config['generator_agent'], grammar_prompt=config['target']['grammar_prompt'])
        self.summarizer = SummarizerAgent(config=config['summarizer_agent'])
        self.critic = CriticAgent(config=config['critic_agent'])
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0

    def propose_mutations(self, seed_input: bytes, num: int = 5) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        mutation_prompt = f"""
            Seed input: {seed_input_str}

            Generate a list of {num} mutations for the seed input.
        """
        response = self.generator.run(mutation_prompt=mutation_prompt)
        muts = response.output_parsed.mutations
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens

        return [m.encode('utf-8') for m in muts]

    def report_results(self, good_results: List["ExecutionResult"], bad_results: List["ExecutionResult"]):
        self.generator.add_mutation_feedback(good_results, bad_results)
    
    def generate_summary(self, all_good_results: List["ExecutionResult"], all_bad_results: List["ExecutionResult"]):
        all_good_mutations = set([result.input_data.decode('utf-8', errors='replace') for result in all_good_results])
        all_bad_mutations = set([result.input_data.decode('utf-8', errors='replace') for result in all_bad_results])
        all_bad_mutations = all_bad_mutations - all_good_mutations

        response = self.summarizer.run(all_good_mutations, all_bad_mutations)
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens
        self.generator.add_summary(response.output_text)
    
    def report_session_results(self, results: List["ExecutionResult"]):
        response = self.critic.run(self._fmt_examples("Results of previous mutation session:", results))
        critic_message = response.output_text
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens
        self.total_tokens += response.usage.total_tokens
        self.generator.messages.append({"role": "user", "content": critic_message})
        print(f"Critic message: {critic_message}")

    def get_token_usage(self) -> TokenUsage:
        return TokenUsage(
            input_tokens=self.total_input_tokens,
            output_tokens=self.total_output_tokens,
            total_tokens=self.total_tokens
        )