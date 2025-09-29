from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv
import json
import requests
from typing import List
from ..models import ExecutionResult, MultiAgentTokenUsage, TokenUsage

load_dotenv()

client = OpenAI()

class Mutations(BaseModel):
    mutations: list[str]

class GeneratorAgent:
    def __init__(self, config: dict):
        self.model = config['model']
        self.messages = [
            {
                "role": "system",
                "content": config['system_prompt'] + config['grammar_prompt']
            },
            {
                "role": "user",
                "content": ''
            }
        ]
        self.goal_prompt = config['goal_prompt']
        self.token_usage = TokenUsage(
            input_tokens=0,
            output_tokens=0,
            total_tokens=0
        )

    def run(self, mutation_prompt: str):
        client_input = self.messages + [{"role": "user", "content": mutation_prompt + self.goal_prompt}]
        
        response = client.responses.parse(
            model=self.model,
            input=client_input,
            text_format=Mutations
        )
        muts = response.output_parsed.mutations

        self.messages.append({"role": "assistant", "content": json.dumps({"mutations": muts})})
        self.token_usage.input_tokens += response.usage.input_tokens
        self.token_usage.output_tokens += response.usage.output_tokens
        self.token_usage.total_tokens += response.usage.total_tokens
        return response
    
    def add_mutation_feedback(self, good_mutations: List["ExecutionResult"], bad_mutations: List["ExecutionResult"]):
        self.messages.append({
            "role": "user",
            "content": self._fmt_results("Increased execution state coverage:", good_mutations) + self._fmt_results("Did not increase execution state coverage:", bad_mutations)
        })
    
    def _fmt_results(self, header: str, results: List["ExecutionResult"]) -> str:
        if not results:
            return f"{header}\n  (none)"
        lines = [f"  - {result.input_data.decode('utf-8', errors='replace')}" for result in results]
        return f"{header}\n" + "\n".join(lines)
    
    def add_summary(self, summary: str):
        self.messages[1]['content'] = summary
        self.messages = self.messages[:2]
    
    def edit_goal_prompt(self, goal_prompt: str):
        self.goal_prompt = goal_prompt

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
        self.server = config['server']
        self.initial_prompt = config['initial_prompt']
        self.thread_id = config['thread_id']
        self.binary_path = config['binary_path']
        self.results_dir = config['results_dir']
        self.token_usage = TokenUsage(
            input_tokens=0,
            output_tokens=0,
            total_tokens=0
        )

    def run(self, accepted_results: List["ExecutionResult"], rejected_results: List["ExecutionResult"]):
        accepted_results_str = self._fmt_results("Accepted results:", accepted_results)
        rejected_results_str = self._fmt_results("Rejected results:", rejected_results)
        
        payload = {
            "thread_id": self.thread_id,
            "binary_path": self.binary_path,
            "results_dir": self.results_dir,
            "prompt": self.initial_prompt + accepted_results_str + rejected_results_str,
            "recursion_limit": 4
        }
        
        try:
            response = requests.post(
                f"{self.server}/continue_conversation",
                json=payload,
                headers={"Content-Type": "application/json"},
                stream=True
            )
            response.raise_for_status()

            full_content = ""
            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        content = line_str[6:]
                        if content.strip() == '[DONE]':
                            break
                        full_content += content
                    elif line_str.strip():
                        # Check if this line contains token usage statistics
                        if line_str.strip().startswith('{') and '"type": "stats"' in line_str:
                            try:
                                stats_data = json.loads(line_str.strip())
                                if stats_data.get("type") == "stats" and "tokens" in stats_data:
                                    tokens = stats_data["tokens"]
                                    self.token_usage.input_tokens += tokens.get("input", 0)
                                    self.token_usage.output_tokens += tokens.get("output", 0)
                                    self.token_usage.total_tokens += tokens.get("total", 0)
                            except json.JSONDecodeError:
                                pass
                        else:
                            full_content += line_str

            if full_content.strip().startswith('{') or full_content.strip().startswith('['):
                try:
                    return {"data": json.loads(full_content)}
                except json.JSONDecodeError:
                    pass
            
            return {"data": full_content.strip()}
            
        except requests.exceptions.RequestException as e:
            print(f"Error calling continue-conversation API: {e}")
            return {"data": f"API Error: {e}"}
    
    def _fmt_results(self, header: str, results: List["ExecutionResult"]) -> str:
        if not results:
            return f"{header}\n  (none)"
        lines = [f"  - {result.input_data.decode('utf-8', errors='replace')}" for result in results]
        return f"{header}\n" + "\n".join(lines)
    
    def get_token_usage(self) -> TokenUsage:
        return self.token_usage

class MutationSession:
    def __init__(self, config: dict):
        self.generator = GeneratorAgent(config=config['generator_agent'])
        self.summarizer = SummarizerAgent(config=config['summarizer_agent'])
        self.critic = CriticAgent(config=config['critic_agent'])
        self.mutations_per_seed = config['fuzzer']['mutations']['num_mutations']

    def propose_mutations(self, seed_input: bytes) -> list[bytes]:
        seed_input_str = seed_input.decode('utf-8', errors='replace')
        mutation_prompt = f"""
            Seed input: {seed_input_str}

            Generate a list of {self.mutations_per_seed} mutations for the seed input.
        """
        response = self.generator.run(mutation_prompt=mutation_prompt)
        muts = response.output_parsed.mutations

        return [m.encode('utf-8') for m in muts]

    def report_results(self, good_results: List["ExecutionResult"], bad_results: List["ExecutionResult"]):
        self.generator.add_mutation_feedback(good_results, bad_results)
    
    def generate_summary(self, all_good_results: List["ExecutionResult"], all_bad_results: List["ExecutionResult"]):
        all_good_mutations = set([result.input_data.decode('utf-8', errors='replace') for result in all_good_results])
        all_bad_mutations = set([result.input_data.decode('utf-8', errors='replace') for result in all_bad_results])
        all_bad_mutations = all_bad_mutations - all_good_mutations

        response = self.summarizer.run(all_good_mutations, all_bad_mutations)
        self.generator.add_summary(response.output_text)
    
    def generate_critique(self, accepted_results: List["ExecutionResult"], rejected_results: List["ExecutionResult"]):
        response = self.critic.run(accepted_results, rejected_results)
        critic_message = response["data"]
        self.generator.edit_goal_prompt(critic_message)
        # print(f"Critic message: {critic_message}")

    def get_token_usage(self) -> MultiAgentTokenUsage:
        return MultiAgentTokenUsage(
            generator_token_usage=self.generator.token_usage,
            critic_token_usage=self.critic.token_usage
        )