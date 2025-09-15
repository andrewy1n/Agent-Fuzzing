from agent_fuzzing.mutation_engines.multi_agent import CriticAgent
import yaml

config = yaml.safe_load(open("config.yaml"))['critic_agent']
critic = CriticAgent(config=config)
result = critic.run(accepted_results=[], rejected_results=[])
print(result)