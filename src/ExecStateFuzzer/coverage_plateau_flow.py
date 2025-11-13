import requests
from pathlib import Path
from ExecStateFuzzer.models import SessionData


class CoveragePlateauFlow:
    def __init__(self, config: dict, challenge_name: str):
        self.config = config
        self.endpoint = config['endpoint']
        self.challenge_name = challenge_name
        self.num_calls = 0

    def run(self, session_data: SessionData):
        payload = {
            "session_data": str(session_data.model_dump()),
            "thread_id": self.config['thread_id'],
            "source_docker_id": self.config['source_docker_id'],
            "fuzzer_docker_id": self.config['fuzzer_docker_id'],
            "results_dir": str(Path(self.config['results_dir']) / f"cov_flow_{self.num_calls}"),
            "challenge_name": self.challenge_name,
        }

        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                stream=True,
                timeout=600
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
                    elif line_str.strip() and not line_str.strip().startswith('{'):
                        full_content += line_str
            
            self.num_calls += 1
            return full_content.strip()

                    
        except requests.exceptions.RequestException as e:
            print(f"Error calling coverage plateau flow API: {e}")
            return None