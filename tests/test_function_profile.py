import argparse
import yaml
import codecs
from ExecStateFuzzer.ql_emulation import execute_with_qiling

def main():
    ap = argparse.ArgumentParser(description="Run Qiling with sampling profiler and print function hotspots.")
    ap.add_argument("--input", type=str, required=True)
    args = ap.parse_args()

    input_data = codecs.decode(args.input, 'unicode_escape').encode('latin-1')

    run_config = yaml.safe_load(open("config.yaml"))

    result = execute_with_qiling(input_data, run_config, force_stdout=False)
    print("Function hotspots:", [h.model_dump() for h in result.function_hotspots])

if __name__ == "__main__":
    main()


