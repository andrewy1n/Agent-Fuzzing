# Agent-Fuzzing

Agentic fuzzing framework that combines LLM-based mutation operators with coverage-guided feedback using the Qiling emulation framework.

## Key Features

- **Dynamic Mutation Operators**: Add, edit, delete, and manage mutation operators via REST API
- **Coverage Plateau Detection**: Automatically identifies when fuzzing stalls and triggers critic agent intervention
- **Comprehensive Logging**: Tracks crashes, mutations, coverage over time, and operator effectiveness
- **Execution State Analysis**: Monitor specific program values and predicates during execution
- **CGC Binary Support**: Built-in support for DARPA Cyber Grand Challenge binaries

## Installation

```bash
git clone <repository-url>
cd Agent-Fuzzing

uv venv
uv sync
uv pip install -e .
git clone https://github.com/qilingframework/rootfs.git # qiling rootfs
git clone https://github.com/GrammaTech/cgc-cbs.git # CGC Binaries
```

## Configuration

Edit `config.yaml` to configure:

- **Target binary**: Path to the binary to fuzz
- **Rootfs**: Path to the emulated filesystem
- **Time limits**: Maximum fuzzing duration and execution timeouts
- **Mutation settings**: Operator server URL and mutations per seed
- **Coverage plateau detection**: Timeout threshold for triggering critic agent
- **Execution values**: Custom predicates to track program state
- **Critic agent**: LLM endpoint for adaptive fuzzing guidance

## Usage

### Running the Fuzzer

```bash
python scripts/run_fuzzer.py
```

### Starting the Mutation Operator Server

```bash
python src/agent_fuzzing/mutation_engines/operator_server.py
```

### Building CGC Binaries

```bash
python scripts/build_cgc_bin.py
```

## How It Works

1. **Initialization**: Load seed inputs and establish baseline execution states
2. **Mutation**: Generate mutations using operators from the mutation server
3. **Execution**: Run mutations in Qiling emulator and collect coverage data
4. **Corpus Generation**: Add inputs with new execution states to the corpus
5. **Plateau Detection**: Monitor coverage progress and trigger critic agent when stalled
6. **Adaptation**: Critic agent analyzes results and suggests operator improvements
7. **Results**: Save crashes, coverage snapshots, and operator effectiveness metrics

## Data Models

- **ExecutionResult**: Captures execution outcome, coverage, and execution state
- **ExecutionOutcome**: NORMAL, CRASH, HANG, TIMEOUT
- **FuzzerResult**: Summary statistics and results
- **CoverageSnapshot**: Time-series coverage tracking

## Output

The fuzzer generates:
- `crashes/` - Inputs that caused crashes
- `mutations/` - Generated mutation inputs
- `coverage_over_time.json` - Coverage progression data
- `operator_stats.json` - Effectiveness of each mutation operator
- `fuzzer_result.json` - Summary statistics