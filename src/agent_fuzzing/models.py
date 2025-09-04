from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict

class ExecutionOutcome(Enum):
    NORMAL = "normal"
    CRASH = "crash"
    HANG = "hang"
    TIMEOUT = "timeout"

class ExecutionResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    input_data: bytes
    execution_outcome: ExecutionOutcome
    execution_time: float
    crash_info: Optional[str]
    execution_state: tuple
    stdout: Optional[str]
    cov_bitmap: Optional[bytearray]
    branch_taken_bitmap: Optional[bytearray]
    branch_fallthrough_bitmap: Optional[bytearray]
    instr_address_set: Optional[set[int]]
    total_instructions: int
    pathlen_blocks: int
    call_depth: int

class CrashResult(BaseModel):
    iteration: int
    input_data: str
    crash_info: str
    execution_time: float

class CorpusStatResult(BaseModel):
    total_edges: int
    total_branch_sites: int
    total_unique_instructions: int
    avg_pathlen_blocks: float
    max_pathlen_blocks: int
    avg_calldepth: float
    max_calldepth: int

class FuzzerResult(BaseModel):
    total_executions: int
    inital_seed_count: int
    corpus_count: int
    crashes_found: int
    total_execution_time_seconds: float
    average_execution_time_seconds: float
    crash_rate: float
    corpus_stat_result: CorpusStatResult

ExecutionStateSet = set[tuple]