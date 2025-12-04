import re
from typing import Union


def coerce_value_to_int(value: Union[bytes, bytearray, int]) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, byteorder='little', signed=False)
    return 0


def eval_predicate_expression(expr: str, env: dict) -> bool:
    expr = (expr or '').replace('&&', ' and ').replace('||', ' or ')
    
    def _replace_name(match: re.Match) -> str:
        name = match.group(0)
        if name in ("and", "or", "not", "True", "False"):
            return name
        if name in env:
            try:
                return str(coerce_value_to_int(env[name]))
            except Exception:
                return "0"
        return "0"
    
    substituted = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", _replace_name, expr)
    try:
        return bool(eval(substituted, {"__builtins__": {}}, {}))
    except Exception:
        return False

