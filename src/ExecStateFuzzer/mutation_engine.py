import json
import random
import importlib.util
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import importlib

from .utils import eval_predicate_expression


def execution_state_tuple_to_dict(state_tuple: tuple) -> dict:
    """
    Convert execution_state tuple to a dictionary of execution values.
    
    The tuple format is: (label, value, label, value, ...)
    Labels can be:
    - "name (value)" -> extract "name"
    - "name (sum)" -> extract "name" 
    - "expr" (for predicates) -> skip (not a named value)
    - "expr (count)" -> skip (not a named value)
    - "name (set)" -> extract "name"
    
    Args:
        state_tuple: Execution state tuple from ExecutionResult
        
    Returns:
        Dictionary mapping execution value names to their latest values
    """
    result = {}
    i = 0
    while i < len(state_tuple) - 1:
        label = state_tuple[i]
        value = state_tuple[i + 1]
        
        if isinstance(label, str):
            # Extract name from "name (type)" format
            if '(' in label:
                name = label.split('(')[0].strip()
                # Only include if it's a value or sum type (not predicate/counter/set)
                if '(value)' in label or '(sum)' in label:
                    result[name] = value
            # For predicates, the label is the expression itself - skip
            # For counters, label is "expr (count)" - skip
            # For sets, we could include but they're tuples - skip for now
        
        i += 2
    
    return result


class MutationEngine:    
    def __init__(self, operators_file: str, strategy_file: str):
        self.operators_file = Path(operators_file).resolve()
        self.strategy_file = Path(strategy_file).resolve()
        self.operators_module = None
        self.operators: Dict[str, callable] = {}
        self.rules: List[dict] = []
        
        self._load_operators()
        self._load_strategy()
    
    def _load_operators(self):
        if not self.operators_file.exists():
            raise FileNotFoundError(f"Operators file not found: {self.operators_file}")
        
        module_name = f"operators_{id(self)}"
        spec = importlib.util.spec_from_file_location(module_name, self.operators_file)
        if spec is None or spec.loader is None:
            raise ImportError(f"Failed to load operators from {self.operators_file}")
        
        self.operators_module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = self.operators_module
        spec.loader.exec_module(self.operators_module)
        
        self.operators = {}
        for name in dir(self.operators_module):
            if name.startswith('_'):
                continue
            obj = getattr(self.operators_module, name)
            if callable(obj):
                # Check signature - should accept (data: str, state: dict)
                import inspect
                sig = inspect.signature(obj)
                params = list(sig.parameters.values())
                if len(params) >= 2:
                    self.operators[name] = obj
    
    def _load_strategy(self):
        if not self.strategy_file.exists():
            raise FileNotFoundError(f"Strategy file not found: {self.strategy_file}")
        
        with open(self.strategy_file, 'r') as f:
            data = json.load(f)
        
        self.rules = data.get('rules', [])
        
        # Validate rules
        for rule in self.rules:
            if 'operators' not in rule:
                raise ValueError(f"Rule '{rule.get('name', 'unknown')}' missing 'operators' field")
            if not isinstance(rule['operators'], list):
                raise ValueError(f"Rule '{rule.get('name', 'unknown')}' operators must be a list")
            for op_entry in rule['operators']:
                if not isinstance(op_entry, list) or len(op_entry) != 2:
                    raise ValueError(f"Rule '{rule.get('name', 'unknown')}' operator entry must be [name, weight]")
                op_name, weight = op_entry
                if op_name not in self.operators:
                    raise ValueError(f"Rule '{rule.get('name', 'unknown')}' references unknown operator '{op_name}'")
                if not isinstance(weight, (int, float)) or weight <= 0:
                    raise ValueError(f"Rule '{rule.get('name', 'unknown')}' operator '{op_name}' has invalid weight")
    
    def reload(self):
        self._load_operators()
        self._load_strategy()
    
    def select_rule(self, state: dict) -> Optional[dict]:
        for rule in self.rules:
            condition = rule.get('condition')
            if condition is None:
                # Null condition means always match
                return rule
            if eval_predicate_expression(condition, state):
                return rule
        
        return None
    
    def select_operator(self, rule: dict) -> str:
        operators = rule['operators']
        names = [op[0] for op in operators]
        weights = [op[1] for op in operators]
        
        selected = random.choices(names, weights=weights)[0]
        return selected
    
    def mutate(self, data: bytes, state_tuple: tuple, num_mutations: int) -> List[Tuple[bytes, str]]:
        if not self.operators:
            raise ValueError("No operators loaded")
        if not self.rules:
            raise ValueError("No rules defined in strategy")
        
        # Convert state tuple to dict
        state = execution_state_tuple_to_dict(state_tuple)
        
        mutations = []
        for _ in range(num_mutations):
            # Select matching rule
            rule = self.select_rule(state)
            if rule is None:
                raise ValueError(f"No matching rule for state: {state}")
            
            # Select operator from rule
            op_name = self.select_operator(rule)
            
            # Get operator function
            op_func = self.operators[op_name]
            
            # Execute mutation
            try:
                data_str = data.decode('latin-1')
                mutated_str = op_func(data_str, state)
                mutated_data = mutated_str.encode('latin-1')
                mutations.append((mutated_data, op_name))
            except Exception as e:
                raise RuntimeError(f"Operator '{op_name}' failed: {type(e).__name__}: {e}")
        
        return mutations

