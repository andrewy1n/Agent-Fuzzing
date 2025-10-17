from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import inspect
import random
import os
import json
import yaml

app = FastAPI()
mutation_operators = {}

OPERATORS_FILE = yaml.safe_load(open("config.yaml"))['fuzzer']['mutations']['operators_file']

def persist_operators():
    data = {}
    for name, (weight, func, code) in mutation_operators.items():
        data[name] = {"weight": weight, "code": code}
    os.makedirs(os.path.dirname(OPERATORS_FILE), exist_ok=True)
    with open(OPERATORS_FILE, "w") as f:
        json.dump(data, f)

def load_operators():
    if os.path.exists(OPERATORS_FILE):
        with open(OPERATORS_FILE, "r") as f:
            data = json.load(f)
        for name, meta in data.items():
            local_env = {}
            exec(meta["code"], {}, local_env)
            func = local_env[name]
            mutation_operators[name] = (meta["weight"], func, meta["code"])

class MutateRequest(BaseModel):
    data: str
    num_mutations: int = 1

class MutateWithOperatorRequest(BaseModel):
    data: str

class AddOperatorRequest(BaseModel):
    name: str
    code: str
    weight: float = 1.0

class EditOperatorRequest(BaseModel):
    name: str
    code: str = None
    weight: float = None

class DeleteOperatorRequest(BaseModel):
    name: str

@app.post("/mutate_random")
def mutate_random(request: MutateRequest):
    if not mutation_operators:
        raise HTTPException(status_code=400, detail="No mutation operators available")
    
    mutations = []
    for _ in range(request.num_mutations):
        weights = [mutation_operators[name][0] for name in mutation_operators]
        names = list(mutation_operators.keys())
        selected_name = random.choices(names, weights=weights)[0]
        operator_func = mutation_operators[selected_name][1]
        
        mutated_data = operator_func(request.data)
        mutations.append((mutated_data, selected_name))
    
    return {"mutations": mutations}

@app.post("/mutate/{op_name}")
def mutate(op_name: str, request: MutateWithOperatorRequest):
    if op_name not in mutation_operators:
        raise HTTPException(status_code=404, detail=f"Operator '{op_name}' not found in mutation_operators")
    operator_func = mutation_operators[op_name][1]
    out = operator_func(request.data)
    return {"mutated": out}

@app.post("/add_operator")
def add_operator(request: AddOperatorRequest):
    local_env = {}
    exec(request.code, {}, local_env)

    if request.name not in local_env or not callable(local_env[request.name]):
        raise HTTPException(status_code=400, detail=f"Operator {request.name} not found in provided code")

    func = local_env[request.name]

    sig = inspect.signature(func)
    params = list(sig.parameters.values())
    if len(params) != 1:
        raise HTTPException(status_code=400, detail=f"Operator {request.name} must take exactly one argument")
    if sig.return_annotation not in (str, inspect.Signature.empty):
        raise HTTPException(status_code=400, detail=f"Operator {request.name} must return str")

    try:
        test_result = func("test")
        if not isinstance(test_result, str):
            raise HTTPException(status_code=400, detail=f"Operator {request.name} must return str, got {type(test_result).__name__}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Operator {request.name} test failed: {str(e)}")

    mutation_operators[request.name] = (request.weight, func, request.code)
    persist_operators()
    return {"status": "ok"}

@app.get("/list_operators")
def list_operators():
    operators_info = []
    for name, (weight, func, code) in mutation_operators.items():
        operators_info.append({"name": name, "weight": weight})
    return {"operators": operators_info}

@app.post("/edit_operator")
def edit_operator(request: EditOperatorRequest):
    if request.name not in mutation_operators:
        raise HTTPException(status_code=404, detail=f"Operator '{request.name}' not found in mutation_operators")
    
    current_weight, current_func, current_code = mutation_operators[request.name]
    
    if request.code is not None:
        local_env = {}
        exec(request.code, {}, local_env)

        if request.name not in local_env or not callable(local_env[request.name]):
            raise HTTPException(status_code=400, detail=f"Operator {request.name} not found in code")

        func = local_env[request.name]

        sig = inspect.signature(func)
        params = list(sig.parameters.values())
        if len(params) != 1:
            raise HTTPException(status_code=400, detail=f"Operator {request.name} must take exactly one argument")
        if sig.return_annotation not in (str, inspect.Signature.empty):
            raise HTTPException(status_code=400, detail=f"Operator {request.name} must return str")

        try:
            test_result = func("test")
            if not isinstance(test_result, str):
                raise HTTPException(status_code=400, detail=f"Operator {request.name} must return str, got {type(test_result).__name__}")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Operator {request.name} test failed: {str(e)}")
    else:
        func = current_func
        request.code = current_code
    
    new_weight = request.weight if request.weight is not None else current_weight
    
    mutation_operators[request.name] = (new_weight, func, request.code)
    persist_operators()
    return {"status": "ok"}

@app.post("/delete_operator")
def delete_operator(request: DeleteOperatorRequest):
    if request.name not in mutation_operators:
        raise HTTPException(status_code=404, detail=f"Operator '{request.name}' not found in mutation_operators")
    del mutation_operators[request.name]
    persist_operators()
    return {"status": "ok"}

load_operators()