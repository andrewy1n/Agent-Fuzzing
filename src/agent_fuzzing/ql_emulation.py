import time
from .models import ExecutionResult, ExecutionOutcome
from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.extensions import pipe
from typing import List, Union
import threading
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import re

class _InputFD:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, size: int) -> bytes:
        if self._pos >= len(self._data) or size <= 0:
            return b""
        nl = self._data.find(b"\n", self._pos)
        if nl != -1:
            line_end = nl + 1
            end = min(self._pos + size, line_end)
        else:
            end = min(len(self._data), self._pos + size)
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

def _compute_image_range(image) -> tuple[int, int]:
    base = int(getattr(image, 'base', 0))
    img_path = getattr(image, 'path', None)
    if not img_path:
        return base, base
    try:
        with open(img_path, 'rb') as f:
            data = f.read(4096)
    except Exception as e:
        sys.stderr.write(f"[error] failed to read ELF: {e}\n")
        sys.stderr.flush()
        return base, base
    if len(data) < 64 or data[:4] != b'\x7fELF':
        sys.stderr.write("[error] not a valid ELF header\n")
        sys.stderr.flush()
        return base, base
    ei_class = data[4]
    ei_data = data[5]
    import struct
    if ei_class == 2:  # ELF64
        endian = '<' if ei_data == 1 else '>'
        # e_phoff @0x20 (8), e_phentsize @0x36 (2), e_phnum @0x38 (2)
        e_phoff = struct.unpack_from(endian + 'Q', data, 0x20)[0]
        # read more if needed
        if e_phoff + 56 > len(data):
            try:
                with open(img_path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                sys.stderr.write(f"[error] failed to read full ELF: {e}\n")
                sys.stderr.flush()
                return base, base
        e_phentsize = struct.unpack_from(endian + 'H', data, 0x36)[0]
        e_phnum = struct.unpack_from(endian + 'H', data, 0x38)[0]
        if e_phentsize == 0 or e_phnum == 0:
            return base, base
        ph_min = None
        ph_max = None
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            p_type = struct.unpack_from(endian + 'I', data, off)[0]
            if p_type != 1:  # PT_LOAD
                continue
            p_vaddr = struct.unpack_from(endian + 'Q', data, off + 0x10)[0]
            p_memsz = struct.unpack_from(endian + 'Q', data, off + 0x28)[0]
            if p_memsz == 0:
                continue
            seg_start = p_vaddr
            seg_end = p_vaddr + p_memsz
            ph_min = seg_start if ph_min is None else min(ph_min, seg_start)
            ph_max = seg_end if ph_max is None else max(ph_max, seg_end)
        if ph_min is not None and ph_max is not None and ph_max > ph_min:
            length = ph_max - ph_min
            return base, base + int(length)
    else:
        sys.stderr.write("[error] unsupported ELF class for range computation\n")
        sys.stderr.flush()

def _validate_execution_state_value(value: Union[bytes, int], valid_values_config: dict) -> Union[bytes, int]:
    if not valid_values_config:
        return value
        
    val_type = valid_values_config.get('type')
    
    try:
        if val_type == 'enum':
            if isinstance(value, (bytes, bytearray)):
                int_val = int.from_bytes(value, byteorder='little')
            else:
                int_val = value
            
            allowed_values = valid_values_config.get('values', [])
            if int_val in allowed_values:
                return int_val
            else:
                raise ValueError(f"Invalid enum value: {int_val} not in allowed values {allowed_values}")
                
        elif val_type == 'int':
            if isinstance(value, (bytes, bytearray)):
                int_val = int.from_bytes(value, byteorder='little', signed=valid_values_config.get('signed', False))
            else:
                int_val = value
                
            val_range = valid_values_config.get('range', [])
            if len(val_range) == 2:
                min_val, max_val = val_range
                if min_val <= int_val <= max_val:
                    return int_val
                else:
                    raise ValueError(f"Integer value {int_val} out of range [{min_val}, {max_val}]")
            return int_val
            
        elif val_type == 'bytes':
            if not isinstance(value, (bytes, bytearray)):
                if isinstance(value, int):
                    value = value.to_bytes(4, byteorder='little')
                else:
                    raise ValueError(f"Cannot convert {type(value)} to bytes")
            
            if isinstance(value, bytearray):
                value = bytes(value)
                
            expected_length = valid_values_config.get('length')
            if expected_length is not None and len(value) != expected_length:
                raise ValueError(f"Bytes length {len(value)} does not match expected length {expected_length}")
                    
            alphabet = valid_values_config.get('alphabet', [])
            if alphabet:
                for i, byte_val in enumerate(value):
                    if byte_val not in alphabet:
                        raise ValueError(f"Invalid byte 0x{byte_val:02x} at position {i}, not in allowed alphabet")
                
            return value
            
        elif val_type == 'float':
            if isinstance(value, bytes):
                if len(value) == 4:
                    import struct
                    float_val = struct.unpack('<f', value)[0]
                elif len(value) == 8:
                    import struct
                    float_val = struct.unpack('<d', value)[0]
                else:
                    raise ValueError(f"Invalid byte length {len(value)} for float (expected 4 or 8)")
            else:
                float_val = float(value)
                
            val_range = valid_values_config.get('range', [])
            if len(val_range) == 2:
                min_val, max_val = val_range
                if min_val <= float_val <= max_val:
                    return value if isinstance(value, bytes) else float_val
                else:
                    raise ValueError(f"Float value {float_val} out of range [{min_val}, {max_val}]")
            return value if isinstance(value, bytes) else float_val
            
    except Exception as e:
        sys.stderr.write(f"[warning] validation failed for value {value}: {e}\n")
        sys.stderr.flush()
        return None
        
    return None

def _coerce_value_to_int(value: Union[bytes, bytearray, int]) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, byteorder='little', signed=False)

def _eval_predicate_expression(expr: str, env: dict) -> bool:
    expr = (expr or '').replace('&&', ' and ').replace('||', ' or ')
    def _replace_name(match: re.Match) -> str:
        name = match.group(0)
        if name in ("and", "or", "not", "True", "False"):
            return name
        if name in env:
            try:
                return str(_coerce_value_to_int(env[name]))
            except Exception:
                return "0"
        return "0"
    substituted = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", _replace_name, expr)
    try:
        return bool(eval(substituted, {"__builtins__": {}}, {}))
    except Exception:
        return False

def execute_with_qiling(input_data: bytes, run_config: dict, force_stdout: bool = False, show_execution_values: bool = False) -> ExecutionResult:
    start_time = time.time()
    crash_info = None
    ql = None
    execution_value_samples: dict = {}
    execution_outcome = ExecutionOutcome.NORMAL

    BINARY_PATH = run_config['target']['binary']
    ROOTFS_PATH = run_config['target']['rootfs']
    PER_RUN_TIMEOUT = run_config['fuzzer'].get('per_run_timeout', 0)
    STDOUT = run_config['fuzzer'].get('stdout', False) or force_stdout
    MAP_SIZE = 1 << 16
    EXECUTION_VALUES_DICT = run_config['fuzzer']['execution_values']

    cov_bitmap = bytearray(MAP_SIZE)
    prev_loc = [0]
    branch_taken = bytearray(MAP_SIZE)
    branch_fallthrough = bytearray(MAP_SIZE)
    last_block_end = [None]
    instr_addresses: set[int] = set()
    total_instructions = [0]
    pathlen_blocks = [0]
    call_depth = [0]

    cs = None
    if Cs is None:
        sys.stderr.write("[error] capstone not available; call_depth measurement unavailable\n")
        sys.stderr.flush()

    try:
        _ = input_data.decode('utf-8')
    except UnicodeDecodeError:
        input_data = input_data.decode('utf-8', errors='replace').encode('utf-8')

    try:
        if STDOUT:
            print(f"Executing with input: {input_data.decode(errors='replace')}")
        ql = Qiling([BINARY_PATH], ROOTFS_PATH, console=False)

        img = None
        for image in ql.loader.images:
            if BINARY_PATH in image.path:
                img = image
                break
        
        assert img is not None, f"Could not find {BINARY_PATH} image in loaded images: {[img.path for img in ql.loader.images]}"
        
        img_base, img_end = _compute_image_range(img)

        if Cs is not None:
            try:
                is_64 = int(getattr(ql.arch, 'bits', 64)) == 64
                cs = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
            except Exception:
                cs = None

        ql.add_fs_mapper('/dev/urandom', '/dev/urandom')
        ql.add_fs_mapper('/dev/random', '/dev/urandom')

        for state_item in EXECUTION_VALUES_DICT:
            name = state_item['name']
            mode = state_item['read']['mode']
            valid_values_config = state_item.get('valid_values', {})
            
            if mode == 'register_direct':
                capture_pc_offset = state_item['read']['capture_pc_offset']
                reg = state_item['read']['reg']
                size = state_item['read']['size']
                def make_capture_function(state_name, register, capture_size, validation_config):
                    def capture_state_at_address(ql: Qiling, address: int, size_param: int):
                        reg_value = getattr(ql.arch.regs, register)
                        reg_bytes = reg_value.to_bytes(8, byteorder='little')[:capture_size]
                        
                        validated_value = _validate_execution_state_value(reg_bytes, validation_config)
                        if validated_value is None:
                            return
                        execution_value_samples.setdefault(state_name, []).append(validated_value)
                    return capture_state_at_address
                hook_func = make_capture_function(name, reg, size, valid_values_config)
                ql.hook_code(hook_func, begin=img.base + capture_pc_offset, end=img.base + capture_pc_offset + 1)
            elif mode == 'register_deref':
                capture_pc_offset = state_item['read']['capture_pc_offset']
                reg = state_item['read']['reg']
                ptr_size = state_item['read']['ptr_size']
                size = state_item['read']['size']
                def make_deref_capture_function(state_name, register, capture_size, validation_config):
                    def capture_state_at_address(ql: Qiling, address: int, size_param: int):
                        reg_value = getattr(ql.arch.regs, register)
                        data = ql.mem.read(reg_value, capture_size)
                        validated_value = _validate_execution_state_value(data, validation_config)
                        if validated_value is None:
                            return
                        execution_value_samples.setdefault(state_name, []).append(validated_value)
                        return
                    return capture_state_at_address
                hook_func = make_deref_capture_function(name, reg, size, valid_values_config)
                ql.hook_code(hook_func, begin=img.base + capture_pc_offset, end=img.base + capture_pc_offset + 1)
            elif mode == 'mem_offset':
                capture_pc_offset = state_item['read']['capture_pc_offset']
                offset_from_image = state_item['read']['offset_from_image']
                size = state_item['read']['size']
                def make_mem_capture_function(state_name, offset, capture_size, validation_config):
                    def capture_state_at_address(ql: Qiling, address: int, size_param: int):
                        data = ql.mem.read(img.base + offset, capture_size)
                        validated_value = _validate_execution_state_value(data, validation_config)
                        if validated_value is None:
                            return
                        execution_value_samples.setdefault(state_name, []).append(validated_value)
                        return
                    return capture_state_at_address
                hook_func = make_mem_capture_function(name, offset_from_image, size, valid_values_config)
                ql.hook_code(hook_func, begin=img.base + capture_pc_offset, end=img.base + capture_pc_offset + 1)

        def block_cov_cb(ql, address, size):
            cur = ((address >> 4) ^ (address << 8)) & 0xFFFFFFFF
            idx = (cur ^ prev_loc[0]) & (MAP_SIZE - 1)
            if cov_bitmap[idx] != 0xFF:
                cov_bitmap[idx] = (cov_bitmap[idx] + 1) & 0xFF
            prev_loc[0] = cur >> 1
            pathlen_blocks[0] += 1
            if last_block_end[0] is not None:
                site_hash = ((last_block_end[0] >> 4) ^ (last_block_end[0] << 8)) & 0xFFFFFFFF
                site_idx = site_hash & (MAP_SIZE - 1)
                if address == last_block_end[0]:
                    branch_fallthrough[site_idx] = 1
                else:
                    branch_taken[site_idx] = 1
            last_block_end[0] = address + size

        ql.hook_block(block_cov_cb)

        def instruction_cov_cb(ql, address, size):
            instr_addresses.add(address)
            total_instructions[0] += 1
            inside_module = (img_end > img_base) and (img_base <= address < img_end)

            if cs is None:
                return

            try:
                data = ql.mem.read(address, int(size))
            except Exception:
                return

            for insn in cs.disasm(data, address):
                mnem = (insn.mnemonic or "").lower()
                if inside_module and mnem.startswith('call'):
                    call_depth[0] += 1
                elif mnem.startswith('ret'):
                    if call_depth[0] > 0:
                        call_depth[0] -= 1

        ql.hook_code(instruction_cov_cb)

        input_fd = 100
        ql.os.fd[input_fd] = _InputFD(input_data)

        def read_hook(ql, fd, buf, count):
            if fd != 0:
                return None

            try:
                prim = ql.os.fd[input_fd]
            except Exception:
                prim = None
            if prim is not None and getattr(prim, '_pos', 0) < len(getattr(prim, '_data', b'')):
                return (None, [input_fd, buf, count])

            try:
                ql.emu_stop()
            except Exception:
                pass
            return (-1, [fd, buf, count])

        ql.os.set_syscall('read', read_hook, intercept=QL_INTERCEPT.ENTER)

        stdout_buffer = bytearray()

        def write_call_hook(ql, fd, buf, count):
            try:
                data = ql.mem.read(buf, count)
            except Exception:
                return -1
            if fd in (0, 1):
                try:
                    stdout_buffer.extend(data)
                except Exception:
                    pass
                if STDOUT:
                    try:
                        sys.stdout.buffer.write(data)
                    except Exception:
                        sys.stdout.write(data.decode(errors='ignore'))
                    sys.stdout.flush()
            elif fd == 2:
                try:
                    sys.stderr.buffer.write(data)
                except Exception:
                    sys.stderr.write(data.decode(errors='ignore'))
                sys.stderr.flush()
            return count

        ql.os.set_syscall('write', write_call_hook, intercept=QL_INTERCEPT.CALL)
                
        ql.os.stdin = pipe.SimpleInStream(0)
        ql.os.stdin.write(input_data)
        
        run_done = threading.Event()
        run_exc: List[BaseException] = []

        def _runner():
            try:
                prev_loc[0] = 0
                last_block_end[0] = None
                instr_addresses.clear()
                ql.run()
            except BaseException as e:
                run_exc.append(e)
            finally:
                run_done.set()

        t = threading.Thread(target=_runner, daemon=True)
        t.start()

        per_run_timeout = float(PER_RUN_TIMEOUT)
        if per_run_timeout and per_run_timeout > 0:
            t.join(per_run_timeout)
        else:
            t.join()

        if not run_done.is_set():
            try:
                ql.emu_stop()
            except Exception:
                pass
            t.join(0.25)
            execution_time = time.time() - start_time
            if not run_done.is_set():
                execution_outcome = ExecutionOutcome.HANG
            else:
                execution_outcome = ExecutionOutcome.TIMEOUT
        else:
            if run_exc:
                raise run_exc[0]
            execution_time = time.time() - start_time
            execution_outcome = ExecutionOutcome.NORMAL
        
    except Exception as e:
        execution_time = time.time() - start_time
        execution_outcome = ExecutionOutcome.CRASH
        crash_info = f"{type(e).__name__}: {str(e)}"
        if 'stdout_buffer' not in locals():
            stdout_buffer = bytearray()
        if 'cov_bitmap' not in locals():
            cov_bitmap = None
        if 'branch_taken' not in locals():
            branch_taken = None
        if 'branch_fallthrough' not in locals():
            branch_fallthrough = None
        if 'instr_addresses' not in locals():
            instr_addresses = None
        if 'total_instructions' not in locals():
            total_instructions = 0
        if 'pathlen_blocks' not in locals():
            pathlen_blocks = 0
        if 'call_depth' not in locals():
            call_depth = 0
    
    if show_execution_values:
        for name, values in execution_value_samples.items():
            print(f"{name}: {values}")
    
    state_spec = run_config['fuzzer']['execution_state']

    latest_values = {k: v_list[-1] for k, v_list in execution_value_samples.items() if v_list}

    computed_state = []
    for item in state_spec:
        item_type = item['type']
        if item_type == 'value':
            name = item['name']
            if name in latest_values:
                computed_state.append(f"{name} (value)")
                computed_state.append(latest_values[name])
        elif item_type == 'sum':
            name = item['name']
            values = execution_value_samples.get(name, [])
            total = 0
            for v in values:
                total += _coerce_value_to_int(v)
            computed_state.append(f"{name} (sum)")
            computed_state.append(total)
        elif item_type == 'predicate':
            expr = item['expr']
            fired = _eval_predicate_expression(expr, latest_values)
            if show_execution_values:
                try:
                    print(f"PRED env: {latest_values}")
                    print(f"PRED expr: {expr} -> {fired}")
                except Exception:
                    pass
            computed_state.append(expr)
            computed_state.append(1 if fired else 0)
        elif item_type == 'counter':
            expr = item['expr']
            count = 0
            max_length = max((len(values) for values in execution_value_samples.values()), default=0)
            
            for i in range(max_length):
                step_values = {}
                for name, values in execution_value_samples.items():
                    if i < len(values):
                        step_values[name] = values[i]
                
                if _eval_predicate_expression(expr, step_values):
                    count += 1
            
            if show_execution_values:
                try:
                    print(f"COUNTER expr: {expr} -> {count} times")
                except Exception:
                    pass
            computed_state.append(f"{expr} (count)")
            computed_state.append(count)
        elif item_type == 'set':
            name = item['name']
            values = execution_value_samples.get(name, [])

            unique_values = set()
            for v in values:
                if isinstance(v, (bytes, bytearray)):
                    unique_values.add(v)
                elif isinstance(v, int):
                    unique_values.add(v)
                else:
                    unique_values.add(str(v))
            
            if show_execution_values:
                try:
                    print(f"SET {name}: {tuple(sorted(unique_values))}")
                except Exception:
                    pass
            computed_state.append(f"{name} (set)")
            computed_state.append(tuple(sorted(unique_values)))

    return ExecutionResult(
        input_data=input_data,
        execution_outcome=execution_outcome,
        execution_time=execution_time,
        crash_info=crash_info,
        execution_state=tuple(computed_state),
        stdout=(stdout_buffer.decode(errors='replace') if 'stdout_buffer' in locals() else None),
        cov_bitmap=cov_bitmap,
        branch_taken_bitmap=branch_taken,
        branch_fallthrough_bitmap=branch_fallthrough,
        instr_address_set=(instr_addresses if isinstance(instr_addresses, set) else None),
        total_instructions=total_instructions[0],
        pathlen_blocks=pathlen_blocks[0],
        call_depth=call_depth[0],
    )