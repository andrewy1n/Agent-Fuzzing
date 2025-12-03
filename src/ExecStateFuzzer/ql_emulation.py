import time
from .models import ExecutionResult, ExecutionOutcome, FunctionHotspot
from qiling import Qiling
from qiling.extensions import pipe
from typing import List, Union
import threading
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import re

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

def _load_func_symbols_safe(elf_path: str):
    try:
        from elftools.elf.elffile import ELFFile
        out = []
        with open(elf_path, "rb") as f:
            ef = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = ef.get_section_by_name(secname)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    try:
                        st = sym.entry
                        if sym['st_info']['type'] == 'STT_FUNC' and st.st_size and sym.name:
                            start = st.st_value
                            out.append((start, start + st.st_size, sym.name))
                    except Exception:
                        pass
        out.sort(key=lambda x: x[0])
        starts = [s for s, _, _ in out]
        return out, starts
    except Exception:
        return [], []

def _resolve_symbol_name(symtab, starts, addr: int, img_base: int | None = None) -> str:
    if not symtab:
        return f"0x{addr:x}"
    from bisect import bisect_right
    # Try absolute address first
    i = bisect_right(starts, addr) - 1
    if i >= 0:
        s, e, n = symtab[i]
        if s <= addr < e:
            return n
    # Then try module-relative (e.g., PIE mapped at img_base)
    if img_base is not None:
        rel = addr - img_base
        i = bisect_right(starts, rel) - 1
        if i >= 0:
            s, e, n = symtab[i]
            if s <= rel < e:
                return n
        # Fallback to a readable module-relative offset
        return f"+0x{rel:x}"
    return f"0x{addr:x}"

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

    BINARY_PATH = run_config['target'].get('binary_path') or run_config['target'].get('binary')
    ROOTFS_PATH = run_config['target']['rootfs']
    PER_RUN_TIMEOUT = run_config['fuzzer'].get('per_run_timeout', 0)
    STDOUT = run_config['fuzzer'].get('stdout', False) or force_stdout
    MAP_SIZE = 1 << 16

    fp_cfg = run_config['fuzzer'].get('function_profile', {})
   
    PROFILE_ENABLED = True
    SAMPLE_EVERY = int(fp_cfg.get('sample_every', 100))
    TOP_N = int(fp_cfg.get('top_n', 10))
    TARGET_ONLY = bool(fp_cfg.get('target_only', True))

    if PROFILE_ENABLED:
        symtab, starts = _load_func_symbols_safe(BINARY_PATH)
        samples = {}
        sample_i = [0]
    else:
        symtab, starts, samples, sample_i = [], [], {}, [0]

    # Convert execution_values list to dict for efficient lookup
    execution_values_list = run_config['fuzzer'].get('execution_values') or []
    EXECUTION_VALUES_DICT = {item['name']: item for item in execution_values_list}

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
        if STDOUT:
            print(f"Executing with input: {input_data.decode('latin-1')}")
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

            if PROFILE_ENABLED:
                sample_i[0] += 1
                if sample_i[0] % SAMPLE_EVERY == 0 and ((not TARGET_ONLY) or inside_module):
                    name = _resolve_symbol_name(symtab, starts, address, img_base if inside_module else None)
                    samples[name] = samples.get(name, 0) + 1

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
            if ql.internal_exception is not None:
                execution_outcome = ExecutionOutcome.CRASH
                crash_info = f"{ql.internal_exception}"
            else:
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
            total_instructions = [0]
        if 'pathlen_blocks' not in locals():
            pathlen_blocks = [0]
        if 'call_depth' not in locals():
            call_depth = [0]
    
    function_hotspots = []
    if PROFILE_ENABLED and samples:
        total = sum(samples.values()) or 1
        top = sorted(samples.items(), key=lambda kv: kv[1], reverse=True)[:TOP_N]
        for name, cnt in top:
            pct = 100.0 * cnt / total
            function_hotspots.append(FunctionHotspot(symbol=name, count=cnt, percentage=pct))
    
    # Parse execution values from stdout
    if 'stdout_buffer' in locals() and stdout_buffer:
        try:
            stdout_text = stdout_buffer.decode('latin-1')
            for line in stdout_text.splitlines():
                line = line.strip()
                # Look for "name: value" patterns anywhere in the line
                for exec_name in EXECUTION_VALUES_DICT.keys():
                    pattern = f"{exec_name}:"
                    if pattern in line:
                        # Extract the value after "name:"
                        idx = line.find(pattern)
                        value_part = line[idx + len(pattern):].strip()

                        # Take only the first token (split by whitespace)
                        value_str = value_part.split()[0] if value_part.split() else value_part

                        # Parse value based on type
                        exec_value_def = EXECUTION_VALUES_DICT[exec_name]
                        value_type = exec_value_def.get('type', 'string')

                        try:
                            if value_type == 'int':
                                value = int(value_str)
                            elif value_type == 'float':
                                value = float(value_str)
                            elif value_type == 'bool':
                                value = int(value_str) if value_str.isdigit() else (1 if value_str.lower() in ('true', 'yes', '1') else 0)
                            else:
                                value = value_str

                            # Store the value
                            if exec_name not in execution_value_samples:
                                execution_value_samples[exec_name] = []
                            execution_value_samples[exec_name].append(value)
                        except (ValueError, TypeError, IndexError):
                            pass
        except Exception:
            pass

    if show_execution_values:
        for name, values in execution_value_samples.items():
            print(f"{name}: {values}")

    state_spec = run_config['fuzzer'].get('execution_state') or []

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
        stdout=(stdout_buffer.decode('latin-1') if 'stdout_buffer' in locals() else None),
        cov_bitmap=cov_bitmap,
        branch_taken_bitmap=branch_taken,
        branch_fallthrough_bitmap=branch_fallthrough,
        instr_address_set=(instr_addresses if isinstance(instr_addresses, set) else None),
        total_instructions=total_instructions[0],
        pathlen_blocks=pathlen_blocks[0],
        call_depth=call_depth[0],
        function_hotspots=function_hotspots,
    )