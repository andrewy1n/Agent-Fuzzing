import time
from .models import ExecutionResult, ExecutionOutcome
from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.extensions import pipe
from typing import List
import threading
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

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
    # Parse ELF on disk to determine PT_LOAD span, then relocate by runtime base
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

def execute_with_qiling(input_data: bytes, run_config: dict, force_stdout: bool = False) -> ExecutionResult:
    start_time = time.time()
    crash_info = None
    ql = None
    mutable_state = []
    execution_outcome = ExecutionOutcome.NORMAL

    BINARY_PATH = run_config['target']['binary']
    ROOTFS_PATH = run_config['target']['rootfs']
    PER_RUN_TIMEOUT = run_config['fuzzer'].get('per_run_timeout', 0)
    STDOUT = run_config['fuzzer'].get('stdout', False) or force_stdout
    MAP_SIZE = 1 << 16
    EXECUTION_STATE_DICT = run_config['fuzzer']['execution_state']

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

        for state_item in EXECUTION_STATE_DICT:
            name = state_item['name']
            offset = state_item['address_offset']
            regs = state_item['regs']
            def capture_state_at_address(ql: Qiling, address: int, size: int):
                mutable_state.append(name)
                for reg in regs:
                    reg_value = getattr(ql.arch.regs, reg)
                    mutable_state.append(reg_value)
                return
            ql.hook_code(capture_state_at_address, begin=img.base + offset, end=img.base + offset + 1)

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
    
    return ExecutionResult(
        input_data=input_data,
        execution_outcome=execution_outcome,
        execution_time=execution_time,
        crash_info=crash_info,
        execution_state=tuple(mutable_state),
        stdout=(stdout_buffer.decode(errors='replace') if 'stdout_buffer' in locals() else None),
        cov_bitmap=cov_bitmap,
        branch_taken_bitmap=branch_taken,
        branch_fallthrough_bitmap=branch_fallthrough,
        instr_address_set=(instr_addresses if isinstance(instr_addresses, set) else None),
        total_instructions=total_instructions[0],
        pathlen_blocks=pathlen_blocks[0],
        call_depth=call_depth[0],
    )