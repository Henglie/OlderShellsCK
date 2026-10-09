#!/usr/bin/env python3
"""PE32 exception/context observer, NOT a full tmdunpacker port.

Each ntdll entry hook is consumed once: restore the byte, rewind EIP, never
time-rearm it. No TF/DRx dependency and no claim of continuous single stepping.
An input-entry synchronization INT3 excludes loader NtContinue traffic; it is
counted separately and does not establish an original entry point (OEP).
KUED32 is a kernel transfer: [ESP]=EXCEPTION_RECORD*, [ESP+4]=CONTEXT*.
NtContinue32 is stdcall: [ESP]=return address, [ESP+4]=CONTEXT*, [ESP+8]=alert.
Only planted INT3 hits count as bpHits; events counts all DEBUG_EVENTs.
See docs/research/instrument-implementation.md for original DLL evidence.

py -3.11 -X utf8 dump_instrument.py sample.exe dump.bin [seconds] [max_events] [args_json]
--self-test / --stat sample.exe do not launch a target.
Exit: 0 success, 2 invalid/unsupported input, 5 tool failure, 7 hooks unavailable.
The last stdout line is JSON; <dump>.imports.json is a runtime export snapshot.
"""
import ctypes
import ctypes.wintypes as wt
import json
import math
import os
import subprocess
import sys
import time

P = ctypes.c_void_p
S = ctypes.c_size_t
D = ctypes.c_uint32
W = ctypes.c_uint16
MAX_IMAGE = 0x8000000
MAX_HEADER = 0x100000
CTX_CONTROL = 0x10001
DBG_CONTINUE = 0x10002
DBG_NOT_HANDLED = 0x80010001
BREAKPOINT = 0x80000003
KILL_ON_CLOSE = 0x2000


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [(n, D) for n in ("ControlWord", "StatusWord", "TagWord", "ErrorOffset",
                               "ErrorSelector", "DataOffset", "DataSelector")] + [
        ("RegisterArea", ctypes.c_ubyte * 80), ("Cr0NpxState", D)]


class CONTEXT(ctypes.Structure):
    _fields_ = [(n, D) for n in ("ContextFlags", "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7")] + [
        ("FloatSave", FLOATING_SAVE_AREA)] + [(n, D) for n in (
        "SegGs", "SegFs", "SegEs", "SegDs", "Edi", "Esi", "Ebx", "Edx", "Ecx", "Eax",
        "Ebp", "Eip", "SegCs", "EFlags", "Esp", "SegSs")] + [
        ("ExtendedRegisters", ctypes.c_ubyte * 512)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", D), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR)] + [
        (n, D) for n in ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars",
                        "dwFillAttribute", "dwFlags")] + [
        ("wShowWindow", W), ("cbReserved2", W), ("lpReserved2", P),
        ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", D), ("dwThreadId", D)]


class EXCEPTION_RECORD(ctypes.Structure):  # debugger HOST ABI (not the remote x86 record)
    _fields_ = [("ExceptionCode", D), ("ExceptionFlags", D), ("ExceptionRecord", P),
                ("ExceptionAddress", P), ("NumberParameters", D), ("ExceptionInformation", S * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", D)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE)] + [
        ("lpBaseOfImage", P), ("dwDebugInfoFileOffset", D),
        ("nDebugInfoSize", D), ("lpThreadLocalBase", P), ("lpStartAddress", P),
        ("lpImageName", P), ("fUnicode", W)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", wt.HANDLE), ("lpThreadLocalBase", P), ("lpStartAddress", P)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("lpBaseOfDll", P), ("dwDebugInfoFileOffset", D),
                ("nDebugInfoSize", D), ("lpImageName", P), ("fUnicode", W)]


class DEBUG_UNION(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("CreateThread", CREATE_THREAD_DEBUG_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO), ("ExitCode", D)]


class DEBUG_EVENT(ctypes.Structure):
    _anonymous_ = ["u"]
    _fields_ = [("dwDebugEventCode", D), ("dwProcessId", D), ("dwThreadId", D), ("u", DEBUG_UNION)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOB_LIMITS(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", D), ("MinimumWorkingSetSize", S), ("MaximumWorkingSetSize", S),
                ("ActiveProcessLimit", D), ("Affinity", S), ("PriorityClass", D), ("SchedulingClass", D)]


class JOB_EXTENDED_LIMITS(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOB_LIMITS), ("IoInfo", IO_COUNTERS)] + [
        (n, S) for n in ("ProcessMemoryLimit", "JobMemoryLimit", "PeakProcessMemoryUsed", "PeakJobMemoryUsed")]


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", P), ("AllocationBase", P), ("AllocationProtect", D),
                ("RegionSize", S), ("State", D), ("Protect", D), ("Type", D)]


def number(b, offset, size):
    if offset < 0 or offset + size > len(b):
        raise ValueError("truncated PE/record")
    return int.from_bytes(b[offset:offset + size], "little")


def u16(b, offset):
    return number(b, offset, 2)


def u32(b, offset):
    return number(b, offset, 4)


def user_span(addr, size):
    return isinstance(addr, int) and isinstance(size, int) and 0x10000 <= addr < 0xffff0000 and \
        0 < size <= MAX_IMAGE and addr + size <= 0xffff0000


def parse_pe_summary(b):
    if len(b) < 64 or b[:2] != b"MZ":
        raise ValueError("not PE")
    e = u32(b, 0x3c)
    if not 0x40 <= e <= MAX_HEADER - 24 or b[e:e + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    optional, opt_size, count = e + 24, u16(b, e + 20), u16(b, e + 6)
    magic = u16(b, optional)
    if magic not in (0x10b, 0x20b) or opt_size < (96 if magic == 0x10b else 112):
        raise ValueError("invalid optional header")
    table = optional + opt_size
    headers, size, ep = u32(b, optional + 60), u32(b, optional + 56), u32(b, optional + 16)
    if not 1 <= count <= 96 or table + count * 40 > min(len(b), headers) or not headers <= size <= MAX_IMAGE:
        raise ValueError("invalid image/header/section range")
    ndirs = u32(b, optional + (92 if magic == 0x10b else 108))
    directory = optional + (96 if magic == 0x10b else 112)
    if ndirs > 16 or directory + ndirs * 8 > table or ep >= size:
        raise ValueError("invalid directory/entry range")
    sections = []
    for i in range(count):
        at = table + i * 40
        vs, va, rs, raw = (u32(b, at + o) for o in (8, 12, 16, 20))
        if va + max(vs, rs) > MAX_IMAGE:
            raise ValueError("section range too large")
        sections.append({"name": b[at:at + 8].split(b"\0", 1)[0].decode("latin-1"),
                         "va": va, "vs": vs, "rs": rs, "raw": raw, "flags": u32(b, at + 36)})
    return {"machine": u16(b, e + 4), "magic": magic, "characteristics": u16(b, e + 22),
            "epRva": ep, "sizeOfImage": size, "sizeOfHeaders": headers, "sections": sections,
            "optional": optional, "directory": directory, "directoryCount": ndirs,
            "subsystem": u16(b, optional + 68),
            "managed": bool(ndirs > 14 and u32(b, directory + 14 * 8))}


def stat_sample(path):
    size = os.stat(path).st_size
    if not 64 <= size <= MAX_IMAGE:
        raise ValueError("invalid input size")
    with open(path, "rb") as f:
        b = f.read(MAX_HEADER)
    pe = parse_pe_summary(b)
    if pe["machine"] != 0x14c or pe["magic"] != 0x10b or pe["characteristics"] & 0x2000 or \
            not pe["characteristics"] & 2 or pe["managed"] or pe["subsystem"] not in (2, 3):
        raise ValueError("unsupported-input: requires native x86 PE32 EXE (no DLL/CLR/driver)")
    if pe["sizeOfHeaders"] > size or not pe["epRva"]:
        raise ValueError("invalid input headers/entry")
    for s in pe["sections"]:
        if s["rs"] and (s["raw"] < pe["sizeOfHeaders"] or s["raw"] + s["rs"] > size):
            raise ValueError("truncated section data")
    return pe


def context_valid(ptr, b):
    if not user_span(ptr, ctypes.sizeof(CONTEXT)) or ptr % 4 or b is None or len(b) < 0xcc:
        return False
    return u32(b, 0) & CTX_CONTROL == CTX_CONTROL and u32(b, 0xbc) in (0x1b, 0x23) and \
        bool(u32(b, 0xc0) & 2) and user_span(u32(b, 0xb8), 1) and user_span(u32(b, 0xc4), 4)


def decode_hook(kind, esp, read):
    # No ABI guessing/fallback scans: these two entries have different first stack slots.
    stack = read(esp, 12)
    ptr = u32(stack, 4) if stack is not None else 0
    raw = read(ptr, ctypes.sizeof(CONTEXT)) if user_span(ptr, ctypes.sizeof(CONTEXT)) else None
    result = {"stackPointer": esp, "contextPointer": ptr, "validContext": context_valid(ptr, raw),
              "abi": "kued32-kernel-transfer" if kind == "kued" else "ntcontinue32-stdcall"}
    if result["validContext"]:
        result.update(eip=u32(raw, 0xb8), esp=u32(raw, 0xc4), eflags=u32(raw, 0xc0))
    if stack is not None and kind == "kued":
        rec = u32(stack, 0)
        exr = read(rec, 80) if user_span(rec, 80) else None
        result["exceptionPointer"] = rec
        if exr is not None and u32(exr, 16) <= 15:
            result.update(code=u32(exr, 0), exceptionAddress=u32(exr, 12))
    elif stack is not None:
        result.update(returnAddress=u32(stack, 0), testAlert=u32(stack, 8))
    return result


def oep_candidates(observations, base, pe, cap=8):
    shell = next((s for s in pe["sections"] if s["va"] <= pe["epRva"] < s["va"] + max(s["vs"], s["rs"])), None)
    counts = {}
    for item in observations:
        if not item.get("validContext") or not item.get("executableLanding"):
            continue
        rva = item["eip"] - base
        if not 0 < rva < pe["sizeOfImage"]:
            continue
        if shell and shell["va"] <= rva < shell["va"] + max(shell["vs"], shell["rs"]):
            continue
        if any(s["flags"] & 0x20000000 and s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]) for s in pe["sections"]):
            counts[rva] = counts.get(rva, 0) + 1
    return sorted(counts, key=lambda r: (-counts[r], r))[:cap]  # exact RVAs, not rounded instructions


def run_self_test():
    offsets = {n: getattr(CONTEXT, n).offset for n in ("FloatSave", "SegGs", "Eip", "EFlags", "Esp", "ExtendedRegisters")}
    assert ctypes.sizeof(FLOATING_SAVE_AREA) == 112
    assert FLOATING_SAVE_AREA.RegisterArea.offset == 28 and FLOATING_SAVE_AREA.Cr0NpxState.offset == 108
    assert ctypes.sizeof(CONTEXT) == 716
    assert offsets == {"FloatSave": 28, "SegGs": 140, "Eip": 184, "EFlags": 192, "Esp": 196, "ExtendedRegisters": 204}
    bits = ctypes.sizeof(P) * 8
    assert DEBUG_EVENT.u.offset == (16 if bits == 64 else 12)
    assert ctypes.sizeof(DEBUG_EVENT) == (176 if bits == 64 else 96)
    assert CREATE_PROCESS_DEBUG_INFO.nDebugInfoSize.offset == (36 if bits == 64 else 20)
    assert CREATE_PROCESS_DEBUG_INFO.lpThreadLocalBase.offset == (40 if bits == 64 else 24)
    assert ctypes.sizeof(JOB_EXTENDED_LIMITS) == (144 if bits == 64 else 112)
    assert DBG_NOT_HANDLED == 0x80010001  # 0x40010004 is DBG_TERMINATE_PROCESS
    ctx = CONTEXT(); ctx.ContextFlags = 0x10007; ctx.Eip = 0x401252; ctx.SegCs = 0x23
    ctx.EFlags = 0x202; ctx.Esp = 0x18fef0
    raw = bytes(ctx)
    exr = bytearray(80); exr[:4] = (0xc000001d).to_bytes(4, "little"); exr[12:16] = ctx.Eip.to_bytes(4, "little")
    memory = {0x18fe00: (0x18fe20).to_bytes(4, "little") + (0x18fe80).to_bytes(4, "little") + b"\0" * 4,
              0x18fe20: bytes(exr), 0x18fe80: raw}
    read = lambda a, n: memory[a][:n] if a in memory and len(memory[a]) >= n else None
    decoded = decode_hook("kued", 0x18fe00, read)
    assert decoded["validContext"] and decoded["eip"] == ctx.Eip and decoded["code"] == 0xc000001d
    memory[0x18fe00] = (0x401800).to_bytes(4, "little") + (0x18fe80).to_bytes(4, "little") + b"\0" * 4
    decoded = decode_hook("cont", 0x18fe00, read)
    assert decoded["returnAddress"] == 0x401800 and decoded["validContext"] and "code" not in decoded
    assert not context_valid(0x18fe81, raw) and not context_valid(0x18fe80, raw[:0xc4])
    bad = bytearray(raw); bad[0:4] = (7).to_bytes(4, "little")
    assert not context_valid(0x18fe80, bad)
    assert not user_span(0xffff0000 - 4, 8) and not user_span(0, 4) and not user_span(0x10000, -1)
    pe = {"epRva": 0xc000, "sizeOfImage": 0xd000, "sections": [
        {"va": 0x1000, "vs": 0xb000, "rs": 0, "flags": 0x20000000},
        {"va": 0xc000, "vs": 0x1000, "rs": 0x1000, "flags": 0x20000000}]}
    items = [{"validContext": True, "executableLanding": True, "eip": x} for x in (0x401252, 0x401252, 0x40c020, 0x500000)]
    assert oep_candidates(items, 0x400000, pe) == [0x1252]
    assert oep_candidates([], 0x400000, pe) == []
    try:
        parse_pe_summary(b"MZ" + b"\0" * 62)
        raise AssertionError("accepted invalid header")
    except ValueError:
        pass
    return {"ok": True, "checks": ["ctypes-offsets", "host-debug-event-abi", "job-abi", "kued32-stack",
                                   "ntcontinue32-stack", "context-range", "exact-candidate-range", "pe-header-range"],
            "contextSize": ctypes.sizeof(CONTEXT), "floatSaveSize": ctypes.sizeof(FLOATING_SAVE_AREA), "offsets": offsets}


def windows_api():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    n = ctypes.WinDLL("ntdll", use_last_error=True)
    def bind(dll, name, args, result=wt.BOOL):
        fn = getattr(dll, name); fn.argtypes = args; fn.restype = result
        return fn
    for name, args, result in (
        ("CreateProcessW", [wt.LPCWSTR, wt.LPWSTR, P, P, wt.BOOL, D, P, wt.LPCWSTR, P, P], wt.BOOL),
        ("CreateJobObjectW", [P, wt.LPCWSTR], wt.HANDLE),
        ("SetInformationJobObject", [wt.HANDLE, ctypes.c_int, P, D], wt.BOOL),
        ("AssignProcessToJobObject", [wt.HANDLE, wt.HANDLE], wt.BOOL),
        ("TerminateJobObject", [wt.HANDLE, D], wt.BOOL), ("TerminateProcess", [wt.HANDLE, D], wt.BOOL),
        ("CloseHandle", [wt.HANDLE], wt.BOOL), ("ResumeThread", [wt.HANDLE], D),
        ("OpenThread", [D, wt.BOOL, D], wt.HANDLE), ("WaitForSingleObject", [wt.HANDLE, D], D),
        ("ReadProcessMemory", [wt.HANDLE, P, P, S, P], wt.BOOL),
        ("WriteProcessMemory", [wt.HANDLE, P, P, S, P], wt.BOOL),
        ("FlushInstructionCache", [wt.HANDLE, P, S], wt.BOOL),
        ("VirtualQueryEx", [wt.HANDLE, P, P, S], S),
        ("VirtualProtectEx", [wt.HANDLE, P, S, D, P], wt.BOOL),
        ("WaitForDebugEvent", [P, D], wt.BOOL), ("ContinueDebugEvent", [D, D, D], wt.BOOL),
        ("GetStdHandle", [D], wt.HANDLE), ("PeekNamedPipe", [wt.HANDLE, P, D, P, P, P], wt.BOOL),
        ("K32EnumProcessModulesEx", [wt.HANDLE, P, D, P, D], wt.BOOL),
        ("K32GetModuleFileNameExW", [wt.HANDLE, P, wt.LPWSTR, D], D),
    ):
        bind(k, name, args, result)
    get_name, set_name = ("Wow64GetThreadContext", "Wow64SetThreadContext") if ctypes.sizeof(P) == 8 else ("GetThreadContext", "SetThreadContext")
    get_ctx = bind(k, get_name, [wt.HANDLE, ctypes.POINTER(CONTEXT)])
    set_ctx = bind(k, set_name, [wt.HANDLE, ctypes.POINTER(CONTEXT)])
    bind(n, "NtSuspendProcess", [wt.HANDLE], ctypes.c_int32)
    bind(n, "NtResumeProcess", [wt.HANDLE], ctypes.c_int32)
    return k, n, get_ctx, set_ctx


class Observer:
    def __init__(self, sample, output, pe, seconds, max_events, args):
        self.k, self.n, self.get_ctx, self.set_ctx = windows_api()
        self.sample, self.output, self.pe = sample, output, pe
        self.seconds, self.max_events, self.args = seconds, max_events, args
        self.pi = PROCESS_INFORMATION(); self.job = None
        self.handles = set(); self.threads = {}; self.pending = None
        self.base = 0; self.events = 0; self.sites = {}; self.observations = []
        self.loader_breaks = set(); self.cache = None; self.last_capture = 0
        self.hook_errors = []; self.parent_pipe = None
        self.entry_sync = None; self.entry_passed = False; self.ntdll_base = 0

    def own(self, h):
        if h:
            self.handles.add(int(h))
        return h

    def close(self, h):
        if h and int(h) in self.handles:
            self.k.CloseHandle(h); self.handles.remove(int(h))

    def close_debug_handles(self, ev):
        if ev.dwDebugEventCode == 3:
            info = ev.CreateProcessInfo
            values = {info.hFile, info.hProcess, info.hThread} - {self.pi.hProcess, self.pi.hThread, None}
        elif ev.dwDebugEventCode == 6:
            values = {ev.LoadDll.hFile} - {None}
        elif ev.dwDebugEventCode == 2:
            values = {ev.CreateThread.hThread} - {self.pi.hThread, None}
        else:
            values = set()
        for h in values:
            self.own(h); self.close(h)

    def read(self, addr, size):
        if not addr or not 0 < size <= MAX_IMAGE:
            return None
        buf = ctypes.create_string_buffer(size); got = S()
        if not self.k.ReadProcessMemory(self.pi.hProcess, P(addr), buf, size, ctypes.byref(got)) or got.value != size:
            if os.environ.get("INSTRUMENT_DEBUG"):
                print(f"read failed h={self.pi.hProcess} at={addr:#x} size={size:#x} werr={ctypes.get_last_error()}", file=sys.stderr, flush=True)
            return None
        return buf.raw

    def query(self, addr):
        mbi = MBI()
        return mbi if self.k.VirtualQueryEx(self.pi.hProcess, P(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) else None

    def write_byte(self, addr, byte):
        old = D(); got = S()
        if not self.k.VirtualProtectEx(self.pi.hProcess, P(addr), 1, 0x40, ctypes.byref(old)):
            raise OSError("hook VirtualProtectEx failed")
        try:
            if not self.k.WriteProcessMemory(self.pi.hProcess, P(addr), byte, 1, ctypes.byref(got)) or got.value != 1:
                raise OSError("hook WriteProcessMemory failed")
            if not self.k.FlushInstructionCache(self.pi.hProcess, P(addr), 1) or self.read(addr, 1) != byte:
                raise OSError("hook byte/cache verification failed")
        finally:
            previous = D()
            if not self.k.VirtualProtectEx(self.pi.hProcess, P(addr), 1, old.value, ctypes.byref(previous)):
                raise OSError("hook page protection restore failed")

    def header(self, base):
        b = self.read(base, 0x1000)
        if b is None or b[:2] != b"MZ":
            return None
        e = u32(b, 0x3c)
        if e + 24 > len(b):
            b = self.read(base, min(MAX_HEADER, e + 0x1000))
        if b is None or e + 24 > len(b):
            return None
        length = e + 24 + u16(b, e + 20) + u16(b, e + 6) * 40
        if length > len(b):
            b = self.read(base, length) if length <= MAX_HEADER else None
        try:
            return (b, parse_pe_summary(b)) if b is not None else None
        except ValueError as error:
            if os.environ.get("INSTRUMENT_DEBUG"):
                print(f"header {base:#x}: {error}", file=sys.stderr, flush=True)
            return None

    def cstr(self, addr, maximum=512):
        result = bytearray()
        while len(result) < maximum:
            chunk = self.read(addr + len(result), min(64, maximum - len(result)))
            if chunk is None:
                return None
            if b"\0" in chunk:
                return (result + chunk.split(b"\0", 1)[0]).decode("ascii", "replace")
            result.extend(chunk)
        return None

    def exports(self, base):
        header = self.header(base)
        if not header or header[1]["machine"] != 0x14c or header[1]["magic"] != 0x10b:
            return None
        b, pe = header
        if not pe["directoryCount"]:
            return None
        rva, size = u32(b, pe["directory"]), u32(b, pe["directory"] + 4)
        def data(r, n):
            return self.read(base + r, n) if 0 < r and r + n <= pe["sizeOfImage"] else None
        exp = data(rva, 40) if size >= 40 else None
        if exp is None or rva + size > pe["sizeOfImage"]:
            return None
        count, names = u32(exp, 20), u32(exp, 24)
        if not 1 <= count <= 65536 or not 0 <= names <= count:
            return None
        funcs = data(u32(exp, 28), count * 4)
        nr = data(u32(exp, 32), names * 4) if names else b""
        ords = data(u32(exp, 36), names * 2) if names else b""
        if funcs is None or nr is None or ords is None:
            return None
        by_index = {}
        for i in range(names):
            oi, name_rva = u16(ords, i * 2), u32(nr, i * 4)
            if oi < count and 0 < name_rva < pe["sizeOfImage"]:
                name = self.cstr(base + name_rva)
                if name:
                    by_index[oi] = name
        dll = self.cstr(base + u32(exp, 12)) or ""
        if not dll:
            return None
        result = []
        for i in range(count):
            r = u32(funcs, i * 4)
            if not 0 < r < pe["sizeOfImage"] or rva <= r < rva + size:
                continue  # forwarders are names, not callable VAs
            item = {"rva": hex(r)}
            if i in by_index:
                item["name"] = by_index[i]
            elif 1 <= u32(exp, 16) + i <= 65535:
                item["ordinal"] = u32(exp, 16) + i
            else:
                continue
            result.append(item)
        return {"dll": dll.upper(), "imageBase": hex(base), "exports": result}

    def module_bases(self):
        mods = (P * 4096)(); needed = D()
        if not self.k.K32EnumProcessModulesEx(self.pi.hProcess, mods, ctypes.sizeof(mods), ctypes.byref(needed), 1):
            return []
        return [int(x) for x in mods[:min(needed.value // ctypes.sizeof(P), 4096)] if x]

    def plant(self, base):
        if len(self.sites) == 2:
            return
        exports = self.exports(base)
        if not exports or exports["dll"] != "NTDLL.DLL":
            return
        self.ntdll_base = base
        if not self.entry_passed:
            return  # loader itself calls NtContinue; arm only after the INPUT entry sync
        for item in exports["exports"]:
            kind = {"KiUserExceptionDispatcher": "kued", "NtContinue": "cont"}.get(item.get("name"))
            if not kind:
                continue
            va = base + int(item["rva"], 16)
            if va in self.sites:
                continue  # consumed hooks stay consumed for the whole run
            original = self.read(va, 16)
            if original is None or original[0] == 0xcc:
                self.hook_errors.append("unreadable/already-INT3 " + item["name"])
                continue
            self.sites[va] = {"va": va, "kind": kind, "name": item["name"], "original": original[:1],
                              "entryBytes": original.hex(), "armed": False, "hits": 0}
            self.write_byte(va, b"\xcc")
            self.sites[va]["armed"] = True

    def hook_context(self, site, tid):
        h = self.threads.get(tid)
        if not h:
            h = self.own(self.k.OpenThread(0x1a, False, tid)); self.threads[tid] = h
        ctx = CONTEXT(); ctx.ContextFlags = CTX_CONTROL
        if not h or not self.get_ctx(h, ctypes.byref(ctx)) or ctx.Eip not in (site["va"], site["va"] + 1):
            raise OSError("hook thread context unavailable/mismatched")
        return h, ctx

    def restore_and_rewind(self, site, h, ctx):
        self.write_byte(site["va"], site["original"])
        site["armed"] = False
        ctx.Eip = site["va"]
        if not self.set_ctx(h, ctypes.byref(ctx)):
            raise OSError("hook EIP rewind failed")

    def hit(self, site, tid):
        # DEBUG_EVENT has stopped all threads. No timer can replant behind the rewound EIP.
        site["hits"] += 1
        h, ctx = self.hook_context(site, tid)
        obs = decode_hook(site["kind"], ctx.Esp, self.read)
        obs.update(source=site["kind"], hook=site["name"], hookVa=site["va"], threadId=tid)
        if obs["validContext"]:
            mbi = self.query(obs["eip"])
            obs["executableLanding"] = bool(mbi and mbi.State == 0x1000 and mbi.Protect & 0xf0)
        self.observations.append(obs)
        self.restore_and_rewind(site, h, ctx)

    def capture(self):
        # Always called while all threads are stopped (debug event or NtSuspendProcess).
        header = self.header(self.base)
        if not header:
            raise OSError("cannot read live PE header")
        size = header[1]["sizeOfImage"]
        if not user_span(self.base, size):
            raise OSError("invalid live image range")
        image = bytearray(size); unreadable = []
        at = self.base
        while at < self.base + size:
            mbi = self.query(at)
            if not mbi or not mbi.RegionSize or int(mbi.BaseAddress) + mbi.RegionSize <= at:
                raise OSError("image VirtualQueryEx failed")
            length = min(int(mbi.BaseAddress) + mbi.RegionSize, self.base + size) - at
            data = None
            if mbi.State == 0x1000:
                data = self.read(at, length) if not mbi.Protect & 0x100 else None
                if data is None:
                    old = D()
                    if self.k.VirtualProtectEx(self.pi.hProcess, P(at), length, 2, ctypes.byref(old)):
                        try:
                            data = self.read(at, length)
                        finally:
                            unused = D()
                            if not self.k.VirtualProtectEx(self.pi.hProcess, P(at), length, old.value, ctypes.byref(unused)):
                                raise OSError("dump page protection restore failed")
            if data is not None:
                image[at - self.base:at - self.base + length] = data
            else:
                unreadable.append({"rva": at - self.base, "size": length})
            at += length
        if unreadable:
            raise OSError("incomplete image: unreadable regions")
        modules = []
        for base in self.module_bases():
            item = self.exports(base)
            if item:
                modules.append(item)
        self.cache = (image, {"modules": modules}, header[1], time.monotonic())
        self.last_capture = time.monotonic()

    def capture_running(self):
        if self.n.NtSuspendProcess(self.pi.hProcess) < 0:
            raise OSError("NtSuspendProcess failed")
        try:
            self.capture()
        finally:
            if self.n.NtResumeProcess(self.pi.hProcess) < 0:
                raise OSError("NtResumeProcess failed")

    def finish(self, reason):
        source = "live"
        try:
            self.capture() if self.pending else self.capture_running()
        except OSError:
            if reason not in ("exit", "second-chance") or self.cache is None:
                raise
            source = "cached-live"
        if not self.sites or not any(s["armed"] or s["hits"] for s in self.sites.values()):
            return {"ok": False, "error": "instrumentation-blocked", "detail": self.hook_errors,
                    "stage": "instrumented", "events": self.events, "bpHits": 0}
        image, snapshot, pe, captured = self.cache
        with open(self.output, "wb") as f:
            f.write(image)
        with open(self.output + ".imports.json", "w", encoding="utf-8") as f:
            json.dump(snapshot, f, separators=(",", ":"))
        return {"ok": True, "imageBase": self.base, "size": len(image), "late": True,
                "stage": "instrumented", "events": self.events, "bpHits": sum(s["hits"] for s in self.sites.values()),
                "observations": self.observations, "oepCandidates": oep_candidates(self.observations, self.base, pe),
                "oepConfirmed": False, "oepQuality": "observed-landing-only", "instrumented": True,
                "hookMode": "one-shot", "singleStep": False, "debugPortHidden": False,
                "startupSync": "input-entry-one-shot", "startupSyncHits": int(self.entry_passed),
                "hookSites": [{k: s[k] for k in ("va", "kind", "name", "entryBytes", "armed", "hits")} for s in self.sites.values()],
                "imports": {"snapshot": True, "modules": len(snapshot["modules"]),
                            "exports": sum(len(m["exports"]) for m in snapshot["modules"])},
                "exitReason": reason, "captureSource": source,
                "captureAgeMs": round((time.monotonic() - captured) * 1000), "pid": self.pi.dwProcessId}

    def start(self):
        self.job = self.own(self.k.CreateJobObjectW(None, None))
        limits = JOB_EXTENDED_LIMITS(); limits.BasicLimitInformation.LimitFlags = KILL_ON_CLOSE
        if not self.job or not self.k.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError("Job Object setup failed")
        si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([self.sample, *self.args]))
        if not self.k.CreateProcessW(self.sample, command, None, None, False, 2 | 4, None,
                                     os.path.dirname(self.sample), ctypes.byref(si), ctypes.byref(self.pi)):
            raise OSError("CreateProcessW failed: " + str(ctypes.get_last_error()))
        self.own(self.pi.hProcess); self.own(self.pi.hThread)
        self.threads[self.pi.dwThreadId] = self.pi.hThread
        if not self.k.AssignProcessToJobObject(self.job, self.pi.hProcess):
            raise OSError("AssignProcessToJobObject failed before resume")
        # The suspended first thread must run to generate the initial debug event.
        # DEBUG_ONLY_THIS_PROCESS stops it again before user entry/loader dispatch.
        if self.k.ResumeThread(self.pi.hThread) == 0xffffffff:
            raise OSError("ResumeThread failed")
        if os.environ.get("INSTRUMENT_PARENT_PIPE") == "1":
            self.parent_pipe = self.k.GetStdHandle(0xfffffff6)  # STD_INPUT_HANDLE
        started = time.monotonic()
        while True:
            if self.parent_pipe and not self.k.PeekNamedPipe(self.parent_pipe, None, 0, None, None, None):
                return {"ok": False, "error": "parent-closed", "stage": "instrumented"}
            if time.monotonic() - started >= self.seconds:
                return self.finish("timeout")
            ev = DEBUG_EVENT()
            if not self.k.WaitForDebugEvent(ctypes.byref(ev), 10):
                if ctypes.get_last_error() != 121:  # ERROR_SEM_TIMEOUT
                    raise OSError("WaitForDebugEvent failed: " + str(ctypes.get_last_error()))
                if self.base and time.monotonic() - self.last_capture >= 0.10:
                    self.capture_running()
                continue
            self.pending = (ev.dwProcessId, ev.dwThreadId)
            self.events += 1
            status, code = DBG_CONTINUE, ev.dwDebugEventCode
            if os.environ.get("INSTRUMENT_DEBUG") and self.events <= 40:
                print(f"debug event={code} tid={ev.dwThreadId} base={self.base:#x} hooks={len(self.sites)} hits={sum(s['hits'] for s in self.sites.values())}", file=sys.stderr, flush=True)
            if code == 3:
                info = ev.CreateProcessInfo
                self.base = int(info.lpBaseOfImage or 0)
                self.close_debug_handles(ev)
                va = self.base + self.pe["epRva"]
                original = self.read(va, 1)
                if original is None or original == b"\xcc":
                    raise OSError("input entry synchronization unavailable")
                self.entry_sync = {"va": va, "original": original, "armed": True}
                self.write_byte(va, b"\xcc")
                for base in self.module_bases():
                    self.plant(base)
            elif code == 2:
                self.close_debug_handles(ev)
            elif code == 4:
                h = self.threads.pop(ev.dwThreadId, None)
                if h != self.pi.hThread:
                    self.close(h)
            elif code == 6:
                self.own(ev.LoadDll.hFile)
                try:
                    self.plant(int(ev.LoadDll.lpBaseOfDll or 0))
                finally:
                    self.close(ev.LoadDll.hFile)
            elif code == 1:
                exr = ev.Exception.ExceptionRecord
                ec, address = exr.ExceptionCode, int(exr.ExceptionAddress or 0)
                if os.environ.get("INSTRUMENT_DEBUG") and self.events <= 40:
                    print(f"exception={ec:#x} address={address:#x} first={ev.Exception.dwFirstChance}", file=sys.stderr, flush=True)
                site = self.sites.get(address)
                if ec in (BREAKPOINT, 0x4000001f) and self.entry_sync and self.entry_sync["armed"] and address == self.entry_sync["va"]:
                    h, ctx = self.hook_context(self.entry_sync, ev.dwThreadId)
                    self.restore_and_rewind(self.entry_sync, h, ctx)
                    self.entry_passed = True
                    if self.ntdll_base:
                        self.plant(self.ntdll_base)
                    else:
                        for base in self.module_bases():
                            self.plant(base)
                elif ec in (BREAKPOINT, 0x4000001f) and site and site["armed"]:
                    self.hit(site, ev.dwThreadId)
                elif ec in (BREAKPOINT, 0x4000001f) and not self.entry_passed and ec not in self.loader_breaks and \
                        not self.base <= address < self.base + self.pe["sizeOfImage"]:
                    self.loader_breaks.add(ec)  # only initial loader breaks, never sample INT3s
                    for base in self.module_bases():
                        self.plant(base)
                elif not ev.Exception.dwFirstChance:
                    return self.finish("second-chance")
                else:
                    status = DBG_NOT_HANDLED  # let legitimate SEH/VEH run and reach KUED
            elif code == 5:
                return self.finish("exit")  # preserve pending event until capture/cleanup
            if self.events >= self.max_events:
                return self.finish("event-limit")
            if not self.k.ContinueDebugEvent(*self.pending, status):
                raise OSError("ContinueDebugEvent failed")
            self.pending = None

    def cleanup(self):
        # Covers normal exit, failures before assignment, timeout, and parent pipe EOF.
        if self.job:
            self.k.TerminateJobObject(self.job, 1)
        if self.pi.hProcess:
            self.k.TerminateProcess(self.pi.hProcess, 1)
        if self.pending:
            self.k.ContinueDebugEvent(*self.pending, DBG_CONTINUE); self.pending = None
        # Drain termination debug events so a pending event cannot pin the job's process.
        end = time.monotonic() + 2
        while self.pi.hProcess and self.k.WaitForSingleObject(self.pi.hProcess, 0) == 0x102 and time.monotonic() < end:
            ev = DEBUG_EVENT()
            if self.k.WaitForDebugEvent(ctypes.byref(ev), 10):
                self.close_debug_handles(ev)
                self.k.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
        self.close(self.job)  # unnamed job has no inheritable handles; last-close kills descendants
        if self.pi.hProcess:
            self.k.WaitForSingleObject(self.pi.hProcess, 2000)
        for h in list(self.handles):
            self.close(h)


def main():
    observer = None
    code = 0
    try:
        args = sys.argv[1:]
        if args == ["--self-test"]:
            report = run_self_test()
        elif len(args) == 2 and args[0] == "--stat":
            report = {"ok": True, "pe": stat_sample(os.path.abspath(args[1]))}
        else:
            if not 2 <= len(args) <= 5:
                raise ValueError("usage: sample.exe dump.bin [seconds] [max_events] [args_json]")
            sample, output = (os.path.abspath(p) for p in args[:2])
            seconds = float(args[2]) if len(args) > 2 else 20.0
            max_events = int(args[3]) if len(args) > 3 else 2000
            sample_args = json.loads(args[4]) if len(args) > 4 else []
            if not math.isfinite(seconds) or not 0.1 <= seconds <= 120 or not 16 <= max_events <= 100000 or \
                    not isinstance(sample_args, list) or len(sample_args) > 32 or \
                    any(not isinstance(a, str) or len(a) > 4096 or "\0" in a for a in sample_args):
                raise ValueError("invalid options")
            pe = stat_sample(sample)  # architecture rejected BEFORE CreateProcessW
            if os.name != "nt":
                raise ValueError("win32 required")
            if os.path.normcase(sample) == os.path.normcase(output) or not os.path.isdir(os.path.dirname(output)):
                raise ValueError("invalid output path")
            observer = Observer(sample, output, pe, seconds, max_events, sample_args)
            report = observer.start()
            code = 0 if report["ok"] else 7
    except (OSError, ValueError) as error:
        report = {"ok": False, "error": "instrument-failed" if observer else "unsupported-input",
                  "detail": str(error), "stage": "instrumented"}
        if observer:
            report.update(events=observer.events, bpHits=sum(s["hits"] for s in observer.sites.values()),
                          observations=observer.observations)
        code = 5 if observer else 2
    except Exception as error:
        report = {"ok": False, "error": "tool-error", "detail": str(error), "stage": "instrumented"}
        code = 5
    finally:
        if observer:
            try:
                observer.cleanup()
            except Exception as error:
                report = {"ok": False, "error": "tool-error", "detail": "cleanup failed: " + str(error), "stage": "instrumented"}
                code = 5
    print(json.dumps(report), flush=True)  # completion means cleanup has already run
    return code


if __name__ == "__main__":
    sys.exit(main())
