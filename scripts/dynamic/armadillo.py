#!/usr/bin/env python3
"""Independent x86 master/slave oracle observer (not a PE unpacker).

Only the master is our debuggee. The master remains the slave's debugger.
Explicit probes change flags/ECX in the master's successful GetThreadContext
output, then observe its successful SetThreadContext and ContinueDebugEvent.
No slave attach, CC scan, slave EIP redirection, or guessed repair is performed.
An optional --dump path snapshots the target image (the debugged slave when
present, otherwise the master itself) after observation ends, before tree
cleanup, and while a pending exit event still preserves the address space.
"""
import argparse
import ctypes as C
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "armadillo-oracle/v1"
FLAG_MASK = 0x8C5
DBG_CONTINUE = 0x10002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
BREAKPOINT = 0x80000003
SINGLE_STEP = 0x80000004
MAX_JSON = 2 * 1024 * 1024
MAX_SITES = 32
MAX_SAMPLES = 4096
MAX_API_EVENTS = 4096
MAX_THREADS = 64
U32, U16, PTR, SIZE = C.c_uint32, C.c_uint16, C.c_void_p, C.c_size_t


class BackendError(Exception):
    def __init__(self, reason, detail=""):
        super().__init__(reason)
        self.reason, self.detail = reason, str(detail)


def require(condition, reason, detail=""):
    if not condition:
        raise BackendError(reason, detail)


def u32(value):
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def read_json(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, "input-size-limit")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as error:
        raise BackendError("invalid-json", error) from error


def validate_plan(plan):
    require(isinstance(plan, dict) and u32(plan.get("imageBase")), "invalid-probe-plan")
    sites = plan.get("probes")
    require(isinstance(sites, list) and 0 < len(sites) <= MAX_SITES, "invalid-probe-plan")
    count, addresses, result = 0, set(), []
    for site in sites:
        require(isinstance(site, dict) and u32(site.get("address"))
                and site.get("size") in (2, 5, 6), "invalid-probe-site")
        require(site["address"] >= plan["imageBase"] and site["address"] not in addresses,
                "invalid-probe-site")
        addresses.add(site["address"])
        samples = site.get("samples")
        require(isinstance(samples, list) and 0 < len(samples) <= 128, "invalid-probe-samples")
        count += len(samples)
        require(count <= MAX_SAMPLES, "probe-limit")
        seen, copied = set(), []
        for sample in samples:
            require(isinstance(sample, dict) and u32(sample.get("eflags"))
                    and u32(sample.get("ecx")), "invalid-probe-sample")
            # Probe only condition bits. TF/DF/IOPL changes are not part of this protocol.
            require(sample["eflags"] & ~FLAG_MASK == 0x202, "unsupported-probe-flags")
            key = (sample["eflags"] & FLAG_MASK, sample["ecx"])
            require(key not in seen, "duplicate-probe-sample")
            seen.add(key)
            copied.append(dict(eflags=sample["eflags"], ecx=sample["ecx"]))
        result.append(dict(address=site["address"], size=site["size"], samples=copied))
    return dict(imageBase=plan["imageBase"], probes=result)


def empty_sidecar(image_base=0, mode="probe", reason="probe-unavailable"):
    return dict(schema=SCHEMA, layout="raw-rva", imageBase=image_base, mode=mode,
                status=reason, reason=reason, complete=False, nanRecords=[], probes=[],
                processes=[], apiEvents=[], cleanup=dict(verified=False, survivors=[]))


class OracleStateMachine:
    """Pure correlation state, independently testable without WinDLL or processes."""
    def __init__(self, master_pid, plan):
        self.master_pid = master_pid
        require(u32(master_pid) and master_pid > 0, "invalid-master-pid")
        self.plan = validate_plan(plan)
        self.state = "starting"
        self.processes = {master_pid: dict(pid=master_pid, role="master", debugger="backend")}
        self.sites = {p["address"]: dict(address=p["address"], size=p["size"], samples=p["samples"],
                                          observations=[], status="probe-unavailable") for p in self.plan["probes"]}
        self.pending = {}

    def register_slave(self, pid, tid, parent_pid, image_base, inside_job):
        require(pid != self.master_pid and parent_pid == self.master_pid and inside_job,
                "invalid-slave-ownership")
        require(len(self.processes) < 8, "process-limit")
        self.processes[pid] = dict(pid=pid, tid=tid, parentPid=parent_pid, role="slave",
                                  debuggerPid=self.master_pid, debugSource="master-wait-debug-event",
                                  imageBase=image_base, insideJob=True)
        self.state = "master-debugging-slave"

    def slave_exception(self, caller_pid, pid, tid, address, first_chance):
        require(caller_pid == self.master_pid, "event-not-from-master")
        require(pid in self.processes and self.processes[pid]["role"] == "slave", "unknown-slave")
        self.pending.pop((pid, tid), None)
        if address not in self.sites or not first_chance:
            return
        site = self.sites[address]
        if len(site["observations"]) < len(site["samples"]):
            require(site.get("owner", (pid, tid)) == (pid, tid), "ambiguous-probe-owner")
            site["owner"] = (pid, tid)
            self.pending[(pid, tid)] = dict(site=site, stage="exception", callerPid=caller_pid)

    def context_read(self, caller_pid, pid, tid, context):
        require(caller_pid == self.master_pid, "event-not-from-master")
        pending = self.pending.get((pid, tid))
        if not pending or pending["stage"] not in ("exception", "injected"):
            return None
        # Both CONTROL and INTEGER are needed for EFlags and ECX.
        require(context["ContextFlags"] & 0x10003 == 0x10003, "incomplete-context")
        site = pending["site"]
        require(context["Eip"] in (site["address"], site["address"] + 1), "context-site-mismatch")
        sample = site["samples"][len(site["observations"])]
        pending.update(stage="injected", sample=sample.copy(), originalEip=context["Eip"])
        self.state = "probing"
        return dict(EFlags=(context["EFlags"] & ~FLAG_MASK) | (sample["eflags"] & FLAG_MASK), Ecx=sample["ecx"])

    def context_write(self, caller_pid, pid, tid, context, success):
        require(caller_pid == self.master_pid, "event-not-from-master")
        pending = self.pending.get((pid, tid))
        if not pending or pending["stage"] not in ("injected", "context-written"):
            return
        if not success:
            pending["site"]["reason"] = "master-set-context-failed"
            self.pending.pop((pid, tid), None)
            return
        require(context["ContextFlags"] & 0x10001 == 0x10001 and u32(context["Eip"]), "incomplete-context")
        pending.update(stage="context-written", output=context.copy())

    def continued(self, caller_pid, pid, tid, status, success):
        require(caller_pid == self.master_pid, "event-not-from-master")
        pending = self.pending.pop((pid, tid), None)
        if not pending:
            return
        site = pending["site"]
        if not success or status != DBG_CONTINUE or pending["stage"] != "context-written":
            site["reason"] = "master-did-not-complete-probe"
            return
        site["observations"].append(dict(**pending["sample"], eip=pending["output"]["Eip"],
            outputFlags=pending["output"]["EFlags"], masterPid=caller_pid, slavePid=pid,
            slaveTid=tid, source="master-set-context/continue-success"))
        site.pop("reason", None)
        if len(site["observations"]) == len(site["samples"]):
            site["status"] = "observations-ready"
        if self.complete:
            self.state = "observations-complete"

    @property
    def complete(self):
        return all(p["status"] == "observations-ready" for p in self.sites.values())

    def snapshot(self, reason=None):
        result = empty_sidecar(self.plan["imageBase"])
        result.update(state=self.state, status="observations-ready" if self.complete else "probe-unavailable",
                      reason=None if self.complete else reason or "incomplete-master-observations",
                      complete=self.complete, processes=[p.copy() for p in self.processes.values()],
                      probes=[dict(address=p["address"], size=p["size"], status=p["status"],
                                   observations=[o.copy() for o in p["observations"]],
                                   **({"reason": p["reason"]} if "reason" in p else {})) for p in self.sites.values()])
        return result


class X86_CONTEXT(C.Structure):
    _fields_ = [("ContextFlags", U32), ("DebugRegisters", U32 * 6), ("FloatSave", C.c_ubyte * 112),
                ("SegGs", U32), ("SegFs", U32), ("SegEs", U32), ("SegDs", U32),
                ("Edi", U32), ("Esi", U32), ("Ebx", U32), ("Edx", U32), ("Ecx", U32), ("Eax", U32),
                ("Ebp", U32), ("Eip", U32), ("SegCs", U32), ("EFlags", U32), ("Esp", U32),
                ("SegSs", U32), ("ExtendedRegisters", C.c_ubyte * 512)]


class STARTUPINFO(C.Structure):
    _fields_ = [("cb", U32), ("lpReserved", C.c_wchar_p), ("lpDesktop", C.c_wchar_p), ("lpTitle", C.c_wchar_p),
                *[(n, U32) for n in ("dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars",
                                    "dwFillAttribute", "dwFlags")],
                ("wShowWindow", U16), ("cbReserved2", U16), ("lpReserved2", PTR),
                ("hStdInput", PTR), ("hStdOutput", PTR), ("hStdError", PTR)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [("hProcess", PTR), ("hThread", PTR), ("dwProcessId", U32), ("dwThreadId", U32)]


class EXCEPTION_RECORD(C.Structure):
    _fields_ = [("ExceptionCode", U32), ("ExceptionFlags", U32), ("ExceptionRecord", PTR),
                ("ExceptionAddress", PTR), ("NumberParameters", U32), ("ExceptionInformation", SIZE * 15)]


class EXCEPTION_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", U32)]


class CREATE_PROCESS_INFO(C.Structure):
    _fields_ = [("hFile", PTR), ("hProcess", PTR), ("hThread", PTR), ("lpBaseOfImage", PTR),
                ("dwDebugInfoFileOffset", U32), ("nDebugInfoSize", U32), ("lpThreadLocalBase", PTR),
                ("lpStartAddress", PTR), ("lpImageName", PTR), ("fUnicode", U16)]


class CREATE_THREAD_INFO(C.Structure):
    _fields_ = [("hThread", PTR), ("lpThreadLocalBase", PTR), ("lpStartAddress", PTR)]


class LOAD_DLL_INFO(C.Structure):
    _fields_ = [("hFile", PTR), ("lpBaseOfDll", PTR), ("dwDebugInfoFileOffset", U32),
                ("nDebugInfoSize", U32), ("lpImageName", PTR), ("fUnicode", U16)]


class EVENT_UNION(C.Union):
    _fields_ = [("Exception", EXCEPTION_INFO), ("CreateProcess", CREATE_PROCESS_INFO),
                ("CreateThread", CREATE_THREAD_INFO), ("LoadDll", LOAD_DLL_INFO), ("ExitCode", U32)]


class DEBUG_EVENT(C.Structure):
    _fields_ = [("code", U32), ("pid", U32), ("tid", U32), ("u", EVENT_UNION)]


class JOB_BASIC_LIMITS(C.Structure):
    _fields_ = [("PerProcessUserTimeLimit", C.c_int64), ("PerJobUserTimeLimit", C.c_int64),
                ("LimitFlags", U32), ("MinimumWorkingSetSize", SIZE), ("MaximumWorkingSetSize", SIZE),
                ("ActiveProcessLimit", U32), ("Affinity", SIZE), ("PriorityClass", U32), ("SchedulingClass", U32)]


class JOB_LIMITS(C.Structure):
    _fields_ = [("Basic", JOB_BASIC_LIMITS), ("IoInfo", C.c_uint64 * 6), ("ProcessMemoryLimit", SIZE),
                ("JobMemoryLimit", SIZE), ("PeakProcessMemoryUsed", SIZE), ("PeakJobMemoryUsed", SIZE)]


class JOB_PROCESS_LIST(C.Structure):
    _fields_ = [("assigned", U32), ("count", U32), ("pids", SIZE * 8)]


class PROCESSENTRY(C.Structure):
    _fields_ = [("dwSize", U32), ("cntUsage", U32), ("pid", U32), ("heap", SIZE),
                ("module", U32), ("threads", U32), ("parentPid", U32), ("priority", C.c_int32),
                ("flags", U32), ("exe", C.c_wchar * 260)]


class MEMORY_BASIC_INFORMATION(C.Structure):
    _fields_ = [("BaseAddress", PTR), ("AllocationBase", PTR), ("AllocationProtect", U32),
                ("RegionSize", SIZE), ("State", U32), ("Protect", U32), ("Type", U32)]


class Win32:
    """Typed ABI; the native library is loaded only when a native run is requested."""
    def __init__(self):
        require(os.name == "nt", "unsupported-platform")
        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateProcessW": ([C.c_wchar_p, C.c_wchar_p, PTR, PTR, C.c_int, U32, PTR, C.c_wchar_p,
                                 C.POINTER(STARTUPINFO), C.POINTER(PROCESS_INFORMATION)], C.c_int),
            "WaitForDebugEvent": ([C.POINTER(DEBUG_EVENT), U32], C.c_int),
            "ContinueDebugEvent": ([U32, U32, U32], C.c_int), "CloseHandle": ([PTR], C.c_int),
            "ReadProcessMemory": ([PTR, PTR, PTR, SIZE, C.POINTER(SIZE)], C.c_int),
            "WriteProcessMemory": ([PTR, PTR, PTR, SIZE, C.POINTER(SIZE)], C.c_int),
            "VirtualProtectEx": ([PTR, PTR, SIZE, U32, C.POINTER(U32)], C.c_int),
            "VirtualQueryEx": ([PTR, PTR, PTR, SIZE], SIZE),
            "FlushInstructionCache": ([PTR, PTR, SIZE], C.c_int),
            "SuspendThread": ([PTR], U32), "ResumeThread": ([PTR], U32),
            "CreateJobObjectW": ([PTR, C.c_wchar_p], PTR),
            "SetInformationJobObject": ([PTR, C.c_int, PTR, U32], C.c_int),
            "QueryInformationJobObject": ([PTR, C.c_int, PTR, U32, C.POINTER(U32)], C.c_int),
            "AssignProcessToJobObject": ([PTR, PTR], C.c_int),
            "TerminateJobObject": ([PTR, U32], C.c_int), "TerminateProcess": ([PTR, U32], C.c_int),
            "IsProcessInJob": ([PTR, PTR, C.POINTER(C.c_int)], C.c_int),
            "OpenProcess": ([U32, C.c_int, U32], PTR),
            "GetCurrentProcess": ([], PTR), "GetProcessId": ([PTR], U32),
            "GetProcessIdOfThread": ([PTR], U32), "GetThreadId": ([PTR], U32),
            "DuplicateHandle": ([PTR, PTR, PTR, C.POINTER(PTR), U32, C.c_int, U32], C.c_int),
            "WaitForSingleObject": ([PTR, U32], U32),
            "CreateToolhelp32Snapshot": ([U32, U32], PTR),
            "Process32FirstW": ([PTR, C.POINTER(PROCESSENTRY)], C.c_int),
            "Process32NextW": ([PTR, C.POINTER(PROCESSENTRY)], C.c_int),
            "Wow64GetThreadContext": ([PTR, C.POINTER(X86_CONTEXT)], C.c_int),
            "Wow64SetThreadContext": ([PTR, C.POINTER(X86_CONTEXT)], C.c_int),
            "GetThreadContext": ([PTR, C.POINTER(X86_CONTEXT)], C.c_int),
            "SetThreadContext": ([PTR, C.POINTER(X86_CONTEXT)], C.c_int),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = args, result

    def check(self, result, operation):
        require(bool(result), "native-api-failed", f"{operation}:{C.get_last_error()}")
        return result

    def read(self, process, address, size):
        require(0 < size <= 1024 * 1024 and u32(address) and address + size <= 0x100000000, "remote-read-limit")
        buffer, count = C.create_string_buffer(size), SIZE()
        self.check(self.k.ReadProcessMemory(process, PTR(address), buffer, size, C.byref(count)), "ReadProcessMemory")
        require(count.value == size, "partial-remote-read")
        return buffer.raw

    def read_image(self, process, address, size):
        # Whole-image dump read; the bound matches pe32_header's image-size limit.
        require(0 < size <= 128 * 1024 * 1024 and u32(address) and address + size <= 0x100000000, "image-read-limit")
        buffer, count = C.create_string_buffer(size), SIZE()
        self.check(self.k.ReadProcessMemory(process, PTR(address), buffer, size, C.byref(count)), "ReadProcessMemory")
        require(count.value == size, "partial-image-read")
        return buffer.raw

    def strip_guard(self, process, base, size):
        # Best-effort PAGE_GUARD removal before a dump read (packer tripwires);
        # failures surface as the subsequent read error instead of being masked.
        stripped, address = 0, base
        while address < base + size:
            mbi = MEMORY_BASIC_INFORMATION()
            if not self.k.VirtualQueryEx(process, PTR(address), C.byref(mbi), C.sizeof(mbi)) or not mbi.RegionSize:
                break
            if mbi.State == 0x1000 and mbi.Protect & 0x100:  # committed + PAGE_GUARD
                old = U32()
                self.k.VirtualProtectEx(process, PTR(address), min(mbi.RegionSize, base + size - address),
                                        mbi.Protect & ~0x100, C.byref(old))
                stripped += 1
            address += mbi.RegionSize
        return stripped

    def write(self, process, address, data, code=False):
        require(0 < len(data) <= 716 and u32(address), "remote-write-limit")
        old, count = U32(), SIZE()
        if code:
            self.check(self.k.VirtualProtectEx(process, PTR(address), len(data), 0x40, C.byref(old)), "VirtualProtectEx")
        try:
            self.check(self.k.WriteProcessMemory(process, PTR(address), data, len(data), C.byref(count)), "WriteProcessMemory")
            require(count.value == len(data), "partial-remote-write")
            if code:
                self.check(self.k.FlushInstructionCache(process, PTR(address), len(data)), "FlushInstructionCache")
        finally:
            if code:
                restore = U32()
                self.check(self.k.VirtualProtectEx(process, PTR(address), len(data), old.value, C.byref(restore)), "restore-protection")

    def context(self, thread):
        context = X86_CONTEXT(); context.ContextFlags = 0x10007
        fn = self.k.Wow64GetThreadContext if C.sizeof(PTR) == 8 else self.k.GetThreadContext
        self.check(fn(thread, C.byref(context)), "GetThreadContext(master)")
        return context

    def set_context(self, thread, context):
        fn = self.k.Wow64SetThreadContext if C.sizeof(PTR) == 8 else self.k.SetThreadContext
        self.check(fn(thread, C.byref(context)), "SetThreadContext(master)")

    def duplicate(self, process, handle):
        local = PTR()
        self.check(self.k.DuplicateHandle(process, PTR(handle), self.k.GetCurrentProcess(), C.byref(local),
                                          0, False, 2), "DuplicateHandle")
        return local.value

    def parent_pid(self, pid):
        snapshot = self.k.CreateToolhelp32Snapshot(2, 0)
        require(snapshot and snapshot != PTR(-1).value, "process-snapshot-failed")
        try:
            item = PROCESSENTRY(); item.dwSize = C.sizeof(item)
            available = self.k.Process32FirstW(snapshot, C.byref(item))
            for _ in range(65536):
                if not available:
                    break
                if item.pid == pid:
                    return item.parentPid
                available = self.k.Process32NextW(snapshot, C.byref(item))
            raise BackendError("slave-parent-unavailable")
        finally:
            self.k.CloseHandle(snapshot)


def context_values(raw):
    require(len(raw) == 716, "invalid-context-bytes")
    return {name: struct.unpack_from("<I", raw, offset)[0] for name, offset in
            (("ContextFlags", 0), ("Ecx", 0xAC), ("Eip", 0xB8), ("EFlags", 0xC0))}


def pe32_header(read, base):
    dos = read(base, 64)
    require(dos[:2] == b"MZ", "unsupported-master-image")
    offset = struct.unpack_from("<I", dos, 0x3C)[0]
    require(64 <= offset <= 1024 * 1024, "unsupported-master-image")
    header = read(base + offset, 248)
    require(header[:4] == b"PE\0\0" and struct.unpack_from("<H", header, 4)[0] == 0x14C
            and struct.unpack_from("<H", header, 24)[0] == 0x10B, "unsupported-architecture")
    size = struct.unpack_from("<I", header, 80)[0]
    require(0 < size <= 128 * 1024 * 1024 and base + size <= 0x100000000, "image-size-limit")
    return header, size


class MasterOracleBackend:
    APIS = {"WaitForDebugEvent": 2, "GetThreadContext": 2, "SetThreadContext": 2, "ContinueDebugEvent": 3}

    def __init__(self, plan, timeout=15, max_events=20000, dump_path=None):
        self.plan = validate_plan(plan)
        require(type(timeout) in (int, float) and 0 < timeout <= 60, "invalid-timeout")
        require(type(max_events) is int and 0 < max_events <= 50000, "event-limit")
        self.timeout, self.max_events = timeout, max_events
        self.dump_path, self.dump_record = dump_path, None
        self.win, self.machine = None, None
        self.job, self.master, self.pi = None, None, None
        self.handles, self.threads, self.process_handles = set(), {}, {}
        self.breakpoints, self.frames, self.steps, self.installed = {}, {}, {}, {}
        self.api_events, self.event_count = [], 0
        self.exceptions = []
        self.assigned, self.loader_seen, self.loaded_modules = False, set(), 0
        self.last_event = None

    def own(self, handle):
        if handle:
            self.handles.add(handle)
        return handle

    def log(self, api, phase, tid, **values):
        require(len(self.api_events) < MAX_API_EVENTS, "api-event-limit")
        self.api_events.append(dict(api=api, phase=phase, masterPid=self.pi.dwProcessId, masterTid=tid, **values))

    def add_breakpoint(self, address, api=None, frame=None):
        bp = self.breakpoints.get(address)
        if not bp:
            original = self.win.read(self.master, address, 1)
            require(original != b"\xcc", "api-breakpoint-conflict")
            bp = dict(original=original, api=api, refs=0, armed=True)
            self.breakpoints[address] = bp
            self.win.write(self.master, address, b"\xcc", code=True)
        if frame:
            bp["refs"] += 1
        if api:
            require(bp["api"] in (None, api), "ambiguous-api-address")
            bp["api"] = api

    def install_module(self, base):
        self.loaded_modules += 1
        require(self.loaded_modules <= 256, "module-limit")
        try:
            header, size = pe32_header(lambda a, n: self.win.read(self.master, a, n), base)
        except BackendError as error:
            if error.reason in ("unsupported-architecture", "remote-read-limit", "unsupported-master-image"):
                return
            raise
        export, length = struct.unpack_from("<II", header, 120)
        if not export or length < 40 or export + length > size:
            return

        def read_rva(rva, count):
            require(0 < rva and rva + count <= size, "invalid-remote-export")
            return self.win.read(self.master, base + rva, count)

        def text(rva):
            data = bytearray()
            while len(data) < 256:
                block = read_rva(rva + len(data), min(32, size - rva - len(data)))
                data.extend(block)
                if 0 in block:
                    return bytes(data).split(b"\0", 1)[0].decode("ascii", errors="replace")
            raise BackendError("remote-export-name-limit")

        directory = read_rva(export, 40)
        name_rva, nfunc, nnames, funcs, names, ords = (struct.unpack_from("<I", directory, o)[0]
                                                    for o in (12, 20, 24, 28, 32, 36))
        if text(name_rva).lower() not in ("kernel32.dll", "kernelbase.dll"):
            return
        require(0 < nfunc <= 16384 and nnames <= 16384, "remote-export-limit")
        function_table, name_table, ordinal_table = read_rva(funcs, nfunc * 4), read_rva(names, nnames * 4), read_rva(ords, nnames * 2)
        for index in range(nnames):
            name = text(struct.unpack_from("<I", name_table, index * 4)[0])
            if name not in self.APIS or name in self.installed:
                continue
            ordinal = struct.unpack_from("<H", ordinal_table, index * 2)[0]
            require(ordinal < nfunc, "invalid-remote-export")
            rva = struct.unpack_from("<I", function_table, ordinal * 4)[0]
            if export <= rva < export + length:  # Forwarders are resolved by subsequent real module exports.
                continue
            require(0 < rva < size, "invalid-remote-export")
            self.add_breakpoint(base + rva, api=name)
            self.installed[name] = base + rva

    def thread_identity(self, remote_handle):
        handle = self.win.duplicate(self.master, remote_handle)
        try:
            pid, tid = self.win.k.GetProcessIdOfThread(handle), self.win.k.GetThreadId(handle)
            require(pid and tid, "invalid-slave-thread-handle")
            return pid, tid
        finally:
            self.win.k.CloseHandle(handle)

    def slave_event(self, raw):
        code, pid, tid = struct.unpack_from("<III", raw)
        require(pid != self.pi.dwProcessId, "master-reported-self-event")
        if code == 3:
            h_process = self.own(self.win.duplicate(self.master, struct.unpack_from("<I", raw, 16)[0]))
            require(self.win.k.GetProcessId(h_process) == pid, "slave-handle-pid-mismatch")
            in_job = C.c_int()
            self.win.check(self.win.k.IsProcessInJob(h_process, self.job, C.byref(in_job)), "IsProcessInJob(slave)")
            base = struct.unpack_from("<I", raw, 24)[0]
            header, size = pe32_header(lambda a, n: self.win.read(h_process, a, n), base)
            require(base == self.plan["imageBase"], "image-base-mismatch")
            for site in self.plan["probes"]:
                require(base <= site["address"] and site["address"] + site["size"] <= base + size, "probe-site-outside-image")
            self.process_handles[pid] = h_process
            self.machine.register_slave(pid, tid, self.win.parent_pid(pid), base, bool(in_job.value))
        elif code == 1:
            if pid not in self.machine.processes:
                raise BackendError("unknown-slave")
            exception, address, first_chance = (struct.unpack_from("<I", raw, offset)[0] for offset in (12, 24, 92))
            if exception == BREAKPOINT and address in self.machine.sites:
                require(self.win.read(self.process_handles[pid], address, 1) == b"\xcc", "probe-site-not-int3")
                self.machine.slave_exception(self.pi.dwProcessId, pid, tid, address, first_chance)
        elif code == 5 and pid in self.machine.processes:
            self.machine.processes[pid]["exitObservedByMaster"] = True

    def api_enter(self, tid, api, context):
        stack = self.win.read(self.master, context.Esp, (self.APIS[api] + 1) * 4)
        values = struct.unpack("<" + "I" * (self.APIS[api] + 1), stack)
        frame = dict(api=api, args=values[1:], ret=values[0], tid=tid)
        require(sum(len(v) for v in self.frames.values()) < 128, "api-call-depth-limit")
        if api == "SetThreadContext":
            frame["identity"] = self.thread_identity(frame["args"][0])
            frame["context"] = context_values(self.win.read(self.master, frame["args"][1], 716))
        self.frames.setdefault((tid, frame["ret"]), []).append(frame)
        self.add_breakpoint(frame["ret"], frame=frame)
        self.log(api, "entry", tid)

    def api_return(self, frame, context):
        api, args, tid, success = frame["api"], frame["args"], frame["tid"], bool(context.Eax)
        self.log(api, "return", tid, success=success)
        if api == "WaitForDebugEvent" and success:
            self.slave_event(self.win.read(self.master, args[0], 96))
        elif api == "GetThreadContext" and success:
            pid, slave_tid = self.thread_identity(args[0])
            raw = self.win.read(self.master, args[1], 716)
            update = self.machine.context_read(self.pi.dwProcessId, pid, slave_tid, context_values(raw))
            if update:
                # Modify the master's output buffer, never the slave's debugger relationship or EIP.
                for name, offset in (("EFlags", 0xC0), ("Ecx", 0xAC)):
                    self.win.write(self.master, args[1] + offset, struct.pack("<I", update[name]))
        elif api == "SetThreadContext":
            pid, slave_tid = frame["identity"]
            self.machine.context_write(self.pi.dwProcessId, pid, slave_tid, frame["context"], success)
        elif api == "ContinueDebugEvent":
            self.machine.continued(self.pi.dwProcessId, args[0], args[1], args[2], success)

    def breakpoint_hit(self, event, address):
        bp = self.breakpoints[address]
        context = self.win.context(self.threads[event.tid])
        require(context.Eip in (address, address + 1), "master-breakpoint-context-mismatch")
        frames = self.frames.get((event.tid, address))
        if frames:
            frame = frames.pop(); bp["refs"] -= 1
            self.api_return(frame, context)
            if not frames:
                self.frames.pop((event.tid, address), None)
        if bp["api"]:
            self.api_enter(event.tid, bp["api"], context)
        require(event.tid not in self.steps, "nested-master-single-step")
        suspended = []
        for tid, handle in self.threads.items():
            if tid != event.tid:
                require(self.win.k.SuspendThread(handle) != 0xFFFFFFFF, "suspend-master-thread-failed")
                suspended.append(handle)
        self.win.write(self.master, address, bp["original"], code=True)
        bp["armed"] = False
        self.steps[event.tid] = dict(address=address, suspended=suspended, originalTF=context.EFlags & 0x100)
        context.Eip = address; context.EFlags |= 0x100
        self.win.set_context(self.threads[event.tid], context)

    def step_complete(self, event):
        step = self.steps.pop(event.tid)
        context = self.win.context(self.threads[event.tid])
        context.EFlags = (context.EFlags & ~0x100) | step["originalTF"]
        self.win.set_context(self.threads[event.tid], context)
        address = step["address"]; bp = self.breakpoints[address]
        if bp["api"] or bp["refs"]:
            self.win.write(self.master, address, b"\xcc", code=True)
            bp["armed"] = True
        else:
            self.breakpoints.pop(address)
        for handle in step["suspended"]:
            require(self.win.k.ResumeThread(handle) != 0xFFFFFFFF, "resume-master-thread-failed")

    def event(self, event):
        require(event.pid == self.pi.dwProcessId, "backend-received-slave-event")
        status = DBG_CONTINUE
        if event.code == 3:
            info = event.u.CreateProcess
            self.own(info.hProcess); self.threads[event.tid] = self.own(info.hThread)
            if info.hFile:
                self.win.k.CloseHandle(info.hFile)
            self.machine.state = "observing-master"
            self.machine.processes[event.pid].update(parentPid=os.getpid(), insideJob=True,
                                                     imageBase=int(info.lpBaseOfImage or 0))
        elif event.code == 2:
            require(len(self.threads) < MAX_THREADS, "thread-limit")
            self.threads[event.tid] = self.own(event.u.CreateThread.hThread)
        elif event.code == 4:
            self.threads.pop(event.tid, None)
        elif event.code == 6:
            if event.u.LoadDll.hFile:
                self.win.k.CloseHandle(event.u.LoadDll.hFile)
            self.install_module(int(event.u.LoadDll.lpBaseOfDll or 0))
        elif event.code == 1:
            exception = event.u.Exception.ExceptionRecord
            address = int(exception.ExceptionAddress or 0)
            if len(self.exceptions) < 64:
                self.exceptions.append(dict(code=exception.ExceptionCode, address=address, tid=event.tid,
                                            firstChance=event.u.Exception.dwFirstChance))
            if exception.ExceptionCode in (BREAKPOINT, 0x4000001F) and address in self.breakpoints and self.breakpoints[address]["armed"]:
                self.breakpoint_hit(event, address)
            elif exception.ExceptionCode in (SINGLE_STEP, 0x4000001E) and event.tid in self.steps:
                self.step_complete(event)
            elif exception.ExceptionCode in (BREAKPOINT, 0x4000001F) and exception.ExceptionCode not in self.loader_seen:
                self.loader_seen.add(exception.ExceptionCode)
            else:
                status = DBG_EXCEPTION_NOT_HANDLED
        return status

    def dump_image(self):
        """Snapshot the sample image while the job tree (or exit event) is still alive."""
        record = dict(requested=True, path=self.dump_path, ok=False, role=None, pid=None,
                      stage=self.machine.state if self.machine else None, imageBase=None,
                      size=None, guardRegions=0)
        try:
            target = None
            if self.machine:
                target = next((p for p in self.machine.processes.values() if p["role"] == "slave"), None)
            if target:
                handle = self.process_handles.get(target["pid"])
                require(handle, "slave-handle-unavailable")
                base = target["imageBase"]
                record.update(role="slave", pid=target["pid"])
            else:
                # Graceful degrade for non-dual-process samples: dump the master.
                require(self.master and self.machine and self.pi, "no-dump-target")
                master = self.machine.processes.get(self.pi.dwProcessId, {})
                base = master.get("imageBase")
                require(base, "master-image-base-unavailable")
                handle = self.master
                record.update(role="master", pid=self.pi.dwProcessId)
            header, size = pe32_header(lambda a, n: self.win.read(handle, a, n), base)
            record["guardRegions"] = self.win.strip_guard(handle, base, size)
            image = self.win.read_image(handle, base, size)
            with open(self.dump_path, "wb") as output:
                output.write(image)
            record.update(ok=True, imageBase=base, size=size)
        except BackendError as error:
            record.update(reason=error.reason, detail=error.detail)
        except OSError as error:
            record.update(reason="dump-io-error", detail=str(error))
        return record

    def cleanup(self):
        if not self.win:
            return dict(verified=False, survivors=[])
        k = self.win.k
        terminated = False
        tree_pids, tree_verified = [], False
        if self.assigned:
            members, returned = JOB_PROCESS_LIST(), U32()
            if k.QueryInformationJobObject(self.job, 3, C.byref(members), C.sizeof(members), C.byref(returned)) and members.count <= 8:
                tree_pids = [int(pid) for pid in members.pids[:members.count]]
                tree_verified = True
                for pid in tree_pids:
                    if pid in self.process_handles:
                        continue
                    handle = k.OpenProcess(0x101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
                    if not handle:
                        tree_verified &= C.get_last_error() == 87  # Already exited.
                        continue
                    self.own(handle)
                    in_job = C.c_int()
                    if k.IsProcessInJob(handle, self.job, C.byref(in_job)) and in_job.value:
                        self.process_handles[pid] = handle
                    else:
                        tree_verified = False
            terminated = bool(k.TerminateJobObject(self.job, 0xA24))
        elif self.pi and self.pi.hProcess:
            terminated = bool(k.TerminateProcess(self.pi.hProcess, 0xA24))
        if self.last_event:
            k.ContinueDebugEvent(self.last_event.pid, self.last_event.tid, DBG_CONTINUE)
            self.last_event = None
        # Debug-event suspension can delay process signalling. Drain ONLY our master.
        until = time.monotonic() + 2
        while self.master and k.WaitForSingleObject(self.master, 0) == 0x102 and time.monotonic() < until:
            event = DEBUG_EVENT()
            if k.WaitForDebugEvent(C.byref(event), 20):
                if event.code == 6 and event.u.LoadDll.hFile:
                    k.CloseHandle(event.u.LoadDll.hFile)
                if event.code == 3:
                    self.own(event.u.CreateProcess.hProcess); self.own(event.u.CreateProcess.hThread)
                    if event.u.CreateProcess.hFile:
                        k.CloseHandle(event.u.CreateProcess.hFile)
                if event.code == 2:
                    self.own(event.u.CreateThread.hThread)
                k.ContinueDebugEvent(event.pid, event.tid, DBG_CONTINUE)
        # Kill-on-close is an independent fallback, followed by per-PID handle checks.
        if self.job:
            k.CloseHandle(self.job); self.job = None
        survivors = []
        for pid, handle in self.process_handles.items():
            if k.WaitForSingleObject(handle, 500) != 0:
                survivors.append(pid)
        for handle in self.handles:
            k.CloseHandle(handle)
        self.handles.clear()
        return dict(jobAssigned=self.assigned, killOnClose=self.assigned, terminated=terminated,
                    processTreePids=tree_pids, verified=self.assigned and tree_verified and not survivors, survivors=survivors)

    def run(self, sample, arguments=()):
        require(self.win is None and self.pi is None, "backend-already-used")
        result, reason = None, None
        try:
            # Validate the file architecture before creating any process.
            with open(sample, "rb") as handle:
                dos = handle.read(64)
                require(len(dos) == 64 and dos[:2] == b"MZ", "unsupported-master-image")
                offset = struct.unpack_from("<I", dos, 0x3C)[0]
                require(64 <= offset <= 1024 * 1024, "unsupported-master-image")
                handle.seek(offset); header = handle.read(26)
                require(len(header) == 26 and header[:4] == b"PE\0\0" and header[4:6] == b"L\x01"
                        and header[24:26] == b"\x0b\x01", "unsupported-architecture")
            self.win = Win32(); k = self.win.k
            self.job = k.CreateJobObjectW(None, None); self.win.check(self.job, "CreateJobObjectW")
            limits = JOB_LIMITS(); limits.Basic.LimitFlags = 0x2000 | 0x8 | 0x200
            limits.Basic.ActiveProcessLimit = 8; limits.JobMemoryLimit = 256 * 1024 * 1024
            self.win.check(k.SetInformationJobObject(self.job, 9, C.byref(limits), C.sizeof(limits)), "SetInformationJobObject")
            si, self.pi = STARTUPINFO(), PROCESS_INFORMATION(); si.cb = C.sizeof(si)
            command = C.create_unicode_buffer(subprocess.list2cmdline([str(Path(sample).resolve()), *arguments]))
            # 0x2 is DEBUG_ONLY_THIS_PROCESS; DEBUG_PROCESS is 0x1, NOT 0x2.
            self.win.check(k.CreateProcessW(None, command, None, None, False, 0x2 | 0x4, None, None,
                                           C.byref(si), C.byref(self.pi)), "CreateProcessW(master)")
            self.master = self.own(self.pi.hProcess); self.own(self.pi.hThread)
            self.process_handles[self.pi.dwProcessId] = self.master
            self.machine = OracleStateMachine(self.pi.dwProcessId, self.plan)
            self.win.check(k.AssignProcessToJobObject(self.job, self.master), "AssignProcessToJobObject")
            self.assigned = True
            require(k.ResumeThread(self.pi.hThread) != 0xFFFFFFFF, "resume-master-failed")
            until = time.monotonic() + self.timeout
            while not self.machine.complete:
                require(time.monotonic() < until, "probe-timeout")
                require(self.event_count < self.max_events, "event-limit")
                event = DEBUG_EVENT()
                if not k.WaitForDebugEvent(C.byref(event), 20):
                    require(C.get_last_error() == 121, "wait-debug-event-failed", C.get_last_error())
                    continue
                self.last_event = event; self.event_count += 1
                status = self.event(event)
                if event.code == 5 and self.dump_path and self.dump_record is None:
                    # A dying debuggee's address space survives only until its
                    # exit event is continued; snapshot it while it is intact.
                    self.dump_record = self.dump_image()
                self.win.check(k.ContinueDebugEvent(event.pid, event.tid, status), "ContinueDebugEvent(master)")
                self.last_event = None
                if event.code == 5:
                    raise BackendError("master-exited-before-probes", f"exitCode:{event.u.ExitCode:#x}")
            result = self.machine.snapshot()
        except BackendError as error:
            reason = error.reason
            result = self.machine.snapshot(reason) if self.machine else empty_sidecar(self.plan["imageBase"])
            result.update(reason=reason, detail=error.detail)
            if reason.startswith("unsupported"):
                result["status"] = "unsupported"
        except (OSError, ValueError, C.ArgumentError) as error:
            result = self.machine.snapshot("native-error") if self.machine else empty_sidecar(self.plan["imageBase"])
            result.update(reason="native-error", detail=str(error))
        finally:
            if self.dump_path and self.dump_record is None:
                self.dump_record = self.dump_image()
            cleanup = self.cleanup()
        if self.dump_record is not None:
            result["dump"] = self.dump_record
        result.update(apiEvents=self.api_events, installedApis=list(self.installed), debugEventCount=self.event_count,
                      masterExceptions=self.exceptions, cleanup=cleanup)
        if self.assigned and not cleanup["verified"]:
            result.update(status="probe-unavailable", complete=False, reason="process-cleanup-unverified")
        return result


def supplied_records(request):
    require(isinstance(request, dict) and u32(request.get("imageBase")), "invalid-record-request")
    records = request.get("nanRecords")
    require(isinstance(records, list) and len(records) <= 65536, "record-limit")
    copied = []
    for record in records:
        require(isinstance(record, dict) and all(u32(record.get(k)) for k in ("address", "destination", "size")), "invalid-record")
        require(record.get("condition") is None or isinstance(record["condition"], str) and len(record["condition"]) <= 16, "invalid-record")
        require(record.get("jumpType") is None or u32(record["jumpType"]), "invalid-record")
        copied.append({k: record[k] for k in ("address", "destination", "size", "condition", "jumpType") if k in record})
    result = empty_sidecar(request["imageBase"], "records", "records-ready")
    result.update(reason=None, nanRecords=copied)
    # complete remains false: only JS has verified/patched the memory-image bytes.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("records", "probe"), required=True)
    parser.add_argument("--records", help="normalized JSON records; framing conversion belongs to nanomites.js")
    parser.add_argument("--sample", help="x86 master executable")
    parser.add_argument("--probe-plan", help="explicit addresses, independent lengths, flags/ECX samples")
    parser.add_argument("--sample-arg", action="append", default=[])
    parser.add_argument("--sidecar", help="JSON output path; stdout always contains the same protocol")
    parser.add_argument("--dump", help="write the target memory image after observation, before tree cleanup")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--max-events", type=int, default=20000)
    args = parser.parse_args(argv)
    try:
        if args.mode == "records":
            require(args.records and not args.sample and not args.probe_plan and not args.dump, "invalid-record-mode")
            result = supplied_records(read_json(args.records))
        else:
            require(not args.records, "invalid-probe-mode")
            require(args.sample and args.probe_plan, "missing-probe-plan")
            plan = validate_plan(read_json(args.probe_plan))
            result = MasterOracleBackend(plan, args.timeout, args.max_events, args.dump).run(args.sample, args.sample_arg)
    except (BackendError, OSError) as error:
        result = empty_sidecar(mode=args.mode)
        result["reason"] = error.reason if isinstance(error, BackendError) else "input-io-error"
        result["detail"] = str(error)
    text = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if args.sidecar:
        with open(args.sidecar, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text, flush=True)
    return 0 if result["status"] in ("records-ready", "observations-ready") else 3


if __name__ == "__main__":
    sys.exit(main())
