#!/usr/bin/env python3
"""Known-OEP debugger dump: run a sample under a Win32 debugger, break at a
caller-supplied OEP, and dump the in-memory image before any OEP code runs.
Containment: DEBUG_ONLY_THIS_PROCESS + Job Object kill-on-close + wall-clock timeout.
Anti-anti-debug v2: soft INT3s on the Wow64 (32-bit stdcall) ntdll entries of
NtQueryInformationProcess (fakes ProcessDebugPort/ProcessDebugObjectHandle/
ProcessDebugFlags for self-queries) and NtQuerySystemInformation (fakes
SystemKernelDebuggerInformation 0x23 as {Enabled=0, NotPresent=1}); other
classes pass through with a throttled re-arm. Success JSON carries
"antiAntiDebug": {planted, hits[, faked, va|reason], sysInfo: {...}}. Set
DUMP_ANTIANTI=0 to disable the hooks.
Usage: python dump_oep.py <sample.exe> <oep_rva_hex> <out.bin> [timeout_s]
Exit codes: 0 ok, 2 usage, 3 timeout, 4 process exited before breakpoint, 5 internal.
"""
import ctypes, ctypes.wintypes as wt, json, os, sys, time
from ctypes import c_wchar_p as LPWSTR

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_size_t

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", LPWSTR), ("lpDesktop", LPWSTR), ("lpTitle", LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", LPVOID), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]

class FLOATING_SAVE_AREA(ctypes.Structure):
    # Canonical x86 FSA, exactly 112 bytes (0x70). The legacy copy carried a
    # spurious ErrorOperand[2] after Tag, pushing every post-FSA field +8 so
    # the auto-oep poll read the wrong slot through ctx.Eip (MT31/T36).
    _fields_ = [("Control", wt.DWORD), ("Status", wt.DWORD), ("Tag", wt.DWORD),
                ("ErrorOffset", wt.DWORD), ("ErrorSelector", wt.DWORD),
                ("DataOffset", wt.DWORD), ("DataSelector", wt.DWORD),
                ("RegisterArea", ctypes.c_byte * 80), ("Cr0NpxState", wt.DWORD)]

class CONTEXT(ctypes.Structure):
    # Canonical x86 CONTEXT layout (Eax=0xB0, Eip=0xB8, Esp=0xC4, total 716).
    # One layout for every Get/SetThreadContext site: the auto-oep EIP poll
    # and the NtQueryInformationProcess hook below.
    _fields_ = [("ContextFlags", wt.DWORD), ("Dr0", wt.DWORD), ("Dr1", wt.DWORD),
                ("Dr2", wt.DWORD), ("Dr3", wt.DWORD), ("Dr6", wt.DWORD), ("Dr7", wt.DWORD),
                ("FloatSave", FLOATING_SAVE_AREA), ("SegGs", wt.DWORD), ("SegFs", wt.DWORD),
                ("SegEs", wt.DWORD), ("SegDs", wt.DWORD), ("Edi", wt.DWORD), ("Esi", wt.DWORD),
                ("Ebx", wt.DWORD), ("Edx", wt.DWORD), ("Ecx", wt.DWORD), ("Eax", wt.DWORD),
                ("Ebp", wt.DWORD), ("Eip", wt.DWORD), ("SegCs", wt.DWORD), ("EFlags", wt.DWORD),
                ("Esp", wt.DWORD), ("SegSs", wt.DWORD), ("ExtendedRegisters", ctypes.c_byte * 512)]

WOW64_CONTEXT = CONTEXT  # same canonical struct; the Wow64 alias keeps hook call sites explicit
# (call sites: the auto-oep EIP poll and the ntdll soft-breakpoint hooks below)

assert ctypes.sizeof(FLOATING_SAVE_AREA) == 112 and WOW64_CONTEXT.Eax.offset == 0xB0 \
    and WOW64_CONTEXT.Eip.offset == 0xB8 and WOW64_CONTEXT.Esp.offset == 0xC4 \
    and ctypes.sizeof(WOW64_CONTEXT) == 716

class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", wt.DWORD), ("ExceptionFlags", wt.DWORD),
                ("ExceptionRecord", LPVOID), ("ExceptionAddress", LPVOID),
                ("NumberParameters", wt.DWORD), ("ExceptionInformation", ctypes.c_size_t * 15)]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wt.DWORD)]

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("lpBaseOfImage", LPVOID), ("lpDebugInfo", LPVOID),
                ("lpThreadLocalBase", LPVOID), ("lpStartAddress", LPVOID),
                ("lpImageName", LPVOID), ("fUnicode", wt.WORD)]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("pad", ctypes.c_byte * 176)]

class DEBUG_EVENT(ctypes.Structure):
    _anonymous_ = ["u"]
    _fields_ = [("dwDebugEventCode", wt.DWORD), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD), ("u", DEBUG_EVENT_UNION)]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
                ("Affinity", ULONG_PTR), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD)]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]

class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [("Characteristics", wt.DWORD), ("TimeDateStamp", wt.DWORD),
                ("MajorVersion", wt.WORD), ("MinorVersion", wt.WORD),
                ("Name", wt.DWORD), ("Base", wt.DWORD),
                ("NumberOfFunctions", wt.DWORD), ("NumberOfNames", wt.DWORD),
                ("AddressOfFunctions", wt.DWORD), ("AddressOfNames", wt.DWORD),
                ("AddressOfNameOrdinals", wt.DWORD)]

LIST_MODULES_32BIT = 0x01
MAX_EXPORT_FUNCTIONS = 200000

try:
    EnumProcessModulesEx = k32.K32EnumProcessModulesEx
    GetModuleFileNameExW = k32.K32GetModuleFileNameExW
except AttributeError:  # pre-Win7 psapi.dll fallback
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    EnumProcessModulesEx = psapi.EnumProcessModulesEx
    GetModuleFileNameExW = psapi.GetModuleFileNameExW
EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(LPVOID), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
EnumProcessModulesEx.restype = wt.BOOL
GetModuleFileNameExW.argtypes = [wt.HANDLE, LPVOID, wt.LPWSTR, wt.DWORD]
GetModuleFileNameExW.restype = wt.DWORD
k32.OpenThread.restype = wt.HANDLE
k32.GetCurrentProcess.restype = wt.HANDLE
k32.GetProcessId.restype = wt.DWORD

def fail(code, message):
    print(json.dumps({"ok": False, "error": message}), file=sys.stdout, flush=True)
    sys.exit(code)

def patch_peb(h_process):
    # Anti-anti-debugging v1: hide this debugger from the classic user-mode
    # probes. Covered:
    #  - PEB.BeingDebugged (IsDebuggerPresent)
    #  - PEB.NtGlobalFlag (debug-heap FLG_* bits)
    #  - PEB.ProcessHeap (main heap only, v1 scope): a heap created under a
    #    debugger gets Flags/ForceFlags bits HEAP_TAIL_CHECKING_ENABLED(0x20)
    #    | HEAP_FREE_CHECKING_ENABLED(0x40) | HEAP_VALIDATE_PARAMETERS_ENABLED
    #    (0x40000000) (plus the adjacent debug-heap bit 0x20000000 on some
    #    releases); protectors test Flags/ForceFlags for them. Only those
    #    known detection bits are cleared, never the whole field, so heap
    #    behavior stays intact. All patch failures are silently tolerated.
    # NOT covered by patch_peb: rdtsc/timing checks. The kernel-level probes
    # (NtQueryInformationProcess ProcessDebugPort / ProcessDebugObjectHandle /
    # ProcessDebugFlags) are hidden by the ntdll soft-breakpoint hook below
    # (anti-anti-debug v2), not by this function.
    ntdll = ctypes.WinDLL("ntdll")
    class PBI(ctypes.Structure):
        _fields_ = [("Reserved1", LPVOID), ("PebBaseAddress", LPVOID),
                    ("Reserved2", LPVOID * 2), ("UniqueProcessId", ctypes.c_size_t), ("Reserved3", LPVOID)]
    info = PBI(); returned = ctypes.c_ulong(0)
    if ntdll.NtQueryInformationProcess(h_process, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)) != 0:
        return False
    peb = info.PebBaseAddress
    if not peb:
        return False
    n = SIZE_T(0)
    k32.WriteProcessMemory(h_process, LPVOID(peb + 2), b"\x00", 1, ctypes.byref(n))            # BeingDebugged
    k32.WriteProcessMemory(h_process, LPVOID(peb + 0x68), b"\x00\x00\x00\x00", 4, ctypes.byref(n))  # NtGlobalFlag
    # PEB.ProcessHeap (x86 PEB+0x18) -> _HEAP.Flags(+0x0C) / _HEAP.ForceFlags(+0x10)
    heap_ptr = ctypes.c_uint32(0)
    if k32.ReadProcessMemory(h_process, LPVOID(peb + 0x18), ctypes.byref(heap_ptr), 4, ctypes.byref(n)) and heap_ptr.value:
        pair = ctypes.create_string_buffer(8)
        if k32.ReadProcessMemory(h_process, LPVOID(heap_ptr.value + 0x0C), pair, 8, ctypes.byref(n)) and n.value == 8:
            mask = 0x60000060  # 0x20|0x40 tail/free checking, 0x40000000 validate-params, 0x20000000 debug-heap bit
            flags = int.from_bytes(pair.raw[0:4], "little") & ~mask
            force = int.from_bytes(pair.raw[4:8], "little") & ~mask
            k32.WriteProcessMemory(h_process, LPVOID(heap_ptr.value + 0x0C),
                                   flags.to_bytes(4, "little") + force.to_bytes(4, "little"), 8, ctypes.byref(n))
    return True

def main():
    if len(sys.argv) < 4:
        fail(2, "usage: dump_oep.py <sample.exe> <oep_rva_hex|auto> <out.bin> [timeout_s] [mode] [delay_s]")
    sample, oep_rva_s, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
    mode = sys.argv[5] if len(sys.argv) > 5 else "oep"
    delay_s = float(sys.argv[6]) if len(sys.argv) > 6 else 0.25
    auto_oep = oep_rva_s.lower() == "auto"
    oep_rva = 0 if auto_oep else int(oep_rva_s, 0)

    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{sample}"')
    if not k32.CreateProcessW(None, cmd, None, None, False, 0x2 | 0x4, None, None, ctypes.byref(si), ctypes.byref(pi)):
        fail(5, f"CreateProcessW error {ctypes.get_last_error()}")

    job = k32.CreateJobObjectW(None, None)
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
    k32.AssignProcessToJobObject(job, pi.hProcess)
    k32.ResumeThread(pi.hThread)

    h_process = None; image_base = 0; breakpoint_va = 0; h_main_thread = None
    oep_original_byte = None
    planted = [False]; oep_saved_byte = [None]; saw_unpack = [False]
    started = time.monotonic(); hit = False; error = None
    exit_late = [False]  # EXIT_PROCESS fallback dumps after the app ran: late

    # --- rdtsc interference assessment (T37; documented decision: NOT DONE) ---
    # Soft INT3 hooks cannot intercept rdtsc: it is an unprivileged inline
    # instruction -- no syscall to redirect, no exception to swallow. The
    # candidate v3 mechanisms all fail on this host class or on soundness:
    #  * DR hardware breakpoints / EFlags.TF: they trap code/data access, not
    #    rdtsc itself -- and this VBS/HVCI host silently filters DR7 G-bits
    #    and TF anyway (MT17 platform finding), so even their own use cases
    #    are dead here.
    #  * CR4.TSD (rdtsc -> #GP, SEH-shadow the fault): CR4 is kernel-owned; a
    #    user-mode debugger cannot set it per-debuggee. The kernel-driver
    #    route (TitanHide-style TSC skew on context switch) is undeployable:
    #    driver signing + VBS already owns the platform.
    #  * Own hypervisor with RDTSC-exit interception: no VMX slot is left on
    #    a VBS host; on bare metal it is a project of its own, not a v3
    #    tweak, and it changes every timing observable process-wide.
    #  * Patching 0F 31 sites / "rdtsc-dense page" guard pilot (the one
    #    low-cost candidate the card allows): rejected. 0F 31 as data is
    #    everywhere -- patching corrupts data, guarding trips on ordinary
    #    writes; packers run rdtsc from freshly VirtualAlloc'd pages that
    #    cannot be enumerated in advance; and a guard exception only SIGNALS
    #    the timing code, it does not mask the delta -- the actual observable
    #    (huge TSC step across our Python debug-event round trip) remains.
    #    Cost/risk >> benefit; no pilot survived the cost side.
    # Residual exposure accepted as-is: a protector taking TSC deltas around
    # the very calls we fake still measures our per-hit debug-loop latency.
    # Nothing in the current sample corpus gates on that; if one ever does,
    # the honest fix is lowering hot-path latency (fewer debug events), not
    # rdtsc interception.

    # Anti-anti-debug v2 state: soft INT3s on the 32-bit (Wow64) ntdll
    # entries of NtQueryInformationProcess and NtQuerySystemInformation.
    # "armed" = the 0xCC is live; pass-throughs disarm it and the loop tail
    # re-arms after a >=6ms throttle so non-debug classes never thrash the
    # debugger loop.
    anti_on = os.environ.get("DUMP_ANTIANTI", "1") != "0"

    def make_hook(export, ret_imm):
        return {"export": export, "ret": ret_imm, "va": 0, "orig": 0, "armed": False,
                "ever": False, "hits": 0, "faked": 0, "fail": None, "rearm_at": 0.0}

    nqip = make_hook("NtQueryInformationProcess", 0x14)  # 5 args, ret 0x14
    nqsi = make_hook("NtQuerySystemInformation", 0x10)   # 4 args, ret 0x10

    def plant_int3():
        # Plant the OEP INT3 only if the packer has already written the OEP
        # byte (an early plant would be overwritten). Returns True on success.
        if planted[0] or not breakpoint_va:
            return planted[0]
        probe = ctypes.c_byte(0); n0 = SIZE_T(0)
        if not k32.ReadProcessMemory(h_process, LPVOID(breakpoint_va), ctypes.byref(probe), 1, ctypes.byref(n0)) or probe.value == 0:
            return False
        oep_saved_byte[0] = probe.value
        n1 = SIZE_T(0)
        if k32.WriteProcessMemory(h_process, LPVOID(breakpoint_va), b"\xcc", 1, ctypes.byref(n1)):
            planted[0] = True
        return planted[0]

    def looks_like_int2d(address):
        # int 0x2d is the 2-byte insn CD 2D. Its ExceptionAddress normally
        # points just past the insn, so probe the 2 bytes before the address;
        # also accept the 2 bytes at the address (address-at-insn delivery,
        # mirroring how the INT3 path accepts breakpoint_va and +1).
        if not h_process or not address:
            return False
        start = address - 2 if address >= 2 else address
        probe = ctypes.create_string_buffer(4); nread = SIZE_T(0)
        if not k32.ReadProcessMemory(h_process, LPVOID(start), probe, 4, ctypes.byref(nread)) or nread.value < 2:
            return False
        return probe.raw[0:2] == b"\xcd\x2d" or probe.raw[2:4] == b"\xcd\x2d"

    ev = DEBUG_EVENT()
    poll_until = [None]
    extract_at = [None]
    auto_target = [None]
    auto_shell = [None]
    auto_armed = [False]
    def do_dump(late):
        n = SIZE_T(0)
        header = ctypes.create_string_buffer(0x400)
        if not k32.ReadProcessMemory(h_process, LPVOID(image_base), header, 0x400, ctypes.byref(n)) or n.value < 0x200:
            raise RuntimeError("cannot read PE header from memory")
        e_lfanew = int.from_bytes(header.raw[0x3c:0x40], "little")

        def read_full(size):
            # FSG fix (2nd half): the auto-oep tripwire arms PAGE_GUARD across
            # the whole target region; guard pages the debuggee never touched
            # are still armed at dump time and make ReadProcessMemory fail
            # wholesale with ERROR_PARTIAL_COPY. Detection is over by now, so
            # strip the guard bit (keep the base protection) before reading.
            class MBI(ctypes.Structure):
                _fields_ = [("BaseAddress", LPVOID), ("AllocationBase", LPVOID), ("AllocationProtect", wt.DWORD),
                            ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]
            addr = image_base
            while addr < image_base + size:
                mbi = MBI()
                if not k32.VirtualQueryEx(h_process, LPVOID(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) or not mbi.RegionSize:
                    break
                if mbi.State == 0x1000 and mbi.Protect & 0x100:  # committed + PAGE_GUARD
                    old = wt.DWORD(0)
                    k32.VirtualProtectEx(h_process, LPVOID(addr), SIZE_T(min(mbi.RegionSize, image_base + size - addr)),
                                         mbi.Protect & ~0x100, ctypes.byref(old))
                addr += mbi.RegionSize
            buf = ctypes.create_string_buffer(size)
            if not k32.ReadProcessMemory(h_process, LPVOID(image_base), buf, size, ctypes.byref(n)) or n.value != size:
                return None
            return buf

        def size_from_section_table():
            # FSG fix: its in-memory image can carry a mangled PE header
            # (DOS/PE overlap, implausible SizeOfImage). Rebuild the size
            # from the section table: max(section VA+VS) rounded up to
            # SectionAlignment; use 0x1000 as the alignment when that field
            # is itself unreadable or implausible, or when the table cannot
            # be read at all (then no usable sections means no size either).
            if not (0x40 <= e_lfanew <= 0x380):
                return None
            try:
                nsec = int.from_bytes(header.raw[e_lfanew + 6:e_lfanew + 8], "little")
                opt_size = int.from_bytes(header.raw[e_lfanew + 20:e_lfanew + 22], "little")
                if not (1 <= nsec <= 96):
                    return None
                align = int.from_bytes(header.raw[e_lfanew + 0x38:e_lfanew + 0x3c], "little")
                if not align or align & (align - 1) or not (0x200 <= align <= 0x10000):
                    align = 0x1000
                table = read_mem(image_base + e_lfanew + 24 + opt_size, 40 * nsec)
                if table is None:
                    return None
                end = 0
                for i in range(nsec):
                    vs = int.from_bytes(table[i * 40 + 8:i * 40 + 12], "little")
                    va = int.from_bytes(table[i * 40 + 12:i * 40 + 16], "little")
                    end = max(end, va + vs)
                if end <= 0:
                    return None
                return (end + align - 1) & ~(align - 1)
            except Exception:  # noqa: BLE001
                return None

        # Primary: in-memory SizeOfImage, sanity-bounded to [0x1000,
        # 0x8000000]; outside that (FSG garbage) skip straight to the
        # section-table fallback. A field that looks valid but whose tail
        # pages are not committed also falls back after a failed read.
        size_of_image = None
        if 0x40 <= e_lfanew <= 0x380:
            field = int.from_bytes(header.raw[e_lfanew + 0x50:e_lfanew + 0x54], "little")
            if 0x1000 <= field <= 0x8000000:
                size_of_image = field
        buf = read_full(size_of_image) if size_of_image else None
        size_used = size_of_image if buf is not None else None
        if size_used is None:
            fallback = size_from_section_table()
            if fallback and 0x1000 <= fallback <= 0x8000000:
                alt = read_full(fallback)
                if alt is not None:
                    buf = alt
                    size_used = fallback
        if buf is None or size_used is None:
            raise RuntimeError("cannot dump image")
        with open(out_path, "wb") as handle:
            handle.write(buf.raw[: size_used])
        return {"ok": True, "imageBase": image_base, "oepRva": oep_rva, "size": size_used, "late": late}

    def read_mem(addr, size):
        buf = ctypes.create_string_buffer(size)
        n = SIZE_T(0)
        if not k32.ReadProcessMemory(h_process, LPVOID(addr), buf, size, ctypes.byref(n)) or n.value != size:
            return None
        return buf.raw

    def read_cstr(addr, limit=512):
        data = read_mem(addr, limit)
        if data is None:
            return None
        return data.split(b"\0", 1)[0].decode("latin-1")

    def find_export_va(base, wanted):
        # Minimal export walker for one remote 32-bit module: header bounds,
        # export directory, linear name scan (robust to unsorted tables),
        # ordinal back-mapping, forwarder rejection.
        hdr = read_mem(base, 0x400)
        if hdr is None or hdr[:2] != b"MZ":
            return 0
        e = int.from_bytes(hdr[0x3c:0x40], "little")
        if not (0x40 <= e <= 0x380) or hdr[e:e + 4] != b"PE\x00\x00" or hdr[e + 24:e + 26] != b"\x0b\x01":
            return 0
        exp_rva = int.from_bytes(hdr[e + 0x78:e + 0x7c], "little")
        exp_size = int.from_bytes(hdr[e + 0x7c:e + 0x80], "little")
        if not exp_rva:
            return 0
        raw = read_mem(base + exp_rva, 40)
        if raw is None:
            return 0
        nfuncs = int.from_bytes(raw[20:24], "little")
        nnames = int.from_bytes(raw[24:28], "little")
        if not nnames or nfuncs > MAX_EXPORT_FUNCTIONS or nnames > MAX_EXPORT_FUNCTIONS:
            return 0
        names_raw = read_mem(base + int.from_bytes(raw[32:36], "little"), 4 * nnames)
        if names_raw is None:
            return 0
        for i in range(nnames):
            name_rva = int.from_bytes(names_raw[4 * i:4 * i + 4], "little")
            if name_rva and read_cstr(base + name_rva, 64) == wanted:
                o = read_mem(base + int.from_bytes(raw[36:40], "little") + 2 * i, 2)
                if o is None:
                    return 0
                idx = int.from_bytes(o, "little")
                if idx >= nfuncs:
                    return 0
                fr = read_mem(base + int.from_bytes(raw[28:32], "little") + 4 * idx, 4)
                if fr is None:
                    return 0
                rva = int.from_bytes(fr, "little")
                if not rva or (exp_rva <= rva < exp_rva + exp_size):
                    return 0
                return base + rva
        return 0

    def find_ntdll_hooks():
        # Resolve the Wow64 (32-bit) ntdll entries for both hooks. Retried on
        # later events while ntdll32 is not enumerable yet; per-hook fail
        # only records terminal causes (found module, bad entry).
        if not anti_on or not h_process:
            return
        pending = [h for h in (nqip, nqsi) if not h["va"] and h["fail"] is None]
        if not pending:
            return
        mods = (LPVOID * 256)(); needed = wt.DWORD(0)
        if not EnumProcessModulesEx(h_process, mods, ctypes.sizeof(mods), ctypes.byref(needed), LIST_MODULES_32BIT):
            return
        for i in range(min(needed.value // ctypes.sizeof(LPVOID), 256)):
            base = int(mods[i] or 0)
            if not base:
                continue
            path_buf = ctypes.create_unicode_buffer(1024)
            dll = path_buf.value.rsplit("\\", 1)[-1].lower() if GetModuleFileNameExW(h_process, LPVOID(base), path_buf, 1024) else ""
            if dll != "ntdll.dll":
                continue
            for h in pending:
                va = find_export_va(base, h["export"])
                first = read_mem(va, 1) if va else None
                if va and first and first[0] != 0xCC:
                    h["va"] = va; h["orig"] = first[0]
                else:
                    h["fail"] = "entry unreadable/already-INT3" if va else "export not found"
            return

    def remote_poke(addr, data):
        # Write bytes into remote memory with the VirtualProtectEx RWX dance
        # and an instruction-cache flush (needed when patching live code).
        old = wt.DWORD(0); n = SIZE_T(0)
        if not k32.VirtualProtectEx(h_process, LPVOID(addr), SIZE_T(len(data)), 0x40, ctypes.byref(old)):
            return False
        ok = bool(k32.WriteProcessMemory(h_process, LPVOID(addr), data, len(data), ctypes.byref(n))) and n.value == len(data)
        k32.FlushInstructionCache(h_process, LPVOID(addr), SIZE_T(len(data)))
        prev = wt.DWORD(0)
        k32.VirtualProtectEx(h_process, LPVOID(addr), SIZE_T(len(data)), old.value, ctypes.byref(prev))
        return ok

    def arm_hook(h):
        if not (anti_on and h["va"] and not h["armed"] and h_process):
            return False
        if remote_poke(h["va"], b"\xcc") and read_mem(h["va"], 1) == b"\xcc":
            h["armed"] = True; h["ever"] = True
            return True
        h["rearm_at"] = time.monotonic() + 0.05  # transient failure: retry later
        return False

    def handle_is_self(remote_handle):
        # -1 is the current-process pseudo handle; other values are resolved
        # by duplicating the debuggee-side handle into this process and
        # comparing PIDs, so queries about other processes stay truthful.
        if remote_handle == 0xFFFFFFFF:
            return True
        if not remote_handle:
            return False
        dup = wt.HANDLE(0)
        if k32.DuplicateHandle(h_process, wt.HANDLE(remote_handle), k32.GetCurrentProcess(), ctypes.byref(dup), 0, False, 0x2):
            pid = k32.GetProcessId(dup)
            k32.CloseHandle(dup)
            return pid == pi.dwProcessId
        return False

    def nqip_try_fake(stack):
        # Ground truth for a NOT-debugged process: DebugPort returns
        # 0 with STATUS_SUCCESS; DebugObjectHandle returns 0 with
        # STATUS_PORT_NOT_SET (the kernel fails the query, so probes
        # keyed on NT_SUCCESS() also stay quiet); DebugFlags returns
        # 1 (NoDebugInherit) with STATUS_SUCCESS. ReturnLength is
        # only written on the success-shaped answers.
        def u32at(o):
            return int.from_bytes(stack[o:o + 4], "little")
        proc_handle, klass, info, infolen, retlen = (u32at(o) for o in (4, 8, 0xC, 0x10, 0x14))
        if klass in (0x07, 0x1E, 0x1F) and info and infolen >= 4 and handle_is_self(proc_handle):
            value, ntstatus = (0, 0) if klass == 0x07 else ((0, 0xC0000353) if klass == 0x1E else (1, 0))
            return ntstatus, [(info, value.to_bytes(4, "little"))], (retlen if klass != 0x1E else 0), 4
        return None

    def nqsi_try_fake(stack):
        # SystemKernelDebuggerInformation (0x23): report the classic
        # "no kernel debugger" pair {KernelDebuggerEnabled=0,
        # KernelDebuggerNotPresent=1} with STATUS_SUCCESS and
        # ReturnLength 2. On a stock host this already equals the truth
        # (the class watches KD, not user-mode debuggers); faking it
        # guarantees the answer even on a KD-enabled rig and keeps the
        # query out of syscall-level timing.
        def u32at(o):
            return int.from_bytes(stack[o:o + 4], "little")
        klass, info, infolen, retlen = (u32at(o) for o in (4, 8, 0xC, 0x10))
        if klass == 0x23 and info and infolen >= 2:
            return 0, [(info, b"\x00\x01")], retlen, 2
        return None

    def handle_trap(h, tid, stack_len, try_fake):
        # Soft-BP hit at h["va"] (32-bit stdcall): [esp]=ret, args follow.
        # try_fake(stack) -> (eax, [(addr, bytes)...], retlen_addr,
        # retlen_value) or None to pass through. The faked path emulates
        # `ret <h["ret"]>` and keeps the 0xCC armed; everything else passes
        # through: restore the original byte, rewind EIP onto it,
        # DBG_CONTINUE, re-arm after the shared throttle. Buffer
        # writability is proven by the WriteProcessMemory calls themselves;
        # a read-only probe buffer falls through to the honest syscall.
        h["hits"] += 1
        h_thread = k32.OpenThread(0x18, False, tid)  # GET|SET CONTEXT
        ctx = WOW64_CONTEXT(); ctx.ContextFlags = 0x10003  # i386 CONTROL|INTEGER (Eax is INTEGER)
        stack = None
        if h_thread and k32.Wow64GetThreadContext(h_thread, ctypes.byref(ctx)) and ctx.Eip in (h["va"], h["va"] + 1):
            stack = read_mem(ctx.Esp, stack_len)
        if os.environ.get("DUMP_DEBUG"):
            dbg = "%s tid=%d eip=%s" % (h["export"], tid, hex(ctx.Eip) if h_thread else "?")
            if stack is not None:
                dbg += " args=" + ",".join(hex(int.from_bytes(stack[i:i + 4], "little")) for i in range(4, len(stack), 4))
            print(dbg, file=sys.stderr, flush=True)
        faked = False
        if stack is not None:
            plan = try_fake(stack)
            if plan is not None:
                eax, writes, retlen_addr, retlen_value = plan
                n = SIZE_T(0)
                if all(k32.WriteProcessMemory(h_process, LPVOID(addr), data, len(data), ctypes.byref(n)) and n.value == len(data)
                       for addr, data in writes):
                    if retlen_addr:
                        k32.WriteProcessMemory(h_process, LPVOID(retlen_addr), retlen_value.to_bytes(4, "little"), 4, ctypes.byref(n))
                    ctx.Eax = eax
                    ctx.Eip = int.from_bytes(stack[0:4], "little")       # return address
                    ctx.Esp = (ctx.Esp + 4 + h["ret"]) & 0xFFFFFFFF       # emulate ret imm16
                    if k32.Wow64SetThreadContext(h_thread, ctypes.byref(ctx)):
                        faked = True
                        h["faked"] += 1
        if not faked:
            h["armed"] = False
            h["rearm_at"] = time.monotonic() + 0.006
            remote_poke(h["va"], bytes([h["orig"] & 0xFF]))
            if h_thread and stack is not None:
                ctx.Eip = h["va"]
                k32.Wow64SetThreadContext(h_thread, ctypes.byref(ctx))
        if h_thread:
            k32.CloseHandle(h_thread)
        return 0x00010002  # DBG_CONTINUE (both paths fully handle the trap)

    def hook_report(h):
        report = {"planted": h["ever"], "hits": h["hits"]}
        if h["va"]:
            report["faked"] = h["faked"]; report["va"] = hex(h["va"])
        else:
            report["reason"] = h["fail"] or "32-bit ntdll entry not resolved"
        return report

    def anti_report():
        if not anti_on:
            return {"planted": False, "hits": 0, "reason": "disabled",
                    "sysInfo": {"planted": False, "hits": 0}}
        return {**hook_report(nqip), "sysInfo": hook_report(nqsi)}

    def collect_module_exports(base):
        # base: remote module load address (HMODULE in the debuggee).
        # Returns the contract dict, or None when the module must be skipped.
        hdr = read_mem(base, 0x400)
        if hdr is None or hdr[:2] != b"MZ":
            return None
        e_lfanew = int.from_bytes(hdr[0x3c:0x40], "little")
        if not (0x40 <= e_lfanew <= 0x380) or hdr[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        if hdr[e_lfanew + 24:e_lfanew + 26] != b"\x0b\x01":  # PE32 targets only
            return None
        exp_rva = int.from_bytes(hdr[e_lfanew + 0x78:e_lfanew + 0x7c], "little")   # DataDirectory[0].VirtualAddress
        exp_size = int.from_bytes(hdr[e_lfanew + 0x7c:e_lfanew + 0x80], "little")  # DataDirectory[0].Size
        if not exp_rva:
            return None
        raw = read_mem(base + exp_rva, ctypes.sizeof(IMAGE_EXPORT_DIRECTORY))
        if raw is None:
            return None
        expdir = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(raw)
        nfuncs, nnames = expdir.NumberOfFunctions, expdir.NumberOfNames
        if nfuncs == 0 or nfuncs > MAX_EXPORT_FUNCTIONS or nnames > MAX_EXPORT_FUNCTIONS:
            return None
        funcs_raw = read_mem(base + expdir.AddressOfFunctions, 4 * nfuncs)
        if funcs_raw is None:
            return None
        names_by_index = {}
        if nnames:
            names_raw = read_mem(base + expdir.AddressOfNames, 4 * nnames)
            ords_raw = read_mem(base + expdir.AddressOfNameOrdinals, 2 * nnames)
            if names_raw is None or ords_raw is None:
                return None
            for i in range(nnames):
                name_rva = int.from_bytes(names_raw[4 * i:4 * i + 4], "little")
                oi = int.from_bytes(ords_raw[2 * i:2 * i + 2], "little")
                if not name_rva or oi >= nfuncs:
                    continue
                s = read_cstr(base + name_rva)
                if s:
                    names_by_index[oi] = s
        dll = ""
        path_buf = ctypes.create_unicode_buffer(1024)
        if GetModuleFileNameExW(h_process, LPVOID(base), path_buf, 1024):
            dll = path_buf.value.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
        if not dll and expdir.Name:
            dll = read_cstr(base + expdir.Name) or ""
        if not dll:
            return None
        exports = []
        for idx in range(nfuncs):
            rva = int.from_bytes(funcs_raw[4 * idx:4 * idx + 4], "little")
            # skip empty slots and forwarders (RVA inside the export directory)
            if not rva or (exp_rva <= rva < exp_rva + exp_size):
                continue
            if idx in names_by_index:
                exports.append({"rva": hex(rva), "name": names_by_index[idx]})
            else:
                exports.append({"rva": hex(rva), "ordinal": expdir.Base + idx})
        if not exports:
            return None
        return {"dll": dll.upper(), "imageBase": hex(base), "exports": exports}

    def collect_imports():
        mods = (LPVOID * 1024)()
        needed = wt.DWORD(0)
        if not h_process or not EnumProcessModulesEx(h_process, mods, ctypes.sizeof(mods), ctypes.byref(needed), LIST_MODULES_32BIT):
            return []
        count = min(needed.value // ctypes.sizeof(LPVOID), 1024)
        result = []
        for i in range(count):
            base = int(mods[i] or 0)
            if base:
                try:
                    info = collect_module_exports(base)
                except Exception:  # noqa: BLE001
                    info = None
                if info:
                    result.append(info)
        return result

    def write_imports(modules):
        with open(out_path + ".imports.json", "w", encoding="utf-8") as handle:
            json.dump({"modules": modules}, handle, separators=(",", ":"))

    def dump_imports_safe():
        # Never let export collection break an otherwise successful dump.
        try:
            write_imports(collect_imports())
        except Exception:  # noqa: BLE001
            pass

    while not hit:
        if auto_oep and auto_armed[0]:
            ctx = CONTEXT(); ctx.ContextFlags = 0x10001
            if k32.Wow64GetThreadContext(pi.hThread, ctypes.byref(ctx)):
                eip = ctx.Eip
                target, shell = auto_target[0], auto_shell[0]
                if target and shell and target[0] <= eip < target[1] and not (shell[0] <= eip < shell[1]) and eip >= image_base:
                    try:
                        # Precise catch: EIP observed inside the unpacked
                        # region, not the timeout fallback -> not a late dump.
                        result = do_dump(False)
                        dump_imports_safe()
                        print(json.dumps({**result, "stage": "auto-oep", "eipRva": eip - image_base, "antiAntiDebug": anti_report()}), flush=True)
                        sys.exit(0)
                    except Exception as exception:  # noqa: BLE001
                        fail(5, f"auto-oep dump failed: {exception}")
        if mode == "extract" and extract_at[0] is not None and time.monotonic() >= extract_at[0]:
            try:
                result = do_dump(True)
                try:
                    dump_imports_safe()
                except Exception:  # noqa: BLE001
                    pass
                print(json.dumps({**result, "antiAntiDebug": anti_report()}), flush=True)
                sys.exit(0)
            except Exception as exception:  # noqa: BLE001
                fail(5, f"extract dump failed: {exception}")
        if poll_until[0] is None and time.monotonic() - started > timeout_s:
            # Collect exports while the process is still alive; written only
            # if the late dump below succeeds.
            late_imports = None
            if saw_unpack[0] and h_process:
                try:
                    late_imports = collect_imports()
                except Exception:  # noqa: BLE001
                    late_imports = None
            k32.TerminateProcess(pi.hProcess, 1)
            if saw_unpack[0] and h_process:
                # Fallback: decompression finished but the OEP race was lost
                # (VBS hosts filter DR/TF). Dump the unpacked memory anyway.
                try:
                    result = do_dump(True)
                    if late_imports is not None:
                        try:
                            write_imports(late_imports)
                        except Exception:  # noqa: BLE001
                            pass
                    stage = "auto-oep-late" if auto_oep else None
                    print(json.dumps({**result, **({"stage": stage} if stage else {}), "antiAntiDebug": anti_report()}), flush=True)
                    sys.exit(0)
                except Exception as exception:  # noqa: BLE001
                    fail(5, f"late dump failed: {exception}")
            fail(3, "timeout before OEP breakpoint")
        if not k32.WaitForDebugEvent(ctypes.byref(ev), (0 if auto_armed[0] else 5) if auto_oep else 100 if mode == "extract" else 500):
            # auto mode: once armed, poll the EIP at full speed (0ms wait) --
            # the decompression-finish -> OEP-jump window is sub-millisecond,
            # a 5ms cadence misses it every time (T36 second root cause).
            continue
        code = ev.dwDebugEventCode
        # Any post-decompression event (load dll, thread, exception) is a
        # chance the packer has finished writing the OEP byte: try planting.
        if code != 3 and breakpoint_va and not auto_oep:
            plant_int3()
        if sys.stderr.isatty() or os.environ.get("DUMP_DEBUG"):
            print(f"event {code} pid={ev.dwProcessId} tid={ev.dwThreadId}", file=sys.stderr, flush=True)
        status = 0x00010002  # DBG_CONTINUE
        try:
            if code == 3:  # CREATE_PROCESS_DEBUG_EVENT
                h_process = ev.u.CreateProcessInfo.hProcess or pi.hProcess
                h_main_thread = wt.HANDLE(ev.u.CreateProcessInfo.hThread)
                image_base = ev.u.CreateProcessInfo.lpBaseOfImage or 0
                if not image_base:
                    raise RuntimeError("no image base")
                breakpoint_va = image_base + oep_rva
                if auto_oep:
                    # Heuristic target region: the section with the largest
                    # virtual size and near-zero raw data is the decompression
                    # destination; the shell lives in the entry section.
                    header = ctypes.create_string_buffer(0x1000)
                    n = SIZE_T(0)
                    k32.ReadProcessMemory(h_process, LPVOID(image_base), header, 0x1000, ctypes.byref(n))
                    e_lfanew = int.from_bytes(header.raw[0x3c:0x40], "little")
                    nsec = int.from_bytes(header.raw[e_lfanew + 6:e_lfanew + 8], "little")
                    opt_size = int.from_bytes(header.raw[e_lfanew + 20:e_lfanew + 22], "little")
                    ep_rva = int.from_bytes(header.raw[e_lfanew + 0x28:e_lfanew + 0x2c], "little")
                    best, shell = None, None
                    for i in range(min(nsec, 16)):
                        at = e_lfanew + 24 + opt_size + i * 40
                        vs = int.from_bytes(header.raw[at + 8:at + 12], "little")
                        va = int.from_bytes(header.raw[at + 12:at + 16], "little")
                        rs = int.from_bytes(header.raw[at + 16:at + 20], "little")
                        if vs < 0x1000:
                            continue
                        if shell is None and va <= ep_rva < va + max(vs, rs):
                            shell = (va, va + max(vs, rs, 0x1000))
                        if rs <= 0x400 and (best is None or vs > best[1] - best[0]):
                            best = (va, va + vs)
                    # Store ABSOLUTE VAs: the EIP poll below compares raw
                    # register values. Comparing section RVAs against a
                    # garbage/low absolute Eip once fired a premature dump
                    # of the still-zero decompression buffer (seen on FSG).
                    auto_target[0] = (image_base + best[0], image_base + best[1]) if best else None
                    auto_shell[0] = (image_base + shell[0], image_base + shell[1]) if shell else None
                    if best:
                        old = wt.DWORD(0)
                        span = best[1] - best[0]
                        k32.VirtualProtectEx(h_process, LPVOID(image_base + best[0]), SIZE_T(span), 0x40 | 0x100, ctypes.byref(old))
                elif mode == "oep":
                    # Guard the OEP page: its first write by the packer tells us
                    # decompression has started (DR/TF are filtered on VBS hosts).
                    guard_page = image_base + (oep_rva & ~0xFFF)
                    old = wt.DWORD(0)
                    if not k32.VirtualProtectEx(h_process, LPVOID(guard_page), SIZE_T(0x1000), 0x40 | 0x100, ctypes.byref(old)):
                        raise RuntimeError(f"VirtualProtectEx(GUARD) error {ctypes.get_last_error()}")
                if anti_on:
                    find_ntdll_hooks()
            elif code == 1:  # EXCEPTION_DEBUG_EVENT
                record = ev.u.Exception.ExceptionRecord
                ecode = record.ExceptionCode & 0xFFFFFFFF
                address = record.ExceptionAddress or 0
                if os.environ.get("DUMP_DEBUG"):
                    print(f"exception {ecode:#x} at {address:#x} bp={breakpoint_va:#x} first={ev.u.Exception.dwFirstChance}", file=sys.stderr, flush=True)
                int3_hit = ecode in (0x80000003, 0x4000001f) and address in (breakpoint_va, breakpoint_va + 1)
                if (ecode == 0x80000001 and address == breakpoint_va) or (int3_hit and breakpoint_va):
                    # Either a GUARD_PAGE hit while executing exactly at the
                    # OEP, or the INT3 we planted: the image is unpacked and
                    # ready to dump. Restore the overwritten OEP byte first.
                    if planted[0] and oep_saved_byte[0] is not None:
                        n_restore = SIZE_T(0)
                        k32.WriteProcessMemory(h_process, LPVOID(breakpoint_va), bytes([oep_saved_byte[0] & 0xFF]), 1, ctypes.byref(n_restore))
                    do_dump(False)
                    dump_imports_safe()
                    hit = True
                elif anti_on and ecode in (0x80000003, 0x4000001f) and (
                        (nqip["armed"] and address in (nqip["va"], nqip["va"] + 1))
                        or (nqsi["armed"] and address in (nqsi["va"], nqsi["va"] + 1))):
                    # Our ntdll hooks (never the OEP INT3: different module) —
                    # placed before the int2d/loader-break branches so neither
                    # can shadow them or swallow them.
                    if nqip["armed"] and address in (nqip["va"], nqip["va"] + 1):
                        status = handle_trap(nqip, ev.dwThreadId, 0x18, nqip_try_fake)
                    else:
                        status = handle_trap(nqsi, ev.dwThreadId, 0x14, nqsi_try_fake)
                elif ecode == 0x80000001:
                    if auto_oep:
                        # First write into the guarded target region means
                        # decompression started: switch to high-frequency EIP
                        # polling (guard stays disarmed, no refire loop).
                        saw_unpack[0] = True
                        auto_armed[0] = True
                        status = 0x00010002  # DBG_CONTINUE
                    else:
                        # Decompression started. After Continue, poll briefly:
                        # once the native write burst passes the OEP byte, plant
                        # the INT3 during the packer's import-resolution window.
                        saw_unpack[0] = True
                        poll_until[0] = time.monotonic() + 0.05
                        status = 0x00010002  # DBG_CONTINUE
                elif ecode == 0x80000003 and looks_like_int2d(address):
                    # Anti-anti-debug v1: int 0x2d probe (CD 2D), used by e.g.
                    # FSG-era protectors. Behavior map: not debugged, it raises
                    # exactly one exception and the byte after the insn still
                    # executes (no skip); debugged + DBG_CONTINUE, the kernel
                    # skips one extra byte past the insn, diverging from the
                    # not-debugged flow. v1 trade-off: swallow the exception
                    # (DBG_CONTINUE, the debuggee never observes it) and leave
                    # EIP untouched. Rewinding EIP by 1 to cancel the kernel
                    # skip would emulate the not-debugged flow, but the skip
                    # semantics vary across Windows versions and a wrong
                    # adjustment corrupts control flow far worse than the
                    # skip itself. Our own planted INT3 at breakpoint_va is
                    # handled earlier, so this path never shadows it.
                    status = 0x00010002  # DBG_CONTINUE
                elif ecode in (0x80000003, 0x4000001f, 0x406d1388):
                    # loader/system breakpoints and MS_VC_EXCEPTION thread names
                    if ecode == 0x4000001f:
                        patch_peb(h_process)
                        find_ntdll_hooks()
                        arm_hook(nqip)
                        arm_hook(nqsi)
                        if mode == "extract":
                            extract_at[0] = time.monotonic() + delay_s
                        if auto_oep:
                            auto_armed[0] = True
                    status = 0x00010002  # DBG_CONTINUE
                else:
                    status = 0x40010004 if ev.u.Exception.dwFirstChance else 0  # DBG_EXCEPTION_NOT_HANDLED
            elif code in (6, 2):  # LOAD_DLL / CREATE_THREAD
                # A packer resolves imports (LoadLibrary) only after finishing
                # decompression: try planting the OEP INT3 on each of these.
                if code == 6 and anti_on:
                    find_ntdll_hooks()
                plant_int3()
            elif code == 5:  # EXIT_PROCESS_DEBUG_EVENT
                if saw_unpack[0] and h_process and not hit:
                    # Exited without an OEP hit: decompression had started, so
                    # fall back to dumping whatever the image looked like.
                    try:
                        do_dump(True)
                        dump_imports_safe()
                        exit_late[0] = True
                        hit = True
                    except Exception:  # noqa: BLE001
                        pass
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, 0x00010002)
                break
        except Exception as exception:  # noqa: BLE001
            error = str(exception)
            k32.TerminateProcess(pi.hProcess, 1)
            break
        if not hit:
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
            if anti_on:
                # Re-arm each ntdll hook once its throttle window has passed
                # (debuggee runs meanwhile; a thread trapped by the freshly
                # written 0xCC is simply handled as the next hook hit).
                for h in (nqip, nqsi):
                    if h["va"] and not h["armed"]:
                        delay = h["rearm_at"] - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
                        arm_hook(h)
            if poll_until[0] is not None:
                while not planted[0] and time.monotonic() < poll_until[0]:
                    if plant_int3():
                        break
                    time.sleep(0.00002)
                poll_until[0] = None

    k32.TerminateProcess(pi.hProcess, 1)
    k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread); k32.CloseHandle(job)
    if error:
        fail(5, error)
    if not hit:
        fail(4, "process exited before OEP breakpoint")
    with open(out_path, "rb") as handle:
        size = len(handle.read())
    print(json.dumps({"ok": True, "imageBase": image_base, "oepRva": oep_rva, "size": size, "late": exit_late[0],
                      "antiAntiDebug": anti_report()}), flush=True)

if __name__ == "__main__":
    main()
