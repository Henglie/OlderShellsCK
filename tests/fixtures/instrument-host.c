// Original benign x86 host. No CRT, network, persistence, or user-file writes.
// Faults are deliberate UD2s handled by VEH; NtContinue restores a legal context.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

C_ASSERT(sizeof(FLOATING_SAVE_AREA) == 112);
C_ASSERT(sizeof(CONTEXT) == 716);
C_ASSERT(FIELD_OFFSET(CONTEXT, Eip) == 0xb8);
C_ASSERT(FIELD_OFFSET(CONTEXT, EFlags) == 0xc0);
C_ASSERT(FIELD_OFFSET(CONTEXT, Esp) == 0xc4);
C_ASSERT(FIELD_OFFSET(CONTEXT, ExtendedRegisters) == 0xcc);

__declspec(dllexport) volatile DWORD phase = 0;
__declspec(dllexport) volatile DWORD sehCount = 0;
__declspec(dllexport) volatile DWORD continueCount = 0;
__declspec(dllexport) volatile DWORD childPid = 0;
__declspec(dllexport) const unsigned char benignPadding[32768] = "Original benign instrumentation golden fixture; padding for UPX compression.";
static CONTEXT nextContext;
static WCHAR path[MAX_PATH], command[MAX_PATH + 32];
static STARTUPINFOW startup;
static PROCESS_INFORMATION child;

static int contains(const WCHAR *text, const WCHAR *token) {
    DWORD i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; token[j] && text[i + j] == token[j]; ++j) {}
        if (!token[j]) return 1;
    }
    return 0;
}

__declspec(dllexport) __declspec(naked) void faultSite(void) {
    __asm {
        _emit 0x0f
        _emit 0x0b
        ret
    }
}

static LONG CALLBACK handler(EXCEPTION_POINTERS *p) {
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
        p->ContextRecord->Eip == (DWORD)faultSite) {
        ++sehCount;
        p->ContextRecord->Eip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(dllexport) __declspec(noreturn) void landing(void) {
    ++continueCount;
    phase = 3;
    for (;;) Sleep(50);
}

static void spawnChild(void) {
    DWORD i = 0, j = 0;
    const WCHAR *suffix = L"\" --child";
    GetModuleFileNameW(0, path, MAX_PATH);
    command[i++] = L'"';
    while (path[j] && i < MAX_PATH) command[i++] = path[j++];
    j = 0;
    while (suffix[j]) command[i++] = suffix[j++];
    command[i] = 0;
    startup.cb = sizeof(startup);
    if (CreateProcessW(path, command, 0, 0, FALSE, 0, 0, 0, &startup, &child)) {
        childPid = child.dwProcessId;
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
    }
}

// /ENTRY:start /NODEFAULTLIB; no reliance on a compiler-generated main/CRT startup.
__declspec(dllexport) __declspec(noreturn) void start(void) {
    typedef LONG (NTAPI *CONTINUE_FN)(CONTEXT *, BOOLEAN);
    CONTINUE_FN ntContinue;
    const WCHAR *args = GetCommandLineW();
    if (contains(args, L"--child")) for (;;) Sleep(50);
    if (contains(args, L"--tree")) spawnChild();
    phase = 1;
    if (contains(args, L"--exit")) {
        Sleep(350);
        phase = 4;
        ExitProcess(0);
    }
    if (contains(args, L"--quiet")) {
        phase = 2;
        for (;;) Sleep(50);
    }
    if (contains(args, L"--debug-events")) for (;;) OutputDebugStringW(L"benign instrument event limit");
    if (!contains(args, L"--unhandled")) AddVectoredExceptionHandler(1, handler);
    faultSite(); faultSite(); faultSite();
    phase = 2;
    ntContinue = (CONTINUE_FN)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtContinue");
    RtlCaptureContext(&nextContext);
    nextContext.ContextFlags = CONTEXT_FULL;
    nextContext.Eip = (DWORD)landing;
    ntContinue(&nextContext, FALSE);
    ExitProcess(9); // success must never return from NtContinue
}
