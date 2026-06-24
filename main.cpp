/*
 * tc-win-tripletest / main.cpp
 *
 * Captures kernel callback table dispatches and module loads from a child
 * process.  The collected data lets tc-winrun-nc implement a
 * KiUserCallbackDispatcher trampoline so that win32k-triggered callbacks
 * run organically and generate the matching syscall sequence.
 *
 * Build (MSVC, from a Developer Command Prompt):
 *   cl.exe /EHsc /W3 /O2 main.cpp /Fe:tripletest.exe \
 *     /link kernel32.lib user32.lib psapi.lib
 *
 * Build (MinGW / MSYS2):
 *   g++ -std=c++17 -O2 -o tripletest.exe main.cpp \
 *     -lkernel32 -lpsapi -municode
 *
 * Usage:
 *   tripletest.exe [--out file.bin] [--timeout seconds] <exe> [args...]
 *
 * Output: binary trace file (default: tripletest_output.bin)
 * Analyse: python translator.py tripletest_output.bin [out.json]
 *
 * -------------------------------------------------------------------------
 * Binary file format
 * -------------------------------------------------------------------------
 * Header: magic[4]="TWTB" | version[4]=1 | qpc_freq[8]
 *
 * Each record: type[1] | payload_size[4] | qpc[8] | payload[payload_size]
 *
 * Type 0x01  MODULE_LOAD
 *   base[8] | img_size[8] | name_len[4] | name_utf8[name_len]
 *
 * Type 0x02  CALLBACK_IN   (KiUserCallbackDispatcher entry)
 *   seq[8] | api[4]
 *   | input_len[4] | input[input_len]     <- InputBuffer (RDX[0..R8] bytes)
 *   | rip[8] | rsp[8] | rcx[8] | rdx[8] | r8[8]
 *   | stack_len[4] | stack[stack_len]     <- RSP[-16..+144] raw bytes
 *
 * Type 0x03  CALLBACK_OUT  (ZwCallbackReturn / NtCallbackReturn entry)
 *   seq[8] | status[4] | output_len[4] | output[output_len]
 *
 * Type 0x04  THREAD_EVENT
 *   tid[4] | start_addr[8]
 *
 * Type 0x05  PROCESS_EXIT
 *   exit_code[4]
 * -------------------------------------------------------------------------
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <stack>

/* ---------- record type constants ---------- */
#define REC_MODULE_LOAD   0x01
#define REC_CALLBACK_IN   0x02
#define REC_CALLBACK_OUT  0x03
#define REC_THREAD_EVENT  0x04
#define REC_PROCESS_EXIT  0x05

/* ---------- globals ---------- */
static FILE    *g_out  = NULL;
static uint64_t g_seq  = 0;
static HANDLE   g_proc = NULL;

/* ---------- binary write helpers ---------- */
static void wb(const void *p, size_t n) { fwrite(p, 1, n, g_out); }
static void wu8 (uint8_t  v) { wb(&v, 1); }
static void wu32(uint32_t v) { wb(&v, 4); }
static void wu64(uint64_t v) { wb(&v, 8); }

static void begin_rec(uint8_t type, uint32_t size) {
    LARGE_INTEGER li; QueryPerformanceCounter(&li);
    wu8(type); wu32(size); wu64((uint64_t)li.QuadPart);
}

/* ---------- safe remote-memory read ---------- */
static std::vector<uint8_t> rmem(uintptr_t addr, size_t size) {
    if (!addr || !size || size > 256u * 1024u) return {};
    std::vector<uint8_t> buf(size);
    SIZE_T got = 0;
    ReadProcessMemory(g_proc, (LPCVOID)addr, buf.data(), size, &got);
    buf.resize(got);
    return buf;
}

/* ---------- INT3 hook plumbing ---------- */
struct HookSite {
    uintptr_t addr   = 0;
    uint8_t   saved  = 0;    /* original byte */
    bool      armed  = false;
};

static HookSite g_hook_kucb;   /* KiUserCallbackDispatcher */
static HookSite g_hook_ncr;    /* ZwCallbackReturn          */

static bool arm_hook(HookSite &h) {
    uint8_t brk = 0xCC;
    SIZE_T n;
    if (!ReadProcessMemory(g_proc, (LPCVOID)h.addr, &h.saved, 1, &n)) return false;
    if (!WriteProcessMemory(g_proc, (LPVOID)h.addr, &brk, 1, &n))     return false;
    FlushInstructionCache(g_proc, (LPCVOID)h.addr, 1);
    h.armed = true;
    return true;
}
static void disarm_hook(HookSite &h) {
    SIZE_T n;
    WriteProcessMemory(g_proc, (LPVOID)h.addr, &h.saved, 1, &n);
    FlushInstructionCache(g_proc, (LPCVOID)h.addr, 1);
    h.armed = false;
}
static void rearm_hook(HookSite &h) {
    uint8_t brk = 0xCC;
    SIZE_T n;
    WriteProcessMemory(g_proc, (LPVOID)h.addr, &brk, 1, &n);
    FlushInstructionCache(g_proc, (LPCVOID)h.addr, 1);
    h.armed = true;
}

/* thread-id -> which hook site is pending a single-step re-arm */
static std::map<DWORD, HookSite*> g_stepping;

/* stack to pair CALLBACK_IN with CALLBACK_OUT; tracks seq numbers */
static std::stack<uint64_t> g_cb_stack;

/* ---------- event handlers ---------- */
static void on_callback_in(const CONTEXT &ctx) {
    /*
     * KiUserCallbackDispatcher on Windows 10/11 x64 (verified by disassembly):
     *
     *   The kernel sets up a KCALLOUT_FRAME on the user-mode stack at RSP,
     *   then jumps here.  The first three instructions of the function read
     *   the frame fields:
     *
     *     mov rcx,  [rsp+0x20]   ; InputBuffer pointer
     *     mov edx,  [rsp+0x28]   ; InputBufferLength (ULONG)
     *     mov r8d,  [rsp+0x2c]   ; ApiNumber         (ULONG)
     *
     *   Registers at entry (RCX/RDX/R8) are whatever the kernel left there
     *   and are NOT the parameters — read directly from [RSP+offset].
     */
    uintptr_t rsp = (uintptr_t)ctx.Rsp;

    uint64_t input_ptr = 0;
    uint32_t input_len = 0;
    uint32_t api       = 0;
    SIZE_T   nr;
    ReadProcessMemory(g_proc, (LPCVOID)(rsp + 0x20), &input_ptr, 8, &nr);
    ReadProcessMemory(g_proc, (LPCVOID)(rsp + 0x28), &input_len, 4, &nr);
    ReadProcessMemory(g_proc, (LPCVOID)(rsp + 0x2C), &api,       4, &nr);

    auto input_data = rmem(input_ptr, input_len);

    /* Full KCALLOUT_FRAME dump: 256 bytes at RSP */
    auto frame_dump = rmem(rsp, 256);

    uint64_t seq = ++g_seq;
    g_cb_stack.push(seq);

    uint32_t payload =
        8/*seq*/ + 4/*api*/ +
        4/*input_len*/ + (uint32_t)input_data.size() +
        8/*rip*/ + 8/*rsp*/ + 8/*input_ptr*/ +
        4/*frame_len*/ + (uint32_t)frame_dump.size();

    begin_rec(REC_CALLBACK_IN, payload);
    wu64(seq);
    wu32(api);
    wu32((uint32_t)input_data.size());
    if (!input_data.empty()) wb(input_data.data(), input_data.size());
    wu64(ctx.Rip); wu64(rsp); wu64(input_ptr);
    wu32((uint32_t)frame_dump.size());
    if (!frame_dump.empty()) wb(frame_dump.data(), frame_dump.size());
    fflush(g_out);

    wprintf(L"  CALLBACK_IN  seq=%-4llu api=%-4u inlen=%-5u inptr=0x%llx\n",
            (unsigned long long)seq, api, input_len,
            (unsigned long long)input_ptr);
}

static void on_callback_out(const CONTEXT &ctx) {
    /*
     * ZwCallbackReturn(OutputBuffer, OutputBufferLength, Status)
     *   RCX = OutputBuffer pointer (may be NULL)
     *   RDX = OutputBufferLength
     *   R8  = NTSTATUS
     */
    uintptr_t outptr = (uintptr_t)ctx.Rcx;
    uint32_t  outlen = (uint32_t)ctx.Rdx;
    uint32_t  status = (uint32_t)ctx.R8;

    auto output_data = rmem(outptr, outlen);

    uint64_t seq = g_cb_stack.empty() ? 0 : g_cb_stack.top();
    if (!g_cb_stack.empty()) g_cb_stack.pop();

    uint32_t payload = 8/*seq*/ + 4/*status*/ + 4/*outlen*/ + (uint32_t)output_data.size();
    begin_rec(REC_CALLBACK_OUT, payload);
    wu64(seq);
    wu32(status);
    wu32((uint32_t)output_data.size());
    if (!output_data.empty()) wb(output_data.data(), output_data.size());
    fflush(g_out);

    wprintf(L"  CALLBACK_OUT seq=%-4llu status=0x%08X outlen=%-5u\n",
            (unsigned long long)seq, status, (uint32_t)output_data.size());
}

static void log_module_load(void *base_ptr, HANDLE hFile) {
    wchar_t path[MAX_PATH] = {};
    if (hFile && hFile != INVALID_HANDLE_VALUE)
        GetFinalPathNameByHandleW(hFile, path, MAX_PATH, VOLUME_NAME_DOS);
    if (!path[0])
        GetMappedFileNameW(g_proc, base_ptr, path, MAX_PATH);

    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQueryEx(g_proc, base_ptr, &mbi, sizeof(mbi));

    char utf8[1024] = {};
    WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8) - 1, NULL, NULL);
    uint32_t nlen = (uint32_t)strlen(utf8);

    begin_rec(REC_MODULE_LOAD, 8 + 8 + 4 + nlen);
    wu64((uint64_t)(uintptr_t)base_ptr);
    wu64(mbi.RegionSize);
    wu32(nlen);
    wb(utf8, nlen);
    fflush(g_out);

    /* find last backslash for display */
    const char *leaf = utf8;
    for (const char *p = utf8; *p; p++) if (*p == '\\' || *p == '/') leaf = p + 1;
    wprintf(L"  MODULE_LOAD  %hs @ 0x%llx\n", leaf, (unsigned long long)(uintptr_t)base_ptr);
}

/* ---------- main ---------- */
int wmain(int argc, wchar_t **argv) {
    const wchar_t *out_file     = L"tripletest_output.bin";
    int            exe_start    = 1;

    for (int i = 1; i < argc; ) {
        if (wcscmp(argv[i], L"--out") == 0 && i + 1 < argc) {
            out_file = argv[i + 1]; i += 2; exe_start = i;
        } else {
            exe_start = i; break;
        }
    }

    if (exe_start >= argc) {
        fwprintf(stderr,
            L"Usage: tripletest.exe [--out file.bin] <exe> [args...]\n"
            L"\n"
            L"Traces KernelCallbackTable dispatches inside <exe> and writes\n"
            L"a binary trace file.  Close the target application when it has\n"
            L"fully initialised its main window to stop the capture.\n"
            L"Convert the output with: python translator.py tripletest_output.bin\n");
        return 1;
    }

    /* Build command line string */
    std::wstring cmdline;
    for (int i = exe_start; i < argc; i++) {
        if (i > exe_start) cmdline += L' ';
        cmdline += L'"'; cmdline += argv[i]; cmdline += L'"';
    }

    g_out = _wfopen(out_file, L"wb");
    if (!g_out) {
        fwprintf(stderr, L"Cannot open output file: %s\n", out_file);
        return 1;
    }

    /* Write file header */
    static const char magic[] = {'T','W','T','B'};
    wb(magic, 4);
    wu32(1); /* version */
    LARGE_INTEGER freq; QueryPerformanceFrequency(&freq);
    wu64((uint64_t)freq.QuadPart);
    fflush(g_out);

    /*
     * Resolve hook addresses from OUR ntdll.  On Windows 10/11 ntdll is
     * mapped via a shared physical section; ASLR slides it once per boot
     * and the slide is identical in every process, so our addresses are
     * valid for the child as well.
     */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) { fwprintf(stderr, L"ntdll not loaded\n"); return 1; }

    g_hook_kucb.addr = (uintptr_t)GetProcAddress(hNtdll, "KiUserCallbackDispatcher");
    g_hook_ncr.addr  = (uintptr_t)GetProcAddress(hNtdll, "ZwCallbackReturn");
    if (!g_hook_ncr.addr)
        g_hook_ncr.addr = (uintptr_t)GetProcAddress(hNtdll, "NtCallbackReturn");

    if (!g_hook_kucb.addr || !g_hook_ncr.addr) {
        fwprintf(stderr, L"Cannot resolve ntdll symbols\n");
        fclose(g_out); return 1;
    }

    wprintf(L"KiUserCallbackDispatcher: 0x%llx\n", (unsigned long long)g_hook_kucb.addr);
    wprintf(L"ZwCallbackReturn:         0x%llx\n", (unsigned long long)g_hook_ncr.addr);

    /* Launch target process under our debugger */
    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = cmdline;   /* CreateProcessW needs writable buffer */

    if (!CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE,
                        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"CreateProcess failed: %lu\n", GetLastError());
        fclose(g_out); return 1;
    }

    g_proc = pi.hProcess;
    /* Don't kill the tracee if we exit first */
    DebugSetProcessKillOnExit(FALSE);

    wprintf(L"Tracing PID %lu — close the application window when it is ready.\n\n",
            pi.dwProcessId);

    /* ---- debug loop ---- */
    DEBUG_EVENT ev = {};
    bool done = false;

    while (!done && WaitForDebugEvent(&ev, INFINITE)) {
        DWORD cont = DBG_CONTINUE;

        switch (ev.dwDebugEventCode) {

        /* ---- process created: arm hooks ---- */
        case CREATE_PROCESS_DEBUG_EVENT:
            CloseHandle(ev.u.CreateProcessInfo.hFile);
            if (arm_hook(g_hook_kucb))
                wprintf(L"Hooked KiUserCallbackDispatcher\n");
            else
                wprintf(L"WARNING: failed to hook KiUserCallbackDispatcher\n");
            if (arm_hook(g_hook_ncr))
                wprintf(L"Hooked ZwCallbackReturn\n");
            else
                wprintf(L"WARNING: failed to hook ZwCallbackReturn\n");
            wprintf(L"\n");
            break;

        /* ---- DLL loaded ---- */
        case LOAD_DLL_DEBUG_EVENT:
            log_module_load(ev.u.LoadDll.lpBaseOfDll, ev.u.LoadDll.hFile);
            if (ev.u.LoadDll.hFile)
                CloseHandle(ev.u.LoadDll.hFile);
            break;

        /* ---- new thread ---- */
        case CREATE_THREAD_DEBUG_EVENT:
            begin_rec(REC_THREAD_EVENT, 4 + 8);
            wu32(ev.dwThreadId);
            wu64((uint64_t)(uintptr_t)ev.u.CreateThread.lpStartAddress);
            fflush(g_out);
            wprintf(L"  THREAD_EVENT tid=%-6u start=0x%llx\n",
                    ev.dwThreadId,
                    (unsigned long long)(uintptr_t)ev.u.CreateThread.lpStartAddress);
            break;

        /* ---- process exited ---- */
        case EXIT_PROCESS_DEBUG_EVENT:
            begin_rec(REC_PROCESS_EXIT, 4);
            wu32(ev.u.ExitProcess.dwExitCode);
            fflush(g_out);
            wprintf(L"\nPROCESS_EXIT code=%lu\n", ev.u.ExitProcess.dwExitCode);
            done = true;
            break;

        /* ---- exceptions: INT3 hooks + single-step re-arm ---- */
        case EXCEPTION_DEBUG_EVENT: {
            auto &ex = ev.u.Exception;
            uintptr_t ea = (uintptr_t)ex.ExceptionRecord.ExceptionAddress;

            HANDLE hThr = OpenThread(THREAD_ALL_ACCESS, FALSE, ev.dwThreadId);

            if (ex.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                HookSite *hit = nullptr;
                if      (ea == g_hook_kucb.addr && g_hook_kucb.armed) hit = &g_hook_kucb;
                else if (ea == g_hook_ncr.addr  && g_hook_ncr.armed)  hit = &g_hook_ncr;

                if (hit) {
                    CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThr, &ctx);

                    /* restore original byte and re-execute from the same address */
                    disarm_hook(*hit);
                    ctx.Rip = ea;
                    ctx.EFlags |= 0x100u;   /* Trap Flag: single-step to re-arm */
                    g_stepping[ev.dwThreadId] = hit;

                    /* log the event */
                    if (hit == &g_hook_kucb)  on_callback_in(ctx);
                    else                      on_callback_out(ctx);

                    SetThreadContext(hThr, &ctx);
                    cont = DBG_CONTINUE;
                } else {
                    /*
                     * Not our hook.  The initial system breakpoint (ntdll!DbgBreakPoint)
                     * fires as a first-chance EXCEPTION_BREAKPOINT before any user code
                     * runs.  We must answer DBG_CONTINUE or Windows escalates it to a
                     * second-chance exception and kills the process.  Any subsequent
                     * unrecognised first-chance breakpoint is similarly continued so we
                     * don't interfere with CRT/ntdll internal INT3s.
                     */
                    cont = DBG_CONTINUE;
                }
            }
            else if (ex.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                auto it = g_stepping.find(ev.dwThreadId);
                if (it != g_stepping.end() && it->second) {
                    rearm_hook(*it->second);
                    g_stepping.erase(it);
                    cont = DBG_CONTINUE;
                } else {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            else {
                cont = DBG_EXCEPTION_NOT_HANDLED;
                if (!ex.dwFirstChance)
                    wprintf(L"  FATAL EXCEPTION 0x%08X at 0x%llx\n",
                            ex.ExceptionRecord.ExceptionCode,
                            (unsigned long long)ea);
            }

            if (hThr) CloseHandle(hThr);
            break;
        }

        default:
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }

    fclose(g_out);
    wprintf(L"\nDone.  Trace written to: %s\n", out_file);
    wprintf(L"Translate with: python translator.py %s\n", out_file);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
