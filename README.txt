tc-win-tripletest
=================
Captures KernelCallbackTable dispatches and module loads from a Windows
process.  The data is used to implement a KiUserCallbackDispatcher trampoline
in tc-winrun-nc so that win32k-triggered callbacks run with correct inputs and
generate their organic syscall sequences.

What it records
---------------
* Every call to ntdll!KiUserCallbackDispatcher:
    - ApiNumber (index into PEB.KernelCallbackTable)
    - InputBuffer contents (what win32k passes to the callback)
    - Full register snapshot + stack dump at entry
* Every call to ntdll!ZwCallbackReturn (= NtCallbackReturn):
    - Status code
    - OutputBuffer contents (what the callback returned)
* All DLL loads (module name + base address)
* Thread creation events
* Process exit code

Build
-----
Option A — MSVC (from a Developer Command Prompt):
    build.bat

Option B — MinGW-w64 / MSYS2:
    build_mingw.bat

Usage
-----
    tripletest.exe [--out output.bin] C:\Users\Dennis\Desktop\EasyGUI.exe

The tracer launches EasyGUI.exe in a console window.
Wait for the EasyGUI window to appear and be fully drawn, then close it
(or just close the application).  The trace stops when the process exits.

The output file (tripletest_output.bin) is written incrementally, so it is
safe even if the process is killed.

Translate
---------
On Linux (or Windows with Python 3):
    python translator.py tripletest_output.bin              # summary only
    python translator.py tripletest_output.bin trace.json   # + JSON
    python translator.py tripletest_output.bin trace.h5     # + H5 (needs h5py)

Transfer the .bin (or .json / .h5) back and hand it to Claude.

Notes
-----
* The tracer hooks ntdll directly with INT3 breakpoints; no separate DLL is
  injected.  Windows Defender may flag the debug API usage — add an exclusion
  for the tripletest.exe folder if that happens.
* Both MSVC and MinGW builds produce a 64-bit executable.  Make sure you
  build and run a 64-bit binary when tracing 64-bit processes.
* If EasyGUI.exe crashes inside the tracer, the trace file still contains
  everything captured up to that point.
