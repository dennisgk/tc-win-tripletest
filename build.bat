@echo off
REM Build tripletest.exe with MSVC
REM Run from a "Developer Command Prompt for VS 20xx" window.

cl.exe /EHsc /W3 /O2 /nologo main.cpp ^
    /Fe:tripletest.exe ^
    /link kernel32.lib user32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build OK: tripletest.exe
) else (
    echo Build FAILED
    exit /b 1
)
