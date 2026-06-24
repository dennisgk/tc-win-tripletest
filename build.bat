@echo off
REM Build tripletest.exe with MSVC
REM IMPORTANT: run from "x64 Native Tools Command Prompt for VS 20xx"
REM (not the plain Developer Command Prompt - the CONTEXT struct is x64-only)

cl.exe /EHsc /W3 /O2 /nologo /D_CRT_SECURE_NO_WARNINGS main.cpp ^
    /Fe:tripletest.exe ^
    /link kernel32.lib user32.lib psapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build OK: tripletest.exe
) else (
    echo Build FAILED
    exit /b 1
)
