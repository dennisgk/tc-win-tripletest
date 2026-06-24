@echo off
REM Build tripletest.exe with MinGW-w64 (g++)
REM Requires g++.exe on PATH (e.g. from MSYS2: pacman -S mingw-w64-x86_64-toolchain)

g++ -std=c++17 -O2 -o tripletest.exe main.cpp ^
    -lkernel32 -lpsapi -municode

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build OK: tripletest.exe
) else (
    echo Build FAILED
    exit /b 1
)
