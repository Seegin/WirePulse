@echo off
setlocal
cd /d "%~dp0"

where cl >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [WirePulse Core] Compiling wirepulse_pcap.dll with MSVC cl.exe...
    cl /O2 /LD /W4 /D_CRT_SECURE_NO_WARNINGS capture_engine.c ws2_32.lib /Fe:wirepulse_pcap.dll
    goto :done
)

where gcc >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [WirePulse Core] Compiling wirepulse_pcap.dll with MinGW gcc...
    gcc -O3 -std=c11 -Wall -Wextra -shared capture_engine.c -o wirepulse_pcap.dll -lws2_32
    goto :done
)

echo [WirePulse Core] Neither MSVC (cl) nor MinGW (gcc) found in PATH.
echo Please open "x64 Native Tools Command Prompt for VS 2022" and run build.bat,
echo or WirePulse will seamlessly fall back to Python Npcap ctypes / dumpcap bridge.
exit /b 1

:done
echo [WirePulse Core] Build complete: %CD%\wirepulse_pcap.dll
