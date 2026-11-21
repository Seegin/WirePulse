@echo off
setlocal
cd /d "%~dp0"

echo [WirePulse] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10+ not found in PATH. Please install Python 3.
    pause
    exit /b 1
)

python -c "import aiohttp" >nul 2>&1
if errorlevel 1 (
    echo [WirePulse] Installing aiohttp...
    pip install -r requirements.txt
)

if not exist "core\wirepulse_pcap.dll" (
    echo [WirePulse] Attempting to compile C11 Npcap capture engine (optional)...
    call core\build.bat >nul 2>&1
)

echo [WirePulse] Starting WirePulse Network Sniffer & Security Analyzer...
python wirepulse.py %*
pause
