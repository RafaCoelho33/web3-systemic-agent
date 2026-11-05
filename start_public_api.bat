@echo off
setlocal enabledelayedexpansion

echo ==================================================================
echo  Web3 Condition-Action Trigger Agent - Public API Launcher
echo ==================================================================
echo.

set "CLOUDFLARED_BIN="

rem 1. Check if cloudflared is in PATH
where cloudflared >nul 2>&1
if !errorlevel! equ 0 (
    set "CLOUDFLARED_BIN=cloudflared"
) else (
    rem 2. Check standard installation directories
    if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" (
        set "CLOUDFLARED_BIN=C:\Program Files (x86)\cloudflared\cloudflared.exe"
    ) else if exist "C:\Program Files\cloudflared\cloudflared.exe" (
        set "CLOUDFLARED_BIN=C:\Program Files\cloudflared\cloudflared.exe"
    ) else if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe" (
        set "CLOUDFLARED_BIN=%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe"
    )
)

rem 3. If not found, attempt automated installation via WinGet
if "!CLOUDFLARED_BIN!"=="" (
    echo [!] cloudflared was not found in PATH or standard install paths.
    echo [*] Attempting automated installation via winget...
    winget install --id Cloudflare.cloudflared --accept-source-agreements --accept-package-agreements
    
    where cloudflared >nul 2>&1
    if !errorlevel! equ 0 (
        set "CLOUDFLARED_BIN=cloudflared"
    ) else if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" (
        set "CLOUDFLARED_BIN=C:\Program Files (x86)\cloudflared\cloudflared.exe"
    ) else if exist "C:\Program Files\cloudflared\cloudflared.exe" (
        set "CLOUDFLARED_BIN=C:\Program Files\cloudflared\cloudflared.exe"
    ) else if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe" (
        set "CLOUDFLARED_BIN=%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe"
    )
)

if "!CLOUDFLARED_BIN!"=="" (
    echo [ERROR] cloudflared could not be found or installed.
    echo Please install cloudflared manually: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
    pause
    exit /b 1
)

echo [*] Using Cloudflare executable: "!CLOUDFLARED_BIN!"
set "PUBLIC_EVALUATE_ONLY=true"
echo [*] Launching FastAPI uvicorn server in a new window...
start "Web3 Trigger Agent API" cmd /k "set PUBLIC_EVALUATE_ONLY=true && python -m uvicorn api:app --host 0.0.0.0 --port 8000"

echo [*] Waiting 3 seconds for server initialization...
timeout /t 3 /nobreak >nul

echo.
echo ==================================================================
echo  Starting Cloudflare Public Tunnel for http://localhost:8000
echo  Look for your public https://*.trycloudflare.com URL below:
echo ==================================================================
echo.

"!CLOUDFLARED_BIN!" tunnel --url http://localhost:8000
