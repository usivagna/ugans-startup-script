@echo off
REM ============================================================================
REM Windows 11 Developer PC Setup Launcher
REM ============================================================================
REM
REM This batch file launches the PowerShell setup script with the proper
REM execution policy to bypass script signing requirements.
REM
REM IMPORTANT: Right-click this file and select "Run as administrator"
REM
REM Optional: To create a system restore point before running, edit line 37
REM and uncomment the -CreateRestorePoint parameter.
REM ============================================================================

echo.
echo ============================================
echo Windows 11 Developer PC Setup Launcher
echo ============================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Administrator privileges required!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Running with administrator privileges...
echo.

REM Run PowerShell script with execution policy bypass
REM
REM To enable system restore point creation, uncomment one of these lines:
REM powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0setup-windows.ps1" -CreateRestorePoint
REM
REM Default (no restore point):
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0setup-windows.ps1"

echo.
echo ============================================
echo Launcher finished
echo ============================================
echo.
pause
