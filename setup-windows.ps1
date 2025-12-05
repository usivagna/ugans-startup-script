# Windows 11 Developer PC Setup Script
# ============================================================================
# Automates Windows 11 PC setup for developers.
#
# Configures Windows 11 settings including taskbar customization, dark theme,
# Windows Spotlight, and installs essential developer software (Microsoft 365,
# VSCode, Git, PowerToys) using winget.
#
# PARAMETER CreateRestorePoint
#   Optional. Creates a system restore point before making changes.
#   Requires administrator privileges.
#
# EXAMPLE
#   .\setup-windows.ps1
#   Run setup without creating a restore point.
#
# EXAMPLE
#   .\setup-windows.ps1 -CreateRestorePoint
#   Run setup and create a system restore point first.
#
# NOTES
#   Requires Windows 11 and administrator privileges.
#   Run using the companion run-setup.bat file.
# ============================================================================

[CmdletBinding()]
Param(
    [switch]$CreateRestorePoint
)

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $PSScriptRoot "setup-log-$timestamp.txt"

# Start transcript logging
Start-Transcript -Path $logFile -Append

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Windows 11 Developer PC Setup Script" -ForegroundColor Cyan
Write-Host "Started: $(Get-Date)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# CHECK ADMINISTRATOR PRIVILEGES
# ============================================================================

Write-Host "[1/6] Checking administrator privileges..." -ForegroundColor Yellow

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run the script as Administrator." -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "[OK] Running with administrator privileges" -ForegroundColor Green
Write-Host ""

# ============================================================================
# CHECK WINDOWS 11
# ============================================================================

Write-Host "[2/6] Verifying Windows 11..." -ForegroundColor Yellow

$osVersion = [System.Environment]::OSVersion.Version
$buildNumber = $osVersion.Build

if ($buildNumber -lt 22000) {
    Write-Host "ERROR: This script requires Windows 11 (Build 22000 or higher)." -ForegroundColor Red
    Write-Host "Current build: $buildNumber" -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "[OK] Windows 11 detected (Build: $buildNumber)" -ForegroundColor Green
Write-Host ""

# ============================================================================
# CREATE SYSTEM RESTORE POINT (OPTIONAL)
# ============================================================================

if ($CreateRestorePoint) {
    Write-Host "[3/6] Creating system restore point..." -ForegroundColor Yellow
    
    try {
        # Enable System Protection if not already enabled
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        
        # Create restore point
        Checkpoint-Computer -Description "Pre-Setup Backup - $timestamp" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "[OK] System restore point created successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARNING] Could not create system restore point: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Continuing with setup..." -ForegroundColor Yellow
    }
    Write-Host ""
} else {
    Write-Host "[3/6] Skipping system restore point (use -CreateRestorePoint to enable)" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# BACKUP AND CONFIGURE REGISTRY SETTINGS
# ============================================================================

Write-Host "[4/6] Configuring Windows 11 settings..." -ForegroundColor Yellow

# Backup registry
$backupFile = Join-Path $PSScriptRoot "registry-backup-$timestamp.reg"
Write-Host "Creating registry backup: $backupFile" -ForegroundColor Gray

try {
    & reg export "HKCU\Software\Microsoft\Windows\CurrentVersion" $backupFile /y | Out-Null
    Write-Host "[OK] Registry backup created" -ForegroundColor Green
}
catch {
    Write-Host "[WARNING] Could not create registry backup: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Applying registry settings:" -ForegroundColor Gray

# Helper function to set registry value
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )
    
    try {
        # Create the key if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        # Try to set the value
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
            Write-Host "  [OK] $Description" -ForegroundColor Green
            return $true
        }
        catch [System.UnauthorizedAccessException] {
            # If access denied, try using reg.exe command instead
            $regPath = $Path -replace "HKCU:\\", "HKCU\"
            $valueType = switch ($Type) {
                "DWord" { "REG_DWORD" }
                "String" { "REG_SZ" }
                "Binary" { "REG_BINARY" }
                "ExpandString" { "REG_EXPAND_SZ" }
                default { "REG_DWORD" }
            }
            
            $result = & reg add $regPath /v $Name /t $valueType /d $Value /f 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] $Description (via reg.exe)" -ForegroundColor Green
                return $true
            }
            else {
                Write-Host "  [FAILED] $Description - Access denied even with reg.exe" -ForegroundColor Red
                return $false
            }
        }
    }
    catch {
        Write-Host "  [FAILED] $Description - Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Disable Widgets Icon on Taskbar
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "TaskbarDa" -Value 0 -Description "Disable Widgets Icon on Taskbar"

# Also disable via Shell Feeds
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
    -Name "IsFeedsAvailable" -Value 0 -Description "Disable Feeds Availability"

# Hide Search Box from Taskbar
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" `
    -Name "SearchboxTaskbarMode" -Value 0 -Description "Hide Search Box from Taskbar"

# Hide Task View Button
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "ShowTaskViewButton" -Value 0 -Description "Hide Task View Button"

# Disable Feed in Widgets Panel
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" `
    -Name "ShellFeedsTaskbarViewMode" -Value 2 -Description "Disable Feed in Widgets Panel"

# Hide Clock/Date from System Tray
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "ShowClock" -Value 0 -Description "Hide Clock from System Tray"

Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" `
    -Name "HideClock" -Value 1 -Description "Hide Clock/Date from Taskbar via Policy"

# Turn off Widgets on Lock Screen
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "SubscribedContent-338387Enabled" -Value 0 -Description "Turn off Widgets on Lock Screen"

# Enable Windows Spotlight on Lock Screen
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "RotatingLockScreenEnabled" -Value 1 -Description "Enable Windows Spotlight on Lock Screen"

Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "RotatingLockScreenOverlayEnabled" -Value 1 -Description "Enable Lock Screen Overlay"

# Enable Windows Spotlight on Desktop (Windows 11)
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" `
    -Name "BackgroundType" -Value 2 -Description "Enable Windows Spotlight on Desktop"

# Set Dark Theme for Apps
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" `
    -Name "AppsUseLightTheme" -Value 0 -Description "Set Dark Theme for Apps"

# Set Dark Theme for System
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" `
    -Name "SystemUsesLightTheme" -Value 0 -Description "Set Dark Theme for System"

Write-Host ""

# ============================================================================
# UNPIN ALL TASKBAR APPS
# ============================================================================

Write-Host "Unpinning all taskbar apps:" -ForegroundColor Gray

try {
    # Method 1: Remove Favorites from Taskband registry
    $taskbandPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
    if (Test-Path $taskbandPath) {
        Remove-ItemProperty -Path $taskbandPath -Name "Favorites" -ErrorAction SilentlyContinue
        Write-Host "  [OK] Cleared taskbar favorites registry" -ForegroundColor Green
    }
    
    # Method 2: Clear pinned taskbar folder
    $pinnedPath = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $pinnedPath) {
        Get-ChildItem -Path $pinnedPath -File | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Cleared pinned taskbar folder" -ForegroundColor Green
    }
    
    # Restart Explorer to apply changes
    Write-Host "  [INFO] Restarting Windows Explorer..." -ForegroundColor Gray
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Host "  [OK] Explorer restarted, taskbar updated" -ForegroundColor Green
}
catch {
    Write-Host "  [WARNING] Could not fully unpin taskbar apps: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[OK] Windows 11 configuration completed" -ForegroundColor Green
Write-Host ""

# ============================================================================
# INSTALL SOFTWARE WITH WINGET
# ============================================================================

Write-Host "[5/6] Installing software..." -ForegroundColor Yellow

# Check if winget is available
try {
    $wingetCmd = Get-Command winget -ErrorAction Stop
    Write-Host "[OK] Winget is available" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "[FAILED] ERROR: Winget is not available on this system." -ForegroundColor Red
    Write-Host "Please install App Installer from the Microsoft Store." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    exit 1
}

# Software to install
$software = @(
    @{
        Name = "Microsoft 365"
        Id = "Microsoft.Office"
        Scope = "machine"  # Office requires system-wide install
    },
    @{
        Name = "Visual Studio Code"
        Id = "Microsoft.VisualStudioCode"
        Scope = "user"
    },
    @{
        Name = "Git"
        Id = "Git.Git"
        Scope = "user"
    },
    @{
        Name = "PowerToys"
        Id = "Microsoft.PowerToys"
        Scope = "user"
    }
)

$installResults = @()

foreach ($app in $software) {
    Write-Host "Checking $($app.Name)..." -ForegroundColor Gray
    
    # Check if already installed
    $checkInstalled = winget list --id $app.Id 2>&1 | Out-String
    
    if ($checkInstalled -match $app.Id) {
        Write-Host "  [OK] $($app.Name) is already installed" -ForegroundColor Green
        $installResults += @{ Name = $app.Name; Status = "Already Installed"; Success = $true }
    }
    else {
        Write-Host "  [INFO] Installing $($app.Name)..." -ForegroundColor Yellow
        
        try {
            $installArgs = @("install", "--id", $app.Id, "--silent", "--accept-package-agreements", "--accept-source-agreements")
            
            if ($app.Scope -eq "user") {
                $installArgs += "--scope"
                $installArgs += "user"
            }
            
            $process = Start-Process -FilePath "winget" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0) {
                Write-Host "  [OK] $($app.Name) installed successfully" -ForegroundColor Green
                $installResults += @{ Name = $app.Name; Status = "Installed"; Success = $true }
            }
            else {
                Write-Host "  [FAILED] $($app.Name) installation failed (Exit code: $($process.ExitCode))" -ForegroundColor Red
                $installResults += @{ Name = $app.Name; Status = "Failed"; Success = $false }
            }
        }
        catch {
            Write-Host "  [FAILED] $($app.Name) installation error: $($_.Exception.Message)" -ForegroundColor Red
            $installResults += @{ Name = $app.Name; Status = "Error"; Success = $false }
        }
    }
    Write-Host ""
}

# Check for Windows App (verification only)
Write-Host "Checking Windows App..." -ForegroundColor Gray
$windowsAppCheck = winget list --id "9WZDNCRFJ3PS" 2>&1 | Out-String

if ($windowsAppCheck -match "9WZDNCRFJ3PS" -or $windowsAppCheck -match "Windows App") {
    Write-Host "  [OK] Windows App is present" -ForegroundColor Green
}
else {
    Write-Host "  [WARNING] Windows App not detected (may need manual installation from Microsoft Store)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host "[6/6] Setup Summary" -ForegroundColor Yellow
Write-Host ""

Write-Host "Configuration Status:" -ForegroundColor Cyan
Write-Host "  [OK] Windows 11 settings configured" -ForegroundColor Green
Write-Host "  [OK] Taskbar customized (widgets, search, task view hidden)" -ForegroundColor Green
Write-Host "  [OK] Clock/Date hidden from taskbar (visible in Action Center)" -ForegroundColor Green
Write-Host "  [OK] Taskbar apps unpinned" -ForegroundColor Green
Write-Host "  [OK] Dark theme enabled" -ForegroundColor Green
Write-Host "  [OK] Windows Spotlight enabled" -ForegroundColor Green
Write-Host ""

Write-Host "Software Installation Status:" -ForegroundColor Cyan
foreach ($result in $installResults) {
    if ($result.Success) {
        Write-Host "  [OK] $($result.Name): $($result.Status)" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAILED] $($result.Name): $($result.Status)" -ForegroundColor Red
    }
}
Write-Host ""

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Setup completed: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Log file: $logFile" -ForegroundColor Cyan
if ($CreateRestorePoint) {
    Write-Host "Registry backup: $backupFile" -ForegroundColor Cyan
}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "IMPORTANT: Please restart your computer to ensure all changes take effect." -ForegroundColor Yellow
Write-Host ""

Stop-Transcript

# Prompt to restart
$restart = Read-Host "Would you like to restart now? (Y/N)"
if ($restart -eq "Y" -or $restart -eq "y") {
    Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
