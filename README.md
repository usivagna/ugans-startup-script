# Ugan's Startup Script

Automated Windows 11 developer PC setup script that configures system settings and installs essential software.

## What It Does

### Windows 11 Configuration
- Hides Widgets, Search Box, and Task View Button from the taskbar
- Hides the Clock/Date from the taskbar (still visible in Action Center)
- Unpins all default taskbar apps
- Enables Dark Theme for apps and system UI
- Enables Windows Spotlight on the lock screen and desktop
- Sets Windows Terminal as the default terminal host

### Software Installed via Winget
| App | Winget ID |
|-----|-----------|
| Microsoft 365 | `Microsoft.Office` |
| Visual Studio Code | `Microsoft.VisualStudioCode` |
| Git | `Git.Git` |
| GitHub CLI | `GitHub.cli` |
| Node.js LTS (includes npm and npx) | `OpenJS.NodeJS.LTS` |
| Python 3 (latest stable) | `Python.Python.3.13` |
| PowerToys | `Microsoft.PowerToys` |
| Logi Options+ | `Logitech.OptionsPlus` |
| Spotify | `Spotify.Spotify` |
| GitHub Copilot CLI | `GitHub.Copilot` |
| GitHub Copilot app | `GitHub.CopilotApp` |
| Windows App | `Microsoft.WindowsApp` |
| Claude Code | `Anthropic.ClaudeCode` |
| Microsoft Foundry Local | `Microsoft.FoundryLocal` |
| Handy | `cjpais.Handy` |
| PowerShell 7 | `Microsoft.PowerShell` |
| Azure CLI | `Microsoft.AzureCLI` |

### Additional CLI Extension

After Azure CLI is available, the script idempotently installs the public Azure DevOps CLI extension through Azure CLI (not Winget).

## Requirements

- Windows 11 (Build 22000 or higher)
- Administrator privileges
- [App Installer (winget)](https://aka.ms/getwinget) from the Microsoft Store

## Usage

1. Clone or download this repository.
2. Right-click `run-setup.bat` and select **Run as administrator**.

To also create a system restore point before making changes, edit `run-setup.bat` and uncomment the line with `-CreateRestorePoint`, or run the PowerShell script directly:

```powershell
.\setup-windows.ps1 -CreateRestorePoint
```

## Output

Logs and registry backups are saved to the `output/` folder created next to the script:
- `setup-log-<timestamp>.txt` — full transcript of the run
- `registry-backup-<timestamp>.reg` — registry backup (only when `-CreateRestorePoint` is used)

## Notes

- Spotify and Logi Options+ require a non-elevated install; the script handles this automatically via a scheduled task.
- Restart your computer after the script finishes to ensure all changes take effect.
