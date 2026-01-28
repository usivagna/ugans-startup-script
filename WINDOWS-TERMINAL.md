# Windows Terminal Settings

This file contains the Windows Terminal configuration that will be applied by the `setup-windows.ps1` script.

## Features

- **Dark Theme**: Consistent with the Windows 11 dark theme setup
- **Color Scheme**: "One Half Dark" - a popular developer-friendly color scheme
- **Font**: Cascadia Code at 11pt with ligature support
- **Opacity**: 95% for better readability
- **Copy on Select**: Automatically copies selected text to clipboard
- **No Formatting on Copy**: Plain text only (no ANSI codes)

## Keyboard Shortcuts

- **Ctrl+Shift+C**: Copy (uses Shift to avoid conflicting with Ctrl+C interrupt signal)
- **Ctrl+Shift+V**: Paste
- **Ctrl+Shift+F**: Find in terminal
- **Alt+Shift+D**: Duplicate current pane

## Profiles

The configuration includes profiles for:
- **Windows PowerShell** (default, visible)
- **Command Prompt** (visible)
- **Azure Cloud Shell** (hidden by default - unhide in settings if you use Azure)
- **Ubuntu/WSL** (hidden by default - unhide in settings if you use WSL)

## Customization

You can customize this file before running the setup script, or edit it after installation by:
1. Opening Windows Terminal
2. Press `Ctrl+,` to open settings
3. Click "Open JSON file" in the bottom-left corner

## Automatic Application

The `setup-windows.ps1` script will:
1. Install Windows Terminal via winget (if not already installed)
2. Detect the Windows Terminal settings location
3. Backup your existing settings (if any) to the `output/` folder
4. Copy these settings to the appropriate location

**Note**: If Windows Terminal is installed for the first time, you may need to launch it once and then re-run the setup script to apply the settings.

## Documentation

For more information about Windows Terminal customization, see:
- [Windows Terminal Documentation](https://aka.ms/terminal-documentation)
- [Settings Schema](https://aka.ms/terminal-profiles-schema)
