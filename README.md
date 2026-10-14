# YaugerAIO

YaugerAIO is a guided Windows maintenance tool written in PowerShell. It checks system health, offers cleanup tasks, runs the Windows servicing tools, and writes a short report with follow-up actions.

## Install and run (after v1.5.1 is published)

Open **Windows PowerShell** or **PowerShell 7** normally. You do not need to open an elevated console.

```powershell
Install-Module YaugerAIO -Scope CurrentUser
YaugerAIO
```

PowerShell can load an installed module automatically when you enter one of its exported commands. If you prefer an explicit import:

```powershell
Import-Module YaugerAIO
YaugerAIO
```

The command `Start-YaugerAIOWorkflow` is also available for existing users. Both commands start the same guided maintenance script and request administrator approval through Windows UAC. An administrator account or credentials are required to approve that prompt.

**Release status:** v1.5.1 is still being tested on the `fix/psgallery-1.5.1` branch. The current PowerShell Gallery package is an older release and does **not** contain these changes. Do not use the Gallery instructions above to test this branch yet.

## Test the GitHub branch before publication

In a PowerShell window on the Windows machine:

```powershell
$archive = Join-Path $env:TEMP 'YaugerAIO-branch.zip'
$destination = Join-Path $env:TEMP 'YaugerAIO-branch-test'
Invoke-WebRequest -Uri 'https://github.com/Graytools/YaugerAIO/archive/refs/heads/fix/psgallery-1.5.1.zip' -OutFile $archive
Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
Import-Module (Join-Path $destination 'YaugerAIO-fix-psgallery-1.5.1\YaugerAIO.psd1') -Force
YaugerAIO
```

This runs the current repair branch without changing the installed Gallery version. Review the branch before running it on someone else's PC. The commands above download and import the module; only the final `YaugerAIO` command starts maintenance.

## What the workflow does

- Offers Windows Disk Cleanup and user TEMP cleanup.
- Checks free disk space, sampled CPU/RAM usage, graphics driver dates, and time since restart.
- Flushes the DNS resolver cache and attempts browser cache cleanup.
- Checks Windows component store health with `DISM /CheckHealth` (detection only).
- Runs `sfc /scannow` and interprets the result without assuming corruption was repaired.
- Searches for and attempts to install applicable Windows software updates.
- Records a structured maintenance summary and a separate technical log.

The script can close selected running applications if you agree to that prompt. Save documents and close applications yourself first. Updates and servicing operations may take time or require a restart. Run the laptop on AC power.

## Reports

At the end of a run, YaugerAIO prints the paths of:

- `YaugerAIO_Report_<timestamp>.txt` — check results, warnings, unverified items, and follow-up actions.
- `YaugerAIO_Technical_<timestamp>.txt` — recorded diagnostic messages and command output.

It attempts to save both files on the Desktop, falling back to Documents and then the temp directory. If Windows UAC requires credentials for another administrator account, the elevated process may use that account's profile and user-specific paths. Check the paths printed at completion.

## Requirements

- Windows 10 or later
- Windows PowerShell 5.1 or PowerShell 7
- Administrator approval for the maintenance run

Importing the module does not perform maintenance. You must explicitly invoke `YaugerAIO` or `Start-YaugerAIOWorkflow`.

## Development and testing

The `Tests` directory contains Pester coverage for syntax, module imports and exports, temp cleanup safety, servicing result classification, and report formatting. Tests extract individual functions from the maintenance script rather than dot-sourcing it, because the script runs the full workflow at top level.

```powershell
Invoke-Pester -Path ./Tests -Output Detailed
```

GitHub Actions runs the test suite under Windows PowerShell 5.1 and PowerShell 7. Passing unit tests does not replace a full test run on Windows.

## Contributing

Issues and pull requests are welcome at [Graytools/YaugerAIO](https://github.com/Graytools/YaugerAIO). See [LICENSE](LICENSE) for license terms.
