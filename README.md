# YaugerAIO

A guided Windows maintenance tool that checks your PC, clears temporary files, and runs Windows repair and update tools. Follow the prompts; you don't need to know PowerShell.

## Install and run

Open **Windows PowerShell** normally. Enter these two commands, one at a time:

```powershell
Install-Module YaugerAIO -RequiredVersion 1.5.3 -Scope CurrentUser
YaugerAIO
```

**Using Command Prompt (CMD) instead?** Enter these two commands:

```cmd
powershell -NoProfile -Command "Install-Module YaugerAIO -RequiredVersion 1.5.3 -Scope CurrentUser"
powershell -NoProfile -Command "YaugerAIO"
```

Approve PowerShell Gallery prompts if asked. Windows will request administrator permission when the maintenance tool starts.

Once installed, you can run `YaugerAIO` from PowerShell any time without reinstalling it.

## What it does

- Checks disk space, CPU, memory, graphics drivers and system uptime.
- Offers Disk Cleanup and temporary-file cleanup; flushes the DNS cache and attempts browser-cache cleanup.
- Checks Windows for repairable damage with DISM, offering a repair if necessary, then checks protected system files with SFC.
- Checks for and attempts to install available Windows software updates.

**DISM and SFC:** You'll see elapsed time and a percentage when Windows provides one. If a scan stalls, press **Spacebar** to try to stop that task and continue. Interrupting a repair may leave Windows servicing unfinished.

## Your report

When finished, YaugerAIO writes **one report** (`YaugerAIO_Report_*.txt`) to your Desktop, or Documents/TEMP if the Desktop isn't available. It includes what ran, what you chose, results, approximate time spent, change in available drive space, follow-up steps, and detailed errors for troubleshooting.

**Before starting:** Save your work, close your browsers and plug in your laptop. If you approve closing running apps, unsaved work can be lost. Windows Updates may take time and need a restart. Spacebar skip applies to DISM/SFC, **not** Windows Updates.

For issues: [GitHub Issues](https://github.com/Graytools/YaugerAIO/issues). Remove personal details before sharing a report.
