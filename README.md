# YaugerAIO

YaugerAIO is a Windows cleanup and checkup tool I put together in PowerShell. It walks you through a few maintenance jobs, shows you what's going on, and leaves you with a report when it's finished.

You don't need to know PowerShell to use it. Just follow the prompts.

> **Heads up:** I'm still testing the updated version (1.5.1). The copy on PowerShell Gallery is older. The easy installation steps below are for **after** the update is published. If you're helping me test it now, skip to [Testing the new version](#testing-the-new-version).

## Install it once

1. On your Windows computer, open the **Start** menu.
2. Type **PowerShell** and open **Windows PowerShell**. You can open it normally; you don't need to right-click and choose Administrator.
3. Copy and paste this, then press Enter:

```powershell
Install-Module YaugerAIO -Scope CurrentUser
```

PowerShell might ask permission to install a package provider or use the PowerShell Gallery. Read the prompt and answer **Y** if you want to continue installing YaugerAIO.

That's the installation. You only need to do it once.

## Run it whenever you want

Open PowerShell again and enter:

```powershell
YaugerAIO
```

That's it. Windows will ask whether to allow the tool to run as an administrator. Click **Yes** if you want to proceed. If your Windows account isn't an administrator, you may need an administrator's password.

A new PowerShell window will open and walk you through the cleanup. It will ask before running the optional disk and temporary-file cleanups. You don't have to open PowerShell as administrator yourself.

If you prefer to load the module yourself first, this also works:

```powershell
Import-Module YaugerAIO
YaugerAIO
```

The older command, `Start-YaugerAIOWorkflow`, still works too.

## What does it actually do?

It checks your free drive space, CPU and memory use, graphics driver dates, and how long Windows has been running. It can clear temporary files, run Disk Cleanup, flush the DNS cache, and try to clear browser caches.

It also runs two Windows repair checks (DISM and SFC), then looks for and installs available Windows software updates. The DISM check only looks for damage; it doesn't fix it by itself. SFC can repair certain Windows files.

**Before you start:** Save your work, close your browsers and other apps, and plug in your laptop. If you agree to let the tool close running apps for you, anything unsaved in those apps could be lost. Updates can take a while and may require a restart.

## Where do I see the results?

When it finishes, the window tells you where it saved two files:

- **YaugerAIO_Report_...txt** is the one to read first. It says what worked, what didn't, what was skipped, and what to try next.
- **YaugerAIO_Technical_...txt** contains the longer messages and command output, in case you're troubleshooting something.

It tries to save them on your Desktop. If it can't, it tries Documents and then the Windows temporary folder.

A warning in the report doesn't automatically mean your PC is broken. It means there's something worth checking.

## Testing the new version

**This section is for testing the GitHub version before it goes on PowerShell Gallery.** It won't replace an older copy you've already installed.

Open PowerShell on the Windows PC and run these commands one at a time:

```powershell
$zip = "$env:TEMP\YaugerAIO-test.zip"
$folder = "$env:TEMP\YaugerAIO-test"
Invoke-WebRequest 'https://github.com/Graytools/YaugerAIO/archive/refs/heads/fix/psgallery-1.5.1.zip' -OutFile $zip
Expand-Archive $zip -DestinationPath $folder -Force
Import-Module "$folder\YaugerAIO-fix-psgallery-1.5.1\YaugerAIO.psd1" -Force
YaugerAIO
```

The download and import steps just prepare the tool. The last command starts the actual maintenance run and triggers the administrator approval prompt. Only run downloaded scripts you trust.

If Windows blocks the downloaded scripts, check their origin before deciding whether to unblock them.

## For anyone working on the code

The tests are in the `Tests` folder. They check the module, reporting, and individual maintenance functions without running a real cleanup or Windows Update.

```powershell
Invoke-Pester -Path ./Tests -Output Detailed
```

The full maintenance run still needs to be checked on a Windows PC before release.

The code lives at [Graytools/YaugerAIO](https://github.com/Graytools/YaugerAIO). Bug reports and pull requests are welcome. License details are in [LICENSE](LICENSE).
