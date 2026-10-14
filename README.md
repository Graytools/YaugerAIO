# YaugerAIO

YaugerAIO is a Windows cleanup and checkup tool I put together in PowerShell. It walks you through a few maintenance jobs, shows you what's going on, and leaves you with a report when it's finished.

You don't need to know PowerShell to use it. Just follow the prompts.

> **Heads up:** I'm still testing the updated version (1.5.1). The copy on PowerShell Gallery is older. The easy installation steps below are for **after** the update is published. If you're helping me test it now, skip to [Testing the new version](#testing-the-new-version).

## Install it and run it

You don't have to open anything as Administrator. Windows will ask for permission when YaugerAIO actually starts.

### If you opened PowerShell

1. Open the Start menu, type **Windows PowerShell**, and open it normally.
2. Paste these **two lines** and press Enter:

```powershell
Install-Module YaugerAIO -Scope CurrentUser -ErrorAction Stop
YaugerAIO
```

**First line:** downloads and installs YaugerAIO for your Windows account. It doesn't run any cleanup.

**Second line:** starts YaugerAIO. You'll get a Windows administrator permission prompt, followed by the guided maintenance window.

The installation command itself doesn't tell you what to type next. That's why both lines are here, ready to paste. PowerShell might ask you to approve the PowerShell Gallery or install a package provider. Read those prompts and agree if you want to proceed.

### If you opened Command Prompt (CMD)

CMD doesn't understand PowerShell commands on its own. Paste this **single line** into CMD instead:

```cmd
powershell -NoProfile -Command "Install-Module YaugerAIO -Scope CurrentUser -ErrorAction Stop; YaugerAIO"
```

It opens PowerShell behind the scenes, installs the module, then starts the same maintenance window. This works whether CMD is opened normally or as Administrator.

### Next time, you don't need to install it again

From **PowerShell**, just type:

```powershell
YaugerAIO
```

From **CMD**, type:

```cmd
powershell -NoProfile -Command "YaugerAIO"
```

Windows will ask for administrator permission when necessary. Click **Yes** to continue; if you're signed in with a standard Windows account, you may need an administrator's password. A separate console will open so you can follow the prompts and read the results.

If you have an older YaugerAIO already installed, run `Update-Module YaugerAIO` in PowerShell after 1.5.1 is published.

You can also explicitly load the module with `Import-Module YaugerAIO` before running `YaugerAIO`, but you shouldn't have to. The longer command, `Start-YaugerAIOWorkflow`, remains available too.

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
