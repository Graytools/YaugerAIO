# YaugerAIO

YaugerAIO is a Windows maintenance tool I wrote in PowerShell. It checks some common trouble spots, walks you through cleanup, runs Windows repair checks, and leaves you a report explaining what happened.

You don't need to know PowerShell to use it. Open a terminal, enter the commands below, and follow the prompts.

**PowerShell Gallery version: 1.5.1** — [Install from PowerShell Gallery](https://www.powershellgallery.com/packages/YaugerAIO/1.5.1).

**GitHub source version: 1.5.2** — Adds an optional Windows repair step and clearer reports. The 1.5.2 changes are in GitHub source only until a separate Gallery release is published. The installation instructions below still install Gallery version 1.5.1.

## Install and run

### Using PowerShell

1. Open the **Start** menu.
2. Type **PowerShell** and open **Windows PowerShell**. You can open it normally — there's no need to right-click and choose *Run as administrator*.
3. Enter these two commands, one after the other:

```powershell
Install-Module YaugerAIO -Scope CurrentUser -ErrorAction Stop
YaugerAIO
```

**The first command installs YaugerAIO.** It downloads the tool from PowerShell Gallery but does not run any maintenance.

**The second command starts YaugerAIO.** Windows will ask for administrator permission, then open the maintenance window and walk you through the checks.

PowerShell may ask whether you trust PowerShell Gallery or want to install a required package provider. Read the prompt and accept it if you want to continue.

### Using Command Prompt (CMD)

If you opened **Command Prompt** instead, paste this one line:

```cmd
powershell -NoProfile -Command "Install-Module YaugerAIO -Scope CurrentUser -ErrorAction Stop; YaugerAIO"
```

CMD hands those commands to PowerShell. You still get the same administrator prompt and the same maintenance window.

### Next time you want to use it

You only install YaugerAIO once. After that, start it from PowerShell with:

```powershell
YaugerAIO
```

Or from CMD with:

```cmd
powershell -NoProfile -Command "YaugerAIO"
```

If you've installed an older version, enter `Update-Module YaugerAIO` in PowerShell to get the latest published version.

You can also use `Start-YaugerAIOWorkflow` if you've been using that command already. Both commands launch the same tool. There's no need to type `Import-Module` first in a normal PowerShell setup.

## Before you start

**Save your work, close your open programs, and plug in a laptop before running this.**

YaugerAIO doesn't just look at your PC; it performs maintenance. It can remove temporary files, clear browser caches, and **install Windows software updates**. Updates can take a while and may require a restart.

Some cleanup is optional, and the tool asks before running it. It may also offer to close applications holding temporary files open. If you say yes, those applications can be closed without saving their work.

Windows will ask for administrator approval when the tool starts. If your Windows account doesn't have administrator privileges, you'll need credentials from an administrator. You can't skip that Windows security requirement.

## What does it check and clean?

- **Disk space:** Shows how much room is left on the Windows drive and offers Disk Cleanup.
- **Temporary files:** Checks the Windows TEMP folder and asks whether you want to clear it.
- **CPU and memory:** Takes a quick reading of current usage. These are snapshots, not long-term performance tests.
- **Graphics drivers:** Shows detected graphics hardware and driver dates. An older driver date does not automatically mean an update is needed.
- **Uptime:** Reports how long Windows has been running since its last restart.
- **DNS cache:** Flushes Windows' local DNS resolver cache.
- **Browser caches:** Tries to clear cached files from supported browsers. Some files may be in use or belong to other browser profiles.
- **DISM:** Checks Windows repair files for damage. In the 1.5.2 source, if DISM finds repairable damage, YaugerAIO asks before running `DISM /RestoreHealth`, then checks the result again. The published 1.5.1 package only checks for damage.
- **SFC:** Runs `sfc /scannow` to check protected Windows system files and repair what Windows can.
- **Windows Update:** Looks for applicable software updates, downloads them, and attempts installation. If the update service reports a failure or incomplete result, the report should flag that instead of claiming everything succeeded.

The program takes you through these jobs in order. Some steps can take several minutes, especially SFC and Windows Update.

## Where are my results?

At the end of the run, YaugerAIO prints the locations of two text files:

- **`YaugerAIO_Report_<timestamp>.txt`** — Start here. It tells you what succeeded, what failed, what was skipped, and what still needs attention.
- **`YaugerAIO_Technical_<timestamp>.txt`** — More detailed messages and command output, useful when something doesn't work.

The tool tries to save both files on the Desktop. If it can't, it tries Documents and then the temporary folder. Read the file locations shown in the console so you know where they ended up.

The report uses these labels:

| Result | Meaning |
| --- | --- |
| PASS | The check reported success. |
| WARN | Something needs attention or finished only partly. |
| FAIL | The operation failed or could not finish. |
| SKIP | The operation wasn't run. |
| CHECK | The tool couldn't confirm the result; review the details. |

A clean report is useful, but it isn't a guarantee that every part of a computer is healthy.

## If something doesn't work

**`YaugerAIO` isn't recognized:** Make sure the installation finished without errors. Close and reopen PowerShell, then try again. You can check whether it installed with `Get-Module -ListAvailable YaugerAIO`.

**You don't see the administrator prompt:** Make sure you ran `YaugerAIO`, not just `Install-Module`. If Windows needs another administrator's password, somebody with that access will have to approve the request.

**Something fails during maintenance:** Keep the PowerShell window open, note the message, and check the technical log. Don't keep rerunning a failed Windows repair command without checking why it failed.

**Can't find your report:** Look at the two file paths printed at the end of the run. If Windows elevation used a different administrator account, the files may be saved under that account's Desktop or Documents.

For bugs or feature requests, open an [issue on GitHub](https://github.com/Graytools/YaugerAIO/issues). Please remove personal information from logs before attaching them.

## For anyone working on the code

The module is `YaugerAIO.psm1`. It exports `YaugerAIO` and `Start-YaugerAIOWorkflow`. Importing the module does not start maintenance.

The guided maintenance script is `YaugerAIO.ps1`. That file runs the workflow when launched, so **don't dot-source it just to inspect its functions**.

The `Tests` folder has Pester tests for module loading, temporary-file cleanup, DISM/SFC result handling, report generation, and launcher checks:

```powershell
Invoke-Pester -Path ./Tests -Output Detailed
```

The tests are designed not to run an actual Windows cleanup, SFC scan, or Windows Update installation. They can't replace an end-to-end test on a real Windows machine.

Requirements: Windows 10 or later, Windows PowerShell 5.1 or PowerShell 7, and administrator approval for maintenance.

The project is licensed under the MIT License. See [LICENSE](LICENSE) for the details.
