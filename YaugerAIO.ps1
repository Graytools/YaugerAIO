<#PSScriptInfo
.VERSION 1.2.2
.GUID ed3b18c9-b76d-4ba2-b3b4-59b1bf8e2113
.AUTHOR Rick Yauger
.COMPANYNAME SoHo Integration, LLC
.COPYRIGHT Copyright (c) Rick Yauger 2024
.TAGS Maintenance Cleanup HealthCheck
.LICENSEURI https://opensource.org/licenses/MIT
.PROJECTURI https://github.com/Graytools/YaugerAIO
.RELEASENOTES
Initial release to PowerShell Gallery.
#>

# Set console buffer and window size.
$desiredWidth = 130
$desiredHeight = 50
$host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size($desiredWidth, $desiredHeight)
$host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size($desiredWidth, $desiredHeight)

# Set the default runspace for asynchronous handlers.
$global:myRunspace = [runspace]::DefaultRunspace
[runspace]::DefaultRunspace = $global:myRunspace

# --- Auto-Elevation Snippet Start ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $psCmd = if ($PSVersionTable.PSEdition -eq 'Core') { "pwsh.exe" } else { "powershell.exe" }
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        if ($PSCommandPath) {
            $scriptPath = $PSCommandPath
        }
        else {
            Write-Host "This script must be run from a file to auto-elevate." -ForegroundColor Red
            exit
        }
    }
    # Enclose the script path in quotes to handle spaces.
    $quotedScriptPath = '"' + $scriptPath + '"'
    Start-Process $psCmd -Verb RunAs -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $quotedScriptPath
    exit
}
# --- Auto-Elevation Snippet End ---

# Define Next Steps for the overall workflow.
$script:NextStepFor = @{
    'DISM' = 'SFC Scan'
    'SFC'  = 'Windows Updates'
}

$DebugDism = $false  # Set to $true for extra DISM debug output

# Global variables for scan summaries.
$global:DISMSummary = ""
$global:SFCSummary  = ""

# --- Function to Bring Console to Foreground ---
function Focus-Console {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@
    $hwnd = (Get-Process -Id $pid).MainWindowHandle
    [Win32]::SetForegroundWindow($hwnd) | Out-Null
}

# --- Function to Get Processes That May Lock Temp Files ---
function Get-TempLockingProcesses {
    $commonAppsMapping = @{
         "chrome"              = "Google Chrome"
         "firefox"             = "Mozilla Firefox"
         "msedge"              = "Microsoft Edge"
         "opera"               = "Opera"
         "brave"               = "Brave"
         "iexplore"            = "Internet Explorer"
         "outlook"             = "Microsoft Outlook"
         "winword"             = "Microsoft Word"
         "excel"               = "Microsoft Excel"
         "powerpnt"            = "Microsoft PowerPoint"
         "onenote"             = "Microsoft OneNote"
         "skype"               = "Skype"
         "teams"               = "Microsoft Teams"
         "onedrive"            = "OneDrive"
         "discord"             = "Discord"
         "slack"               = "Slack"
         "steam"               = "Steam"
         "epicgameslauncher"   = "Epic Games Launcher"
         "origin"              = "Origin"
         "uplay"               = "Uplay"
         "battlenet"           = "Battle.net"
         "leagueclient"        = "League of Legends"
         "riotclient"          = "Riot Client"
         "valorant"            = "Valorant"
         "spotify"             = "Spotify"
         "itunes"              = "iTunes"
         "vlc"                 = "VLC Media Player"
         "winamp"              = "Winamp"
         "pandora"             = "Pandora"
         "skypeforbusiness"    = "Skype for Business"
         "zoom"                = "Zoom"
         "teamspeak"           = "TeamSpeak"
         "minecraft"           = "Minecraft"
         "roblox"              = "Roblox"
         "fortnite"            = "Fortnite"
         "gog"                 = "GOG Galaxy"
    }
    $runningProcesses = Get-Process | Where-Object { $commonAppsMapping.ContainsKey($_.ProcessName.ToLower()) }
    $result = @()
    foreach ($proc in $runningProcesses) {
         $key = $proc.ProcessName.ToLower()
         $friendly = $commonAppsMapping[$key]
         $result += [PSCustomObject]@{ ProcessName = $key; FriendlyName = $friendly }
    }
    return $result | Sort-Object FriendlyName -Unique
}

# --- Determine Primary Drive ---
$selectedDrive = $env:SystemDrive
if (-not $selectedDrive -or -not ($selectedDrive -match "^[A-Z]:$")) {
    Write-Host "SystemDrive environment variable is not set or invalid. Determining primary drive..." -ForegroundColor Yellow
    $selectedDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Sort-Object -Property Name | Select-Object -First 1).Name + ":"
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
} else {
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
}

# Store initial free space for accurate total space freed calculation.
$initialFreeSpace = (Get-PSDrive -Name $selectedDrive.Substring(0,1)).Free

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

$timestamp = Get-Date -Format "yyyyMMdd"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $desktopPath "YAIO_$timestamp.log"
$script:log = @()
$script:foundAndFixedCorruption = $false
$script:StartTime = Get-Date
$script:runDiskCleanup = $false
$script:needsRestart = $false

function Log {
    param([string]$message, [string]$color = "Cyan")
    $script:log += $message + "`n"
    Write-Host $message -ForegroundColor $color
}

function Get-CBSSummary {
    $cbsPath = "C:\Windows\Logs\CBS\CBS.log"
    if (Test-Path $cbsPath) {
        $lines = Select-String -Path $cbsPath -Pattern "\[SR\].*"
        if ($lines) {
            foreach ($match in $lines) {
                Log "CBS: $($match.Line)" "Red"
            }
        } else {
            Log "No [SR] lines found in CBS.log" "Red"
        }
    } else {
        Log "CBS.log not found or inaccessible." "Red"
    }
}

function Show-Banner {
    $asciiArt = @"
██    ██  █████  ██    ██  ██████  ███████ ██████       █████  ██  ██████      ██    ██  ██    ██████     ██████
 ██  ██  ██   ██ ██    ██ ██       ██      ██   ██     ██   ██ ██ ██    ██     ██    ██ ███         ██         ██
  ████   ███████ ██    ██ ██   ███ █████   ██████      ███████ ██ ██    ██     ██    ██  ██     █████      █████
   ██    ██   ██ ██    ██ ██    ██ ██      ██   ██     ██   ██ ██ ██    ██      ██  ██   ██    ██         ██
   ██    ██   ██  ██████   ██████  ███████ ██   ██     ██   ██ ██  ██████        ████    ██ ██ ███████ ██ ███████
"@
    Write-Host $asciiArt
}

# --- System Check Functions ---
function Check-DiskSpace {
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'"
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        Log "${selectedDrive} Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
    } catch {
        Log "Failed to retrieve disk space info for ${selectedDrive}: $_" "Red"
    }
}

function Check-CPUUsage {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time'
        $usage = [math]::Round($cpu.CounterSamples.CookedValue, 2)
        Log "CPU Usage: $usage%" "Cyan"
    } catch {
        Log "Failed to retrieve CPU usage: $_" "Red"
    }
}

function Flush-DNSCache {
    try {
        Write-Host "Flushing DNS cache..." -ForegroundColor Cyan
        $before = (Get-DnsClientCache).Count
        ipconfig /flushdns | Out-Null
        $after = (Get-DnsClientCache).Count
        $flushed = $before - $after
        Write-Host "✔ DNS cache flushed." -ForegroundColor Cyan
        Write-Host "Entries removed: $flushed" -ForegroundColor Cyan
        Write-Host ""
    } catch {
        Log "Failed to flush DNS cache: $_" "Red"
    }
}

function Check-RAMUsage {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $used = [math]::Round($total - $free, 2)
        $percentUsed = [math]::Round(($used / $total) * 100, 2)
        Log "RAM Usage: $used GB of $total GB ($percentUsed%)" "Cyan"
        Start-Sleep -Seconds 2
        if ($percentUsed -gt 80) {
            Log "Random Access Memory is currently utilized above 80%. Please check and see if you have 14 million tabs open." "Yellow"
            Start-Sleep -Seconds 5
        }
    } catch {
        Log "Failed to retrieve RAM usage: $_" "Red"
    }
}

function Check-GPUDrivers {
    try {
        $gpus = Get-CimInstance Win32_VideoController
        foreach ($gpu in $gpus) {
            if ($gpu.DriverDate) {
                $driverDate = [datetime]$gpu.DriverDate
                $formattedDate = $driverDate.ToString("MMddyyyy")
            } else {
                $formattedDate = "Unknown"
            }
            Log "GPU Detected: $($gpu.Name) - $formattedDate" "Cyan"
            if ($gpu.DriverDate) {
                $releaseDate = [datetime]$gpu.DriverDate
                $monthsDifference = (New-TimeSpan -Start $releaseDate -End (Get-Date)).TotalDays / 30
                if ($monthsDifference -ge 6) {
                    Log "GPU Driver release more than 6 months ago. Please check your GPU Vendor for driver updates." "Red"
                }
                elseif ($monthsDifference -ge 3) {
                    Log "GPU Driver release more than 3 months ago. Please check your GPU Vendor for driver updates." "Yellow"
                }
                else {
                    Log "GPU Driver release is within the last 3 months." "Cyan"
                }
            }
            else {
                Log "GPU Driver release date not available." "Yellow"
            }
        }
        Write-Host ""
    } catch {
        Log "Failed to retrieve GPU driver info: $_" "Red"
    }
}

function Check-SystemUptime {
    try {
        $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
        $days = [math]::Round($uptime.TotalDays, 2)
        Log "System Uptime: $days days" "Cyan"
        Start-Sleep -Seconds 4
        if ($days -lt 3) {
            Log "Great job keeping up on your reboots. Keep it up!" "Yellow"
        }
        elseif ($days -ge 7) {
            $message = @"
🚨 Your system has been running for over a week without a restart!
This can lead to performance issues, memory leaks, and failed updates.
It is strongly recommended that you restart your computer ASAP.
Make it a habit to restart at least every 2-3 days for optimal performance.
"@
            Log $message "Red"
        }
        elseif ($days -ge 3) {
            $message = @"
⚠️ Your system has been running for over 3 days.
Regularly restarting your computer helps:
- Apply critical updates
- Clear temporary files and memory leaks
- Improve performance and stability
For best results, restart at least once every few days.
"@
            Log $message "Yellow"
        }
        Start-Sleep -Seconds 10
    } catch {
        Log "Failed to retrieve system uptime: $_" "Red"
    }
}

function Install-WindowsUpdates {
    Write-Host "Checking for Windows updates..." -ForegroundColor Cyan
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        if ($SearchResult.Updates.Count -eq 0) {
            Write-Host "Windows Updates are current." -ForegroundColor Green
            return
        }
        Write-Host "Updates found:" -ForegroundColor Gray
        $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $SearchResult.Updates) {
            Write-Host "Update: $($update.Title)" -ForegroundColor Gray
            if (-not $update.EulaAccepted) {
                $update.AcceptEula() | Out-Null
            }
            $UpdatesToDownload.Add($update) | Out-Null
        }
        if ($UpdatesToDownload.Count -gt 0) {
            Write-Host "Downloading updates..." -ForegroundColor Cyan
            $Downloader = $UpdateSession.CreateUpdateDownloader()
            $Downloader.Updates = $UpdatesToDownload
            $Downloader.Download() | Out-Null
            Write-Host "Installing updates..." -ForegroundColor Cyan
            $Installer = $UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToDownload
            $InstallationResult = $Installer.Install()
            Write-Host "Updates Installed: $($InstallationResult.UpdatesInstalled)" -ForegroundColor Gray
            if ($InstallationResult.RebootRequired) {
                $script:needsRestart = $true
                Write-Host "A restart is required to complete the update installation." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Log "Error during Windows update process: $_" "Red"
    }
}

# --------------------------------------------------------------
# DISM /CheckHealth only DETECTS component store problems.
# Keep result classification separate so it can be tested safely.
# --------------------------------------------------------------
function Get-DISMCheckHealthStatus {
    param(
        [string]$Output,
        [int]$ExitCode
    )
    if ($ExitCode -ne 0) { return 'Failed' }
    if ($Output -match 'No component store corruption detected') { return 'Healthy' }
    if ($Output -match 'component store is not repairable') { return 'NotRepairable' }
    if ($Output -match 'component store is repairable') { return 'Repairable' }
    return 'Unknown'
}

function Run-DISMCheckHealth {
    Write-Host "Checking Windows component store health (DISM /CheckHealth)..." -ForegroundColor Cyan
    try {
        $dismOutput = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $status = Get-DISMCheckHealthStatus -Output $dismOutput -ExitCode $exitCode
        $script:log += "DISM /CheckHealth status: $status (exit code $exitCode)`n$dismOutput`n"

        switch ($status) {
            'Healthy' { Write-Host "No component store corruption detected. Moving on to SFC." -ForegroundColor Green }
            'NotRepairable' { Write-Host "DISM reports that the component store is not repairable. Further troubleshooting is required." -ForegroundColor Red }
            'Repairable' { Write-Host "DISM detected repairable corruption. /CheckHealth does not repair it; consider DISM /RestoreHealth." -ForegroundColor Yellow }
            'Failed' { Write-Host "DISM /CheckHealth failed (exit code $exitCode). Review the output in the log." -ForegroundColor Red }
            default { Write-Host "DISM completed, but its health status was not recognized. See the logged output." -ForegroundColor Yellow }
        }
    } catch {
        Log "DISM /CheckHealth could not run: $_" "Red"
    }
    Write-Host ""
}

# -------------------------------
# SFC /scannow can repair files. Interpret known result messages conservatively;
# unknown or localized output must not be reported as a successful repair.
# -------------------------------
function Get-SFCScanStatus {
    param(
        [string]$Output,
        [int]$ExitCode
    )
    if ($ExitCode -ne 0) { return 'Failed' }
    if ($Output -match 'found corrupt files but was unable to fix some of them') { return 'Unresolved' }
    if ($Output -match 'found corrupt files and successfully repaired them') { return 'Repaired' }
    if ($Output -match 'did not find any integrity violations') { return 'Healthy' }
    if ($Output -match 'could not perform the requested operation|could not start the repair service|system repair pending') { return 'Failed' }
    return 'Unknown'
}

function Run-SFCScan {
    Write-Host "Executing SFC Scan..." -ForegroundColor Cyan
    try {
        # Tee-Object keeps SFC's native output visible while capturing it for the desktop log.
        $sfcLines = @()
        & sfc.exe /scannow 2>&1 | Tee-Object -Variable sfcLines
        $exitCode = $LASTEXITCODE
        $sfcOutput = $sfcLines | Out-String
        $status = Get-SFCScanStatus -Output $sfcOutput -ExitCode $exitCode
        $script:log += "SFC /scannow status: $status (exit code $exitCode)`n$sfcOutput`n"

        switch ($status) {
            'Healthy' { Write-Host "SFC found no integrity violations." -ForegroundColor Green }
            'Repaired' { Write-Host "SFC reports that corrupt system files were repaired." -ForegroundColor Green }
            'Unresolved' { Write-Host "SFC could not repair all corrupt files. Review CBS.log for details." -ForegroundColor Yellow }
            'Failed' { Write-Host "SFC did not complete successfully (exit code $exitCode). Review the output in the log." -ForegroundColor Red }
            default { Write-Host "SFC completed, but its result was not recognized. Review the output in the log." -ForegroundColor Yellow }
        }
    } catch {
        Log "SFC scan could not run: $_" "Red"
    }
}


# --------------------------------------------------------------
# Functions for clearing browser caches, disk cleanup, and temporary files.
# --------------------------------------------------------------
function Clear-BrowserCaches {
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        if (Test-Path $chromePath) {
            Remove-Item "$chromePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Chrome cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Chrome Browser." "Cyan"
        }
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
        if (Test-Path $edgePath) {
            Remove-Item "$edgePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Edge cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Edge Browser." "Cyan"
        }
        $bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
        if (Test-Path $bravePath) {
            Remove-Item "$bravePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Brave cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Brave Browser." "Cyan"
        }
        if ((Test-Path "$env:LOCALAPPDATA\Opera Software") -or (Test-Path "$env:APPDATA\Opera Software")) {
            $operaStableLocal   = "$env:LOCALAPPDATA\Opera Software\Opera Stable\Cache"
            $operaStableRoaming = "$env:APPDATA\Opera Software\Opera Stable\Cache"
            if (Test-Path $operaStableLocal)   { Remove-Item "$operaStableLocal\*" -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $operaStableRoaming) { Remove-Item "$operaStableRoaming\*" -Recurse -Force -ErrorAction SilentlyContinue }
            $operaGXLocal   = "$env:LOCALAPPDATA\Opera Software\Opera GX\Cache"
            $operaGXRoaming = "$env:APPDATA\Opera Software\Opera GX\Cache"
            if (Test-Path $operaGXLocal)   { Remove-Item "$operaGXLocal\*" -Recurse -Force -ErrorAction SilentlyContinue }
            if (Test-Path $operaGXRoaming) { Remove-Item "$operaGXRoaming\*" -Recurse -Force -ErrorAction SilentlyContinue }
            Log "✔ Opera cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Opera Browser." "Cyan"
        }
        if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
            $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
                foreach ($profile in $profiles) {
                    $cache2Path = (Join-Path $profile.FullName "cache2")
                    $cachePath  = (Join-Path $profile.FullName "cache")
                    if (Test-Path $cache2Path) { Remove-Item "$cache2Path\*" -Recurse -Force -ErrorAction SilentlyContinue }
                    if (Test-Path $cachePath)  { Remove-Item "$cachePath\*" -Recurse -Force -ErrorAction SilentlyContinue }
                }
            }
            Log "✔ Firefox cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Firefox Browser." "Cyan"
        }
    } catch {
        Log "Failed to clear browser caches: $_" "Red"
    }
}

function Run-CleanMgr {
    try {
        Write-Host -NoNewline -ForegroundColor Cyan "Cleaning $selectedDrive Drive"
        $process = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/d ${selectedDrive} /sagerun:1" -WindowStyle Minimized -PassThru
        $dotCount = 0
        while (-not $process.HasExited) {
            $dotCount++
            if ($dotCount -gt 3) { $dotCount = 1 }
            Write-Host -NoNewline "`rCleaning $selectedDrive Drive" -ForegroundColor Cyan
            Write-Host -NoNewline ("." * $dotCount) -ForegroundColor Cyan
            Start-Sleep -Milliseconds 100
        }
        Write-Host ""
        Log "✔ Disk Cleanup executed on ${selectedDrive}." "Cyan"
        Write-Host ""
    } catch {
        Log "Disk Cleanup failed on ${selectedDrive}: $_" "Red"
    }
}

function Get-WindowsTempSize {
    try {
        $tempPath = $env:TEMP
        if ([string]::IsNullOrWhiteSpace($tempPath) -or -not (Test-Path -LiteralPath $tempPath -PathType Container)) {
            Log "Unable to calculate Windows Temp size: TEMP directory is unavailable." "Yellow"
            return 0
        }

        # -Force includes hidden files; -File excludes directories from the total.
        $files = Get-ChildItem -LiteralPath $tempPath -Recurse -File -Force -ErrorAction SilentlyContinue
        $sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
        if (-not $sizeBytes) { $sizeBytes = 0 }
        return [math]::Round($sizeBytes / 1MB, 2)
    } catch {
        Log "Failed to calculate Windows Temp size: $_" "Red"
        return 0
    }
}

function Clear-WindowsTemp {
    try {
        $tempPath = $env:TEMP
        if ([string]::IsNullOrWhiteSpace($tempPath) -or -not (Test-Path -LiteralPath $tempPath -PathType Container)) {
            Log "Skipped Windows Temp cleanup: TEMP directory is unavailable." "Yellow"
            return
        }

        $resolvedPath = (Resolve-Path -LiteralPath $tempPath -ErrorAction Stop).ProviderPath
        $pathRoot = [System.IO.Path]::GetPathRoot($resolvedPath)
        if ([string]::IsNullOrWhiteSpace($pathRoot) -or $resolvedPath.TrimEnd('\', '/') -eq $pathRoot.TrimEnd('\', '/')) {
            Log "Skipped Windows Temp cleanup: TEMP must not be a filesystem root." "Red"
            return
        }

        $tempDirectory = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
        if (($tempDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Log "Skipped Windows Temp cleanup: TEMP must not be a symbolic link or junction." "Red"
            return
        }

        $cleanupErrors = @()
        foreach ($item in Get-ChildItem -LiteralPath $resolvedPath -Force -ErrorAction Stop) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Log "Skipped link or junction in Windows Temp: $($item.Name)" "Yellow"
                continue
            }
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
        }
        if ($cleanupErrors.Count -gt 0) {
            Log "Windows Temp cleanup could not remove $($cleanupErrors.Count) item(s), possibly because they are in use." "Yellow"
        }
    } catch {
        Log "Failed to clear Windows Temp files: $_" "Red"
    }
}

# New function to wrap text without breaking words.
function Wrap-Text {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text,
        [int]$Width = 130
    )
    $words = $Text -split '\s+'
    $line = ""
    $result = ""
    foreach ($word in $words) {
        if (($line.Length + $word.Length + 1) -gt $Width) {
            $result += $line.TrimEnd() + "`n"
            $line = $word + " "
        } else {
            $line += $word + " "
        }
    }
    if ($line) {
        $result += $line.TrimEnd()
    }
    return $result
}

# -------------------------------
# Main Section
# -------------------------------
Show-Banner

Write-Host "During this session, we will:" -ForegroundColor White
Write-Host "- Optionally run Disk Cleanup." -ForegroundColor White
Write-Host "- Optionally clear Windows Temp Files." -ForegroundColor White
Write-Host "- Check available disk space on ${selectedDrive}." -ForegroundColor White
Write-Host "- Check current CPU usage." -ForegroundColor White
Write-Host "- Flush the DNS cache." -ForegroundColor White
Write-Host "- Check RAM usage." -ForegroundColor White
Write-Host "- Check GPU driver(s) and version(s)." -ForegroundColor White
Write-Host "- Log system uptime." -ForegroundColor White
Write-Host "- Clear browser caches. (Chrome, Edge, Brave, Opera, Firefox)" -ForegroundColor White
Write-Host "- DISM Scan for Component Store Corruption." -ForegroundColor White
Write-Host "- SFC Scan to find and fix Windows System Files." -ForegroundColor White
Write-Host "- Check for and install Windows Updates." -ForegroundColor White
Write-Host "" -ForegroundColor White

Focus-Console
Start-Sleep -Seconds 1

Write-Host "Please close all applications and browsers for a clean, smooth Cache Smash.™" -ForegroundColor Yellow
Start-Sleep -Seconds 2
Write-Host "Please press Enter to begin." -ForegroundColor Yellow
[void][System.Console]::ReadKey($true)
Write-Host ""

# --- 1. Disk Cleanup (Optional) ---
Write-Host "Would you like to run Disk Cleanup? (Y/N)" -ForegroundColor Yellow
$key = [Console]::ReadKey($true)
if ($key.KeyChar.ToString().ToUpper() -eq "Y") {
    $script:runDiskCleanup = $true
    Log "✔ User has opted to run Disk Cleanup." "Yellow"
    Run-CleanMgr
} else {
    Log "✖ User has opted not to run Disk Cleanup." "Yellow"
}
Write-Host ""

# --- 2. Clear Windows Temp Files (Optional) ---
$tempSize = Get-WindowsTempSize
if ($tempSize -gt 0) {
    if ($tempSize -gt 1000) {
        $displaySize = ("{0:N2} GB" -f ($tempSize / 1024))
    } else {
        $displaySize = ("{0:N2} MB" -f $tempSize)
    }
    Write-Host ""
    Write-Host "You can reclaim $displaySize from Windows Temp files. Interested? Y/N" -ForegroundColor Yellow
    Write-Host ""
    $tempChoice = [Console]::ReadKey($true)
    if ($tempChoice.KeyChar.ToString().ToUpper() -eq "Y") {
        # Check for any running temp-locking processes.
        $tempLockingApps = Get-TempLockingProcesses
        if ($tempLockingApps.Count -gt 0) {
            Write-Host "`nThe following applications are currently running and may block temp file clearance:" -ForegroundColor Yellow
            foreach ($app in $tempLockingApps) {
                Write-Host "- $($app.FriendlyName)" -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "Would you like to automatically close these applications before clearing temp files? (Y/N)" -ForegroundColor Yellow
            $retryKey = [Console]::ReadKey($true)
            if ($retryKey.KeyChar.ToString().ToUpper() -eq "Y") {
                foreach ($app in $tempLockingApps) {
                    Write-Host "Closing $($app.FriendlyName)..." -ForegroundColor Cyan
                    Get-Process | Where-Object { $_.ProcessName.ToLower() -eq $app.ProcessName } | Stop-Process -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 2
            } else {
                Log "✖ User chose not to close running applications. Proceeding to clear available temp files." "Yellow"
            }
        }
        Clear-WindowsTemp
        Log "✔ Windows Temp Files have been cleared." "Yellow"
    } else {
        Log "✖ User chose not to clear Windows Temp files." "Yellow"
    }
} else {
    Log "✔ No clearable Windows Temp files found." "Cyan"
}
Write-Host ""

# --- 3. Check available disk space ---
Check-DiskSpace
# --- 4. Check current CPU usage ---
Check-CPUUsage
# --- 5. Flush the DNS cache ---
Flush-DNSCache
# --- 6. Check RAM usage ---
Check-RAMUsage

# Insert extra line break between RAM check output and GPU detection.
Write-Host ""

# --- 7. Check GPU drivers and version(s) ---
Check-GPUDrivers
Write-Host ""  # Blank line between GPU and System Uptime
# --- 8. Log system uptime ---
Check-SystemUptime
Write-Host ""  # Blank line between uptime alerts and Cache Smash

# --- Display "Cache Smash..." message with loading dots for 5 seconds ---
$endTime = (Get-Date).AddSeconds(5)
$dotStates = @(".", "..", "...")
$dotIndex = 0
while ((Get-Date) -lt $endTime) {
    $display = "Cache Smash" + $dotStates[$dotIndex]
    Write-Host -NoNewline "$display`r" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 500
    $dotIndex = ($dotIndex + 1) % $dotStates.Count
}
Write-Host ""
Start-Sleep -Seconds 2

# --- 9. Clear browser caches ---
Clear-BrowserCaches

# --- Warning for DISM scan ---
Write-Host ""
Write-Host "We're about to check the component store using DISM /CheckHealth. This check detects problems but does not repair them." -ForegroundColor Yellow
Write-Host "If it's taking longer than expected, please be patient as it verifies the component store." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Write-Host ""

# --- 10. Run DISM /CheckHealth ---
Run-DISMCheckHealth

Write-Host ""  # Extra line break after DISM scan

# --- 11. Run SFC Scan ---
Run-SFCScan

Write-Host ""  # Extra line break before Windows Updates

# --- 12. Check for and install Windows Updates ---
Install-WindowsUpdates

# -------------------------------
# Final Logging and Summary
# -------------------------------
Write-Host ""
$finalFree = (Get-PSDrive -Name $selectedDrive.Substring(0,1)).Free
$spaceFreedBytes = $finalFree - $initialFreeSpace
if ($spaceFreedBytes -lt 0) { $spaceFreedBytes = 0 }
if ($spaceFreedBytes -ge 1GB) {
    $spaceFreedFormatted = ("{0:N2} GB" -f ($spaceFreedBytes / 1GB))
} else {
    $spaceFreedFormatted = ("{0:N2} MB" -f ($spaceFreedBytes / 1MB))
}
Log "✔ Total space freed during this session: $spaceFreedFormatted" "Cyan"

$duration = (Get-Date) - $script:StartTime
Log "⏱ Total script runtime: $($duration.ToString())" "Cyan"

$script:log | Out-File -FilePath $logFile -Encoding UTF8

Log "=============================================" "Cyan"
Log "YaugerAIO tasks completed." "Blue"
Write-Host ""

$thankYouMessage = "Thanks for trying out my Windows AIO Maintenance Tool. For feature requests, or bug reports, please feel welcome to reach out to me at rick.yauger@outlook.com - alternatively, pull requests are welcome."
$wrappedThankYou = Wrap-Text -Text $thankYouMessage -Width 130
Log $wrappedThankYou "Blue"
Write-Host ""

$feedbackMessage = "Check the log file on your desktop for details."
$wrappedFeedback = Wrap-Text -Text $feedbackMessage -Width 130
Log $wrappedFeedback "Blue"
Write-Host ""

try {
    Stop-Transcript
} catch {
    # No transcript active.
}



