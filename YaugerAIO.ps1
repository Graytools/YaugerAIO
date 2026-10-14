<#PSScriptInfo
.VERSION 1.5.2
.GUID ed3b18c9-b76d-4ba2-b3b4-59b1bf8e2113
.AUTHOR Rick Yauger
.COMPANYNAME SoHo Integration, LLC
.COPYRIGHT Copyright (c) Rick Yauger 2024
.TAGS Maintenance Cleanup HealthCheck
.LICENSEURI https://opensource.org/licenses/MIT
.PROJECTURI https://github.com/Graytools/YaugerAIO
.RELEASENOTES
Guided Windows maintenance with optional DISM repairs, automatic elevation, and readable reports.
#>

# Ask Windows for admin rights before doing anything with the console.
# This handles launches from a regular CMD or PowerShell window.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $psCmd = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        Write-Host 'YaugerAIO must be run from a saved script file to request administrator approval.' -ForegroundColor Red
        return
    }

    # Leave the new console open so the user can read the results.
    $quotedScriptPath = '"' + $scriptPath + '"'
    try {
        Start-Process -FilePath $psCmd -Verb RunAs -ArgumentList @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $quotedScriptPath) -ErrorAction Stop
    } catch {
        Write-Host "YaugerAIO did not receive administrator approval. No maintenance was started: $_" -ForegroundColor Yellow
    }
    return
}

# Windows Terminal and some console hosts won't honor resize requests.
try {
    $desiredWidth = 130
    $desiredHeight = 50
    $host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size($desiredWidth, $desiredHeight)
    $host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size($desiredWidth, $desiredHeight)
} catch {
}

# Keep the current runspace available to the console helpers.
$global:myRunspace = [runspace]::DefaultRunspace
[runspace]::DefaultRunspace = $global:myRunspace

# Next-step labels used by the original servicing flow.
$script:NextStepFor = @{
    'DISM' = 'SFC Scan'
    'SFC'  = 'Windows Updates'
}

$DebugDism = $false  # Set to $true for extra DISM debug output

# Scan notes shared across the workflow.
$global:DISMSummary = ""
$global:SFCSummary  = ""

# Bring the new console to the front when possible.
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

# Running applications can hold temp files open.
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

# Prefer the Windows system drive when checking free space.
$selectedDrive = $env:SystemDrive
if (-not $selectedDrive -or -not ($selectedDrive -match "^[A-Z]:$")) {
    Write-Host "SystemDrive environment variable is not set or invalid. Determining primary drive..." -ForegroundColor Yellow
    $selectedDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Sort-Object -Property Name | Select-Object -First 1).Name + ":"
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
} else {
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
}

# Compare free space before and after. Other disk activity can affect this estimate.
$initialFreeSpace = (Get-PSDrive -Name $selectedDrive.Substring(0,1)).Free

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

$script:StartTime = Get-Date
$timestamp = $script:StartTime.ToString("yyyyMMdd_HHmmss_fff")
$script:log = @()
$script:maintenanceResults = @()
$script:foundAndFixedCorruption = $false
$script:runDiskCleanup = $false
$script:needsRestart = $false
$script:choices = @()
$script:stepStartedAt = $null
$script:servicingStopUnconfirmed = $false

function Log {
    param([string]$message, [string]$color = "Cyan")
    $script:log += ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $message)
    Write-Host $message -ForegroundColor $color
}

function Start-YaugerStep {
    param([string]$Name)
    $script:stepStartedAt = Get-Date
    $script:log += ('[{0:HH:mm:ss}] START {1}' -f $script:stepStartedAt, $Name)
}

function Record-YaugerChoice {
    param([string]$Description)
    $entry = ('{0:HH:mm:ss} - {1}' -f (Get-Date), $Description)
    $script:choices += $entry
    $script:log += "CHOICE $entry"
}

# Record each task once, including skipped and interrupted operations.
function Add-MaintenanceResult {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'SKIP', 'CHECK')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Summary,
        [string]$Action = ''
    )
    $seconds = if ($null -ne $script:stepStartedAt) {
        [math]::Round(((Get-Date) - $script:stepStartedAt).TotalSeconds, 1)
    } else { $null }
    $script:maintenanceResults += [PSCustomObject]@{
        Name = $Name
        Status = $Status
        Summary = $Summary
        Action = $Action
        DurationSeconds = $seconds
    }
    $script:log += ('[{0:HH:mm:ss}] RESULT [{1}] {2} - {3} (step elapsed: {4} sec)' -f (Get-Date), $Status, $Name, $Summary, $seconds)
    if ($Action) { $script:log += "FOLLOW-UP $Name - $Action" }
}

# Keep the decisions and summary first. The same file carries full task details afterward.
function Format-YaugerMaintenanceReport {
    param(
        [object[]]$Results = @(),
        [datetime]$StartedAt,
        [datetime]$FinishedAt,
        [string]$ComputerName = 'Unknown',
        [string]$Drive = 'Unknown',
        [string]$SpaceFreed = 'Not measured',
        [bool]$RestartRequired = $false,
        [string[]]$Choices = @(),
        [string[]]$Details = @()
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add('YAUGERAIO 1.5.3 | WINDOWS MAINTENANCE REPORT')
    [void]$lines.Add('=============================================')
    [void]$lines.Add(('Computer: ' + $ComputerName))
    [void]$lines.Add(('Started:  ' + $StartedAt.ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$lines.Add(('Finished: ' + $FinishedAt.ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$lines.Add(('Total time: ' + ([math]::Round(($FinishedAt - $StartedAt).TotalMinutes, 1)) + ' minutes (includes time spent answering prompts)'))
    [void]$lines.Add(('System drive: ' + $Drive))
    [void]$lines.Add(('Change in available drive space: ' + $SpaceFreed))
    [void]$lines.Add('This is a before-and-after estimate, not an exact amount deleted by YaugerAIO.')
    [void]$lines.Add(('Restart requested by Windows Update: ' + $(if ($RestartRequired) { 'YES' } else { 'Not reported' })))
    [void]$lines.Add('')

    $passed = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $warnings = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    $failures = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $checks = @($Results | Where-Object { $_.Status -eq 'CHECK' }).Count
    $skipped = @($Results | Where-Object { $_.Status -eq 'SKIP' }).Count

    [void]$lines.Add('AT A GLANCE')
    [void]$lines.Add('-----------')
    if ($failures -gt 0) {
        [void]$lines.Add('Some maintenance steps failed. Please review the next steps.')
    } elseif ($warnings -gt 0) {
        [void]$lines.Add('Some items still need attention.')
    } elseif ($checks -gt 0) {
        [void]$lines.Add('Some results could not be confirmed.')
    } elseif ($passed -gt 0) {
        [void]$lines.Add('No problems were reported by the completed checks.')
    } else {
        [void]$lines.Add('No completed checks were recorded.')
    }
    [void]$lines.Add(("Passed: {0} | Warnings: {1} | Failed: {2} | Unverified: {3} | Skipped: {4}" -f $passed,$warnings,$failures,$checks,$skipped))
    [void]$lines.Add('')

    [void]$lines.Add('WHAT TO DO NEXT')
    [void]$lines.Add('---------------')
    $followUps = @($Results | Where-Object { $_.Action -and $_.Status -in @('WARN', 'FAIL', 'CHECK', 'SKIP') })
    $number = 0
    foreach ($item in $followUps) {
        $number++
        [void]$lines.Add(('{0}. [{1}] {2}' -f $number, $item.Status, $item.Name))
        [void]$lines.Add(('   ' + (($item.Action -replace '[\r\n]+', ' ').Trim())))
    }
    if ($RestartRequired) {
        $number++
        [void]$lines.Add(('{0}. Save your work and restart Windows to finish updates.' -f $number))
    }
    if ($number -eq 0) { [void]$lines.Add('No specific follow-up action was recorded.') }
    [void]$lines.Add('')

    [void]$lines.Add('YOUR CHOICES')
    [void]$lines.Add('------------')
    if ($Choices.Count -gt 0) {
        foreach ($choice in $Choices) { [void]$lines.Add((' - ' + $choice)) }
    } else { [void]$lines.Add('No interactive choices were recorded.') }
    [void]$lines.Add('')

    [void]$lines.Add('EACH MAINTENANCE STEP')
    [void]$lines.Add('---------------------')
    foreach ($item in $Results) {
        $summary = ([string]$item.Summary -replace '[\r\n]+', ' ').Trim()
        $duration = if ($null -ne $item.DurationSeconds -and $item.DurationSeconds -ne '') {
            (' (about {0} seconds from step start)' -f $item.DurationSeconds)
        } else { '' }
        [void]$lines.Add(('[{0}] {1}{2}' -f $item.Status, $item.Name, $duration))
        [void]$lines.Add(('    ' + $summary))
    }
    if ($Results.Count -eq 0) { [void]$lines.Add('No maintenance results were recorded.') }
    [void]$lines.Add('')

    [void]$lines.Add('STATUS GUIDE')
    [void]$lines.Add('------------')
    [void]$lines.Add('PASS: reported success; WARN: needs attention; FAIL: did not finish successfully.')
    [void]$lines.Add('CHECK: outcome could not be confirmed; SKIP: not run or interrupted.')
    [void]$lines.Add('An interrupted Windows scan or repair may leave unfinished Windows servicing work.')
    [void]$lines.Add('A successful scan does not mean every part of the computer is healthy.')
    [void]$lines.Add('')

    [void]$lines.Add('DETAILED ACTIVITY AND WINDOWS OUTPUT')
    [void]$lines.Add('------------------------------------')
    [void]$lines.Add('For troubleshooting: command messages and recorded activity from this run.')
    [void]$lines.Add('Progress display updates are not repeated here; final outcomes and tool output are.')
    if ($Details.Count -eq 0) { [void]$lines.Add('No additional activity was recorded.') }
    foreach ($detail in $Details) {
        if (-not [string]::IsNullOrWhiteSpace($detail)) { [void]$lines.Add($detail) }
    }
    return ($lines -join [Environment]::NewLine)
}

# Save one complete report on the Desktop, or fall back to Documents or TEMP.
function Save-YaugerMaintenanceReport {
    param(
        [Parameter(Mandatory = $true)][string]$ReportText,
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [string[]]$Destinations = @(
            [Environment]::GetFolderPath('Desktop'),
            [Environment]::GetFolderPath('MyDocuments'),
            [System.IO.Path]::GetTempPath()
        )
    )
    foreach ($folder in $Destinations) {
        if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
        $reportPath = Join-Path $folder ('YaugerAIO_Report_' + $Timestamp + '.txt')
        try {
            Set-Content -LiteralPath $reportPath -Value $ReportText -Encoding UTF8 -ErrorAction Stop
            return $reportPath
        } catch {
            # A redirected Desktop or missing permissions can block a write; try the next folder.
            Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
        }
    }
    throw 'Unable to save the maintenance report to Desktop, Documents, or the temporary directory.'
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

# System checks
function Check-DiskSpace {
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'"
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        Log "${selectedDrive} Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
        if ($freePercentage -lt 10) {
            Add-MaintenanceResult -Name 'System disk space' -Status WARN -Summary "$freeGB GB free ($freePercentage%) on $selectedDrive." -Action 'Free up space or expand the system drive; target at least 10% free space.'
        } else {
            Add-MaintenanceResult -Name 'System disk space' -Status PASS -Summary "$freeGB GB free out of $totalGB GB on $selectedDrive ($freePercentage%)."
        }
    } catch {
        Add-MaintenanceResult -Name 'System disk space' -Status FAIL -Summary 'Could not retrieve drive capacity.' -Action 'Check Disk Management and review the technical log.'
        Log "Failed to retrieve disk space info for ${selectedDrive}: $_" "Red"
    }
}

function Check-CPUUsage {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time'
        $usage = [math]::Round($cpu.CounterSamples.CookedValue, 2)
        Log "CPU Usage: $usage%" "Cyan"
        if ($usage -ge 90) {
            Add-MaintenanceResult -Name 'CPU usage' -Status WARN -Summary "High CPU usage at $usage% during this sample." -Action 'Check Task Manager for CPU-intensive processes if performance is slow.'
        } else {
            Add-MaintenanceResult -Name 'CPU usage' -Status PASS -Summary "CPU usage was $usage% at the time of sampling."
        }
    } catch {
        Add-MaintenanceResult -Name 'CPU usage' -Status FAIL -Summary 'Unable to measure CPU usage.' -Action 'Check Windows Performance Monitor and the technical log.'
        Log "Failed to retrieve CPU usage: $_" "Red"
    }
}

function Flush-DNSCache {
    try {
        Write-Host "Flushing DNS cache..." -ForegroundColor Cyan
        $before = (Get-DnsClientCache).Count
        ipconfig /flushdns | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "ipconfig /flushdns exited with code $LASTEXITCODE"
        }
        $after = (Get-DnsClientCache).Count
        $flushed = $before - $after
        Write-Host "✔ DNS cache flushed." -ForegroundColor Cyan
        Write-Host "Entries removed: $flushed" -ForegroundColor Cyan
        Add-MaintenanceResult -Name 'DNS cache' -Status PASS -Summary 'ipconfig /flushdns completed successfully.'
        Write-Host ""
    } catch {
        Add-MaintenanceResult -Name 'DNS cache' -Status FAIL -Summary 'Unable to confirm that the DNS cache was flushed.' -Action 'Retry ipconfig /flushdns in an elevated command prompt if name resolution is failing.'
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
        if ($percentUsed -gt 80) {
            Add-MaintenanceResult -Name 'Memory usage' -Status WARN -Summary "$used of $total GB in use ($percentUsed%) at sampling time." -Action 'Review memory-heavy apps in Task Manager if the PC is slow.'
        } else {
            Add-MaintenanceResult -Name 'Memory usage' -Status PASS -Summary "$used of $total GB in use ($percentUsed%) at sampling time."
        }
        Start-Sleep -Seconds 2
        if ($percentUsed -gt 80) {
            Log "Random Access Memory is currently utilized above 80%. Please check and see if you have 14 million tabs open." "Yellow"
            Start-Sleep -Seconds 5
        }
    } catch {
        Add-MaintenanceResult -Name 'Memory usage' -Status FAIL -Summary 'Could not measure physical memory usage.' -Action 'Review Task Manager memory usage and the technical log.'
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
                    Add-MaintenanceResult -Name "GPU driver: $($gpu.Name)" -Status WARN -Summary "Driver date is approximately $([math]::Round($monthsDifference)) months old; this does not prove an update is available." -Action 'Check the GPU vendor support page for a newer recommended driver if you have graphics issues.'
                    Log "GPU Driver release more than 6 months ago. Please check your GPU Vendor for driver updates." "Red"
                }
                elseif ($monthsDifference -ge 3) {
                    Add-MaintenanceResult -Name "GPU driver: $($gpu.Name)" -Status CHECK -Summary "Driver date is approximately $([math]::Round($monthsDifference)) months old." -Action 'If you are troubleshooting graphics problems, compare the installed driver with the vendor release.'
                    Log "GPU Driver release more than 3 months ago. Please check your GPU Vendor for driver updates." "Yellow"
                }
                else {
                    Add-MaintenanceResult -Name "GPU driver: $($gpu.Name)" -Status PASS -Summary "Installed driver date is within the last three months."
                    Log "GPU Driver release is within the last 3 months." "Cyan"
                }
            }
            else {
                Add-MaintenanceResult -Name "GPU driver: $($gpu.Name)" -Status CHECK -Summary 'Driver date was not available.' -Action 'Review graphics driver details in Device Manager if necessary.'
                Log "GPU Driver release date not available." "Yellow"
            }
        }
        Write-Host ""
    } catch {
        Add-MaintenanceResult -Name 'GPU driver checks' -Status FAIL -Summary 'Could not query installed graphics drivers.' -Action 'Inspect graphics adapters in Device Manager.'
        Log "Failed to retrieve GPU driver info: $_" "Red"
    }
}

function Check-SystemUptime {
    try {
        $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
        $days = [math]::Round($uptime.TotalDays, 2)
        Log "System Uptime: $days days" "Cyan"
        if ($days -ge 7) {
            Add-MaintenanceResult -Name 'System uptime' -Status CHECK -Summary "Windows has been running for $days days." -Action 'Restart when convenient if updates require it or the system is misbehaving.'
        } else {
            Add-MaintenanceResult -Name 'System uptime' -Status PASS -Summary "Windows has been running for $days days."
        }
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
        Add-MaintenanceResult -Name 'System uptime' -Status FAIL -Summary 'Could not determine the last Windows boot time.' -Action 'Check system information or Event Viewer.'
        Log "Failed to retrieve system uptime: $_" "Red"
    }
}

function Install-WindowsUpdates {
    Write-Host "Checking for Windows updates..." -ForegroundColor Cyan
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'")
        if ($searchResult.Updates.Count -eq 0) {
            Write-Host "No applicable pending software updates found." -ForegroundColor Green
            Add-MaintenanceResult -Name 'Windows Update' -Status PASS -Summary 'No pending software updates returned by Windows Update search.'
            return
        }
        $updates = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            Write-Host "Update: $($update.Title)" -ForegroundColor Gray
            $script:log += "Windows Update found: $($update.Title)"
            if (-not $update.EulaAccepted) { $update.AcceptEula() | Out-Null }
            [void]$updates.Add($update)
        }
        Write-Host "Downloading updates..." -ForegroundColor Cyan
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updates
        $downloadResult = $downloader.Download()
        $script:log += 'Windows Update download result code: ' + $downloadResult.ResultCode
        if ($downloadResult.ResultCode -ne 2) {
            Add-MaintenanceResult -Name 'Windows Update' -Status WARN -Summary 'Not all updates downloaded successfully; installation was not attempted.' -Action 'Open Settings > Windows Update, review errors, and retry when convenient.'
            Write-Host "Windows Update downloads were not fully successful. Installation skipped." -ForegroundColor Yellow
            return
        }
        Write-Host "Installing updates..." -ForegroundColor Cyan
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updates
        $installResult = $installer.Install()
        $script:log += 'Windows Update installation result code: ' + $installResult.ResultCode
        if ($installResult.RebootRequired) {
            $script:needsRestart = $true
            Write-Host "A restart is required to complete the update installation." -ForegroundColor Yellow
        }
        if ($installResult.ResultCode -eq 2) {
            Add-MaintenanceResult -Name 'Windows Update' -Status PASS -Summary "$($updates.Count) software update(s) were reported installed successfully."
            Write-Host "Windows Update reports successful installation." -ForegroundColor Green
        } elseif ($installResult.ResultCode -eq 3) {
            Add-MaintenanceResult -Name 'Windows Update' -Status WARN -Summary 'Windows Update completed with errors; some updates may be missing.' -Action 'Open Settings > Windows Update and review update history or retry failed updates.'
            Write-Host "Windows Update installed some updates but reported errors." -ForegroundColor Yellow
        } else {
            Add-MaintenanceResult -Name 'Windows Update' -Status FAIL -Summary "Windows Update installation returned result code $($installResult.ResultCode)." -Action 'Review Windows Update history and the technical log; retry updates through Settings.'
            Write-Host "Windows Update installation did not complete successfully." -ForegroundColor Red
        }
    } catch {
        Add-MaintenanceResult -Name 'Windows Update' -Status FAIL -Summary 'Windows Update failed or was unavailable.' -Action 'Check Windows Update in Settings, and review the technical log for details.'
        Log "Error during Windows update process: $_" "Red"
    }
}

# CheckHealth looks for component store damage before we offer a repair.
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

# Run native servicing tools separately so the console stays responsive.
# Windows controls the real progress. We only show percentages reported by the tool.
function Get-YaugerNativePercent {
    param([string]$Output)
    if ([string]::IsNullOrWhiteSpace($Output)) { return '' }
    $found = [regex]::Matches($Output, '(?<!\d)(?<value>100(?:[.,]0+)?|\d{1,2}(?:[.,]\d+)?)\s*%')
    if ($found.Count -eq 0) { return '' }
    return ($found[$found.Count - 1].Groups['value'].Value.Replace(',', '.') + '%')
}

function Read-YaugerSharedText {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::Default, $true)
        return $reader.ReadToEnd()
    } catch {
        return ''
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-YaugerSpacePressed {
    try {
        if (-not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
            return ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Spacebar)
        }
    } catch { }
    return $false
}

# Killing DISM/SFC can leave unfinished servicing work. Never claim a skip was a successful scan.
function Stop-YaugerNativeProcess {
    param([System.Diagnostics.Process]$Process)
    try {
        if (-not $Process.HasExited) {
            & taskkill.exe /PID $Process.Id /T /F 2>&1 | Out-Null
        }
    } catch { }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction Stop }
        [void]$Process.WaitForExit(3000)
        $Process.Refresh()
        return $Process.HasExited
    } catch {
        return $false
    }
}

function Invoke-YaugerNativeTask {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$NextStep,
        [scriptblock]$SkipRequested = { Test-YaugerSpacePressed }
    )
    $outFile = Join-Path ([IO.Path]::GetTempPath()) ('YaugerAIO_' + [guid]::NewGuid().ToString('N') + '.out')
    $errFile = Join-Path ([IO.Path]::GetTempPath()) ('YaugerAIO_' + [guid]::NewGuid().ToString('N') + '.err')
    $startedAt = Get-Date
    $process = $null
    $state = 'Failed'
    $exitCode = $null
    $output = ''
    $detail = ''
    $stopConfirmed = $true
    Write-Host "$Label can sometimes pause while Windows works. The percentage may not change for a while." -ForegroundColor Yellow
    Write-Host "Press SPACE to stop this task and continue to $NextStep. Stopping a repair may leave work unfinished." -ForegroundColor Yellow
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $state = 'Completed'
        $lastDisplay = ''
        do {
            $process.Refresh()
            if ($process.HasExited) { break }
            if (& $SkipRequested) {
                $state = 'Skipped'
                Write-Host ""
                Write-Host "Stopping $Label. Windows servicing may need time to settle..." -ForegroundColor Yellow
                $stopConfirmed = Stop-YaugerNativeProcess -Process $process
                if (-not $stopConfirmed) { $state = 'StopUnconfirmed' }
                break
            }
            $captured = Read-YaugerSharedText -Path $outFile
            $percent = Get-YaugerNativePercent -Output $captured
            $elapsedText = ('{0:hh\:mm\:ss}' -f ((Get-Date) - $startedAt))
            $progress = if ($percent) { "reported $percent" } else { 'running' }
            $line = "$Label - $progress | $elapsedText | SPACE: skip to $NextStep"
            if ($line -ne $lastDisplay) {
                Write-Host ("`r{0,-100}" -f $line) -NoNewline -ForegroundColor Cyan
                $lastDisplay = $line
            }
            Start-Sleep -Milliseconds 400
        } while ($true)
        Write-Host ""
        if ($state -eq 'Completed') {
            $process.Refresh()
            $exitCode = $process.ExitCode
        }
        $output = Read-YaugerSharedText -Path $outFile
        $detail = Read-YaugerSharedText -Path $errFile
    } catch {
        $state = 'Failed'
        $detail += "YaugerAIO could not run or monitor ${Label}: $_"
        if ($null -ne $process) { [void](Stop-YaugerNativeProcess -Process $process) }
    } finally {
        foreach ($file in @($outFile, $errFile)) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $process) { $process.Dispose() }
    }
    $elapsed = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 1)
    $script:log += "$Label | outcome: $state | elapsed: $elapsed seconds | exit code: $exitCode"
    if ($state -in @('Skipped', 'StopUnconfirmed')) {
        $script:log += "$Label | Spacebar skip requested; process stopped: $stopConfirmed. Independent Windows servicing may continue."
    }
    if ($output) { $script:log += "$Label | captured command output:" + [Environment]::NewLine + $output }
    if ($detail) { $script:log += "$Label | additional command output:" + [Environment]::NewLine + $detail }
    return [PSCustomObject]@{
        State = $state
        ExitCode = $exitCode
        Output = ($output + [Environment]::NewLine + $detail)
        ElapsedSeconds = $elapsed
    }
}

# The initial check is quick. Ask before starting the potentially lengthy repair.
# The initial check can also stall, so it uses the same monitored runner.
function Run-DISMCheckHealth {
    Write-Host "Checking Windows repair files (DISM /CheckHealth)..." -ForegroundColor Cyan
    try {
        $task = Invoke-YaugerNativeTask -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/CheckHealth') -Label 'DISM health check' -NextStep 'SFC scan'
        if ($task.State -in @('Skipped', 'StopUnconfirmed')) {
            if ($task.State -eq 'StopUnconfirmed') { $script:servicingStopUnconfirmed = $true }
            Add-MaintenanceResult -Name 'Windows repair check' -Status $(if ($task.State -eq 'Skipped') { 'SKIP' } else { 'CHECK' }) -Summary 'DISM health check interrupted by Spacebar; health was not verified.' -Action 'If Windows repairs still appear active, wait for them to settle before retrying.'
            return
        }
        if ($task.State -ne 'Completed') {
            Add-MaintenanceResult -Name 'Windows repair check' -Status FAIL -Summary 'Windows repair check could not be started or monitored.' -Action 'Check the detailed history in the report.'
            return
        }
        $status = Get-DISMCheckHealthStatus -Output $task.Output -ExitCode $task.ExitCode
        $script:log += "DISM /CheckHealth interpretation: $status"
        switch ($status) {
            'Healthy' {
                Add-MaintenanceResult -Name 'Windows repair check' -Status PASS -Summary 'Windows did not report damage to its repair files.'
                Write-Host "Windows repair files look healthy. Moving on to SFC." -ForegroundColor Green
            }
            'Repairable' {
                Add-MaintenanceResult -Name 'Windows repair check' -Status WARN -Summary 'Windows found repairable damage.' -Action 'Check the optional repair result below, or rerun YaugerAIO to attempt repair.'
                Write-Host "Windows found damage it may be able to repair." -ForegroundColor Yellow
                Write-Host "Try DISM repair now? This can take 20-30 minutes or longer and may need internet access. (Y/N)" -ForegroundColor Yellow
                $choice = [Console]::ReadKey($true)
                if ($choice.KeyChar.ToString().ToUpperInvariant() -eq 'Y') {
                    Record-YaugerChoice 'DISM repair offered: accepted.'
                    Start-YaugerStep 'DISM RestoreHealth repair'
                    Invoke-DISMRestoreHealth
                } else {
                    Record-YaugerChoice 'DISM repair offered: declined; repair skipped.'
                    Add-MaintenanceResult -Name 'Windows repair' -Status SKIP -Summary 'You chose not to attempt the optional repair.'
                    Write-Host "Windows repair skipped. Continuing with SFC." -ForegroundColor Yellow
                }
            }
            'NotRepairable' {
                Add-MaintenanceResult -Name 'Windows repair check' -Status FAIL -Summary 'Windows reported damage that the built-in repair cannot fix.' -Action 'Have a technician review the DISM details and Windows recovery options.'
                Write-Host "Windows reports damage that DISM cannot repair automatically." -ForegroundColor Red
            }
            'Failed' {
                Add-MaintenanceResult -Name 'Windows repair check' -Status FAIL -Summary "The Windows repair check failed (DISM exit code $($task.ExitCode))." -Action 'Review the detailed history and have a technician investigate Windows servicing.'
            }
            default {
                Add-MaintenanceResult -Name 'Windows repair check' -Status CHECK -Summary 'Windows repair check finished, but its result was not understood.' -Action 'Review the captured DISM output before assuming Windows is healthy.'
            }
        }
    } catch {
        Add-MaintenanceResult -Name 'Windows repair check' -Status FAIL -Summary 'The Windows repair check or prompt failed.' -Action 'Review the detailed activity in the report.'
        Log "DISM health check failed: $_" "Red"
    }
    Write-Host ""
}

# A zero exit code is not enough to claim the repair worked; recheck Windows afterward.
function Get-DISMRepairVerificationStatus {
    param(
        [int]$RepairExitCode,
        [string]$CheckStatus
    )
    if ($RepairExitCode -ne 0) { return 'Failed' }
    if ($CheckStatus -eq 'Healthy') { return 'Repaired' }
    if ($CheckStatus -in @('Repairable', 'NotRepairable')) { return 'Unresolved' }
    return 'Unverified'
}

function Invoke-DISMRestoreHealth {
    Write-Host "Repairing Windows files with DISM /RestoreHealth..." -ForegroundColor Cyan
    try {
        $task = Invoke-YaugerNativeTask -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth') -Label 'DISM repair' -NextStep 'SFC scan'
        if ($task.State -in @('Skipped', 'StopUnconfirmed')) {
            if ($task.State -eq 'StopUnconfirmed') { $script:servicingStopUnconfirmed = $true }
            Add-MaintenanceResult -Name 'Windows repair' -Status $(if ($task.State -eq 'Skipped') { 'SKIP' } else { 'CHECK' }) -Summary 'DISM repair was interrupted; any repairs are unverified.' -Action 'Allow Windows servicing to finish before attempting repairs again.'
            return
        }
        if ($task.State -ne 'Completed' -or $task.ExitCode -ne 0) {
            Add-MaintenanceResult -Name 'Windows repair' -Status FAIL -Summary 'DISM could not finish the repair successfully.' -Action 'Review the captured DISM output and check Windows Update or consult a technician.'
            return
        }

        Write-Host "Checking whether Windows now reports its repair files as healthy..." -ForegroundColor Cyan
        $verify = Invoke-YaugerNativeTask -FilePath 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/CheckHealth') -Label 'DISM repair verification' -NextStep 'SFC scan'
        if ($verify.State -in @('Skipped', 'StopUnconfirmed')) {
            if ($verify.State -eq 'StopUnconfirmed') { $script:servicingStopUnconfirmed = $true }
            Add-MaintenanceResult -Name 'Windows repair' -Status CHECK -Summary 'DISM repair finished, but you interrupted the follow-up check. Repair was not confirmed.' -Action 'Allow Windows servicing to settle, then check Windows health again.'
            return
        }
        $checkStatus = if ($verify.State -eq 'Completed') {
            Get-DISMCheckHealthStatus -Output $verify.Output -ExitCode $verify.ExitCode
        } else { 'Unknown' }
        $result = Get-DISMRepairVerificationStatus -RepairExitCode $task.ExitCode -CheckStatus $checkStatus
        switch ($result) {
            'Repaired' {
                Add-MaintenanceResult -Name 'Windows repair' -Status PASS -Summary 'DISM attempted repair and a second Windows check reported no remaining damage.'
                Write-Host "Windows reports that the repair worked. SFC will check system files next." -ForegroundColor Green
            }
            'Unresolved' {
                Add-MaintenanceResult -Name 'Windows repair' -Status WARN -Summary 'DISM finished but Windows still reports damage.' -Action 'Review the detailed activity and ask a technician to check Windows servicing.'
            }
            default {
                Add-MaintenanceResult -Name 'Windows repair' -Status CHECK -Summary 'DISM finished, but Windows could not confirm the repair result.' -Action 'Review the detailed DISM output before assuming Windows is repaired.'
            }
        }
    } catch {
        Add-MaintenanceResult -Name 'Windows repair' -Status FAIL -Summary 'The repair or its follow-up check could not finish.' -Action 'Review the detailed activity in the report.'
        Log "DISM /RestoreHealth could not finish: $_" "Red"
    }
}

# SFC messages vary by Windows version and language. Unknown output isn't a pass.
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
    Write-Host "Checking Windows system files with SFC..." -ForegroundColor Cyan
    try {
        $task = Invoke-YaugerNativeTask -FilePath 'sfc.exe' -Arguments @('/scannow') -Label 'SFC scan' -NextStep 'Windows Update'
        if ($task.State -in @('Skipped', 'StopUnconfirmed')) {
            if ($task.State -eq 'StopUnconfirmed') { $script:servicingStopUnconfirmed = $true }
            Add-MaintenanceResult -Name 'SFC system files' -Status $(if ($task.State -eq 'Skipped') { 'SKIP' } else { 'CHECK' }) -Summary 'System file scan interrupted by Spacebar; the result is unknown.' -Action 'Windows may have unfinished servicing work. Wait until it settles before retrying.'
            return
        }
        if ($task.State -ne 'Completed') {
            Add-MaintenanceResult -Name 'SFC system files' -Status FAIL -Summary 'SFC could not start or be monitored.' -Action 'Review the detailed history in the report.'
            return
        }
        $status = Get-SFCScanStatus -Output $task.Output -ExitCode $task.ExitCode
        $script:log += "SFC scan interpretation: $status"
        switch ($status) {
            'Healthy' {
                Add-MaintenanceResult -Name 'SFC system files' -Status PASS -Summary 'Windows found no damaged protected system files.'
            }
            'Repaired' {
                Add-MaintenanceResult -Name 'SFC system files' -Status PASS -Summary 'Windows reports that damaged system files were repaired.'
            }
            'Unresolved' {
                Add-MaintenanceResult -Name 'SFC system files' -Status WARN -Summary 'Windows could not repair some system files.' -Action 'Review the report details and consider checking Windows repairs again.'
            }
            'Failed' {
                Add-MaintenanceResult -Name 'SFC system files' -Status FAIL -Summary "System file scan could not finish (SFC exit code $($task.ExitCode))." -Action 'Review the captured Windows scan output.'
            }
            default {
                Add-MaintenanceResult -Name 'SFC system files' -Status CHECK -Summary 'System file scan finished but its result was not recognized.' -Action 'Review the captured SFC output before assuming all files are healthy.'
            }
        }
    } catch {
        Add-MaintenanceResult -Name 'SFC system files' -Status FAIL -Summary 'The system file scan could not finish.' -Action 'Review the detailed activity in the report.'
        Log "SFC scan could not finish: $_" "Red"
    }
}

# Cleanup tasks
function Clear-BrowserCaches {
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        if (Test-Path $chromePath) {
            Remove-Item "$chromePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "Attempted Chrome default-profile cache cleanup; locked files may remain." "Cyan"
        } else {
            Log "Chrome default-profile cache folder not found; other profiles were not checked." "Cyan"
        }
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
        if (Test-Path $edgePath) {
            Remove-Item "$edgePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "Attempted Edge default-profile cache cleanup; locked files may remain." "Cyan"
        } else {
            Log "Edge default-profile cache folder not found; other profiles were not checked." "Cyan"
        }
        $bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
        if (Test-Path $bravePath) {
            Remove-Item "$bravePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "Attempted Brave default-profile cache cleanup; locked files may remain." "Cyan"
        } else {
            Log "Brave default-profile cache folder not found; other profiles were not checked." "Cyan"
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
            Log "Attempted Opera cache cleanup; some folders or locked files may have been skipped." "Cyan"
        } else {
            Log "Opera cache folders not found in the checked profile locations." "Cyan"
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
            Log "Attempted Firefox profile cache cleanup; some cache folders or locked files may have been skipped." "Cyan"
        } else {
            Log "Firefox profile cache folders not found in the checked location." "Cyan"
        }
        Add-MaintenanceResult -Name 'Browser caches' -Status CHECK -Summary 'Tried to clear selected browser caches, but some files and profiles may not have been checked.' -Action 'Close browsers before running YaugerAIO again if you still need to clear their caches.'
    } catch {
        Add-MaintenanceResult -Name 'Browser caches' -Status FAIL -Summary 'Browser cache cleanup encountered an error.' -Action 'Close running browsers, then retry; see the technical log.'
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
        if ($process.ExitCode -eq 0) {
            Add-MaintenanceResult -Name 'Disk Cleanup' -Status CHECK -Summary 'Disk Cleanup exited successfully; actual cleanup depends on its saved configuration.' -Action 'If storage did not improve, review Disk Cleanup settings and select cleanup categories manually.'
            Log "✔ Disk Cleanup executed on ${selectedDrive}." "Cyan"
        } else {
            Add-MaintenanceResult -Name 'Disk Cleanup' -Status FAIL -Summary "Disk Cleanup exited with code $($process.ExitCode)." -Action 'Open Windows Disk Cleanup and inspect the selected cleanup profile.'
            Log "Disk Cleanup exited with code $($process.ExitCode)." "Red"
        }
        Write-Host ""
    } catch {
        Add-MaintenanceResult -Name 'Disk Cleanup' -Status FAIL -Summary 'Disk Cleanup failed to launch or complete.' -Action 'Run Disk Cleanup manually from Windows.'
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

        # Count hidden files too, but don't count directory entries as files.
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
    $script:tempCleanupOutcome = 'CHECK'
    try {
        $tempPath = $env:TEMP
        if ([string]::IsNullOrWhiteSpace($tempPath) -or -not (Test-Path -LiteralPath $tempPath -PathType Container)) {
            $script:tempCleanupOutcome = 'SKIP'
            Log "Skipped Windows Temp cleanup: TEMP directory is unavailable." "Yellow"
            return
        }

        $resolvedPath = (Resolve-Path -LiteralPath $tempPath -ErrorAction Stop).ProviderPath
        $pathRoot = [System.IO.Path]::GetPathRoot($resolvedPath)
        if ([string]::IsNullOrWhiteSpace($pathRoot) -or $resolvedPath.TrimEnd('\', '/') -eq $pathRoot.TrimEnd('\', '/')) {
            $script:tempCleanupOutcome = 'FAIL'
            Log "Skipped Windows Temp cleanup: TEMP must not be a filesystem root." "Red"
            return
        }

        $tempDirectory = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
        if (($tempDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $script:tempCleanupOutcome = 'FAIL'
            Log "Skipped Windows Temp cleanup: TEMP must not be a symbolic link or junction." "Red"
            return
        }

        $cleanupErrors = @()
        $skippedLinks = 0
        foreach ($item in Get-ChildItem -LiteralPath $resolvedPath -Force -ErrorAction Stop) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $skippedLinks++
                Log "Skipped link or junction in Windows Temp: $($item.Name)" "Yellow"
                continue
            }
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +cleanupErrors
        }
        if ($cleanupErrors.Count -gt 0 -or $skippedLinks -gt 0) {
            $script:tempCleanupOutcome = 'WARN'
            Log "Windows Temp cleanup could not remove $($cleanupErrors.Count) item(s); skipped $skippedLinks link(s)." "Yellow"
        } else {
            $script:tempCleanupOutcome = 'PASS'
        }
    } catch {
        $script:tempCleanupOutcome = 'FAIL'
        Log "Failed to clear Windows Temp files: $_" "Red"
    }
}

# Wrap longer console messages without splitting words.
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

# Guided maintenance run
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
Write-Host "- Check Windows repair files; offer an optional repair if damage is found." -ForegroundColor White
Write-Host "- Scan protected Windows files and repair what Windows can." -ForegroundColor White
Write-Host "- Check for and install Windows Updates." -ForegroundColor White
Write-Host "" -ForegroundColor White

Focus-Console
Start-Sleep -Seconds 1

Write-Host "Please close all applications and browsers for a clean, smooth Cache Smash.™" -ForegroundColor Yellow
Start-Sleep -Seconds 2
Write-Host "Please press Enter to begin." -ForegroundColor Yellow
[void][System.Console]::ReadKey($true)
Record-YaugerChoice 'Started maintenance after the initial confirmation.'
Write-Host ""

# Disk Cleanup (optional)
Start-YaugerStep 'Disk Cleanup'
Write-Host "Would you like to run Disk Cleanup? (Y/N)" -ForegroundColor Yellow
$key = [Console]::ReadKey($true)
if ($key.KeyChar.ToString().ToUpper() -eq "Y") {
    $script:runDiskCleanup = $true
    Record-YaugerChoice 'Disk Cleanup: accepted.'
    Log "✔ User has opted to run Disk Cleanup." "Yellow"
    Run-CleanMgr
} else {
    Record-YaugerChoice 'Disk Cleanup: declined.'
    Add-MaintenanceResult -Name 'Disk Cleanup' -Status SKIP -Summary 'Skipped at user request.'
    Log "✖ User has opted not to run Disk Cleanup." "Yellow"
}
Write-Host ""

# Windows Temp cleanup (optional)
Start-YaugerStep 'Windows temporary-file cleanup'
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
        Record-YaugerChoice "Windows Temp cleanup: accepted. About $displaySize measured before cleanup."
        # Offer to close apps that may be holding temp files open.
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
                Record-YaugerChoice 'Close running applications that may lock temporary files: accepted.'
                foreach ($app in $tempLockingApps) {
                    Write-Host "Closing $($app.FriendlyName)..." -ForegroundColor Cyan
                    try {
                        Get-Process | Where-Object { $_.ProcessName.ToLower() -eq $app.ProcessName } | Stop-Process -Force -ErrorAction Stop
                        $script:log += "Requested application closure: $($app.FriendlyName)"
                    } catch {
                        Log "Could not close $($app.FriendlyName): $_" 'Yellow'
                    }
                }
                Start-Sleep -Seconds 2
            } else {
                Record-YaugerChoice 'Close running applications that may lock temporary files: declined.'
                Log "✖ User chose not to close running applications. Proceeding to clear available temp files." "Yellow"
            }
        }
        Clear-WindowsTemp
        $afterTempSize = Get-WindowsTempSize
        $tempDifference = [math]::Round(($tempSize - $afterTempSize), 2)
        $tempChangeText = "TEMP contained about $tempSize MB before and $afterTempSize MB after; change $tempDifference MB (estimate)."
        $script:log += $tempChangeText
        switch ($script:tempCleanupOutcome) {
            'PASS' {
                Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status PASS -Summary "Cleanup reported no deletion errors. $tempChangeText"
                Log "✔ Windows Temp cleanup completed." "Cyan"
            }
            'WARN' {
                Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status WARN -Summary "Some temp files or links were skipped. $tempChangeText" -Action 'Close apps using temporary files and retry if storage remains low.'
                Log "Windows Temp cleanup was only partially completed." "Yellow"
            }
            'SKIP' {
                Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status SKIP -Summary 'TEMP directory was unavailable; no files were deleted.'
            }
            default {
                Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status FAIL -Summary 'Cleanup failed or was blocked for safety.' -Action 'Inspect TEMP path and technical log; do not manually delete unknown directories.'
                Log "Windows Temp cleanup was not completed." "Red"
            }
        }
    } else {
        Record-YaugerChoice "Windows Temp cleanup: declined (about $displaySize available)."
        Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status SKIP -Summary 'User declined temporary-file cleanup.'
        Log "✖ User chose not to clear Windows Temp files." "Yellow"
    }
} else {
    Record-YaugerChoice 'Windows Temp cleanup: not offered because no removable size was measured.'
    Add-MaintenanceResult -Name 'Windows Temp cleanup' -Status SKIP -Summary 'No removable TEMP file size was measured, or the directory was unavailable.'
    Log "No Windows Temp files were measured for cleanup." "Cyan"
}
Write-Host ""

# Check free disk space.
Start-YaugerStep 'Disk space'
Check-DiskSpace
# Sample CPU usage.
Start-YaugerStep 'CPU usage'
Check-CPUUsage
# Flush the DNS resolver cache.
Start-YaugerStep 'DNS cache flush'
Flush-DNSCache
# Sample memory usage.
Start-YaugerStep 'Memory usage'
Check-RAMUsage


Write-Host ""

# Check the installed graphics drivers.
Start-YaugerStep 'Graphics drivers'
Check-GPUDrivers
Write-Host ""  # Blank line between GPU and System Uptime
# Check how long Windows has been running.
Start-YaugerStep 'Windows uptime'
Check-SystemUptime
Write-Host ""  # Blank line between uptime alerts and Cache Smash

# Original Cache Smash animation.
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

# Try to clear browser caches.
Start-YaugerStep 'Browser cache cleanup'
Clear-BrowserCaches

# Explain the DISM check before it starts.
Write-Host ""
Write-Host "We'll check Windows repair files and offer to fix any repairable damage found." -ForegroundColor Yellow
Write-Host "A repair only starts if you agree to it; it can take a while." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Write-Host ""

# Check component store health with DISM.
Start-YaugerStep 'DISM health check'
Run-DISMCheckHealth

Write-Host ""  

# Run the Windows system file check.
if ($script:servicingStopUnconfirmed) {
    Add-MaintenanceResult -Name 'SFC system files' -Status SKIP -Summary 'Skipped for safety because a previous DISM process may still be running.'
} else {
    Start-YaugerStep 'SFC system file scan'
    Run-SFCScan
}

Write-Host ""  

# Check Windows Update and attempt installation.
if ($script:servicingStopUnconfirmed) {
    Add-MaintenanceResult -Name 'Windows Update' -Status SKIP -Summary 'Skipped for safety because a Windows servicing process could not be confirmed stopped.'
} else {
    Start-YaugerStep 'Windows Update'
    Install-WindowsUpdates
}

# Write one report after the last maintenance step.
Write-Host ""
$spaceChangeFormatted = 'Not measured'
try {
    $finalFree = (Get-PSDrive -Name $selectedDrive.Substring(0,1) -ErrorAction Stop).Free
    $spaceChangeBytes = $finalFree - $initialFreeSpace
    $spaceChangeAbsolute = [math]::Abs($spaceChangeBytes)
    $spaceChangeUnit = if ($spaceChangeAbsolute -ge 1GB) { 'GB' } else { 'MB' }
    $spaceChangeValue = if ($spaceChangeUnit -eq 'GB') {
        [math]::Round($spaceChangeAbsolute / 1GB, 2)
    } else {
        [math]::Round($spaceChangeAbsolute / 1MB, 2)
    }
    $spaceChangeFormatted = if ($spaceChangeBytes -gt 0) {
        "$spaceChangeValue $spaceChangeUnit more free"
    } elseif ($spaceChangeBytes -lt 0) {
        "$spaceChangeValue $spaceChangeUnit less free"
    } else {
        'No change measured'
    }
} catch {
    Log "Unable to measure final disk space: $_" "Yellow"
}
Log "Change in available disk space (approximate): $spaceChangeFormatted" "Cyan"
$finishedAt = Get-Date
Log ("Total script runtime: " + ($finishedAt - $script:StartTime).ToString()) "Cyan"
Log "=============================================" "Cyan"
Log "YaugerAIO maintenance workflow completed." "Blue"

$reportText = Format-YaugerMaintenanceReport -Results $script:maintenanceResults -StartedAt $script:StartTime -FinishedAt $finishedAt -ComputerName $env:COMPUTERNAME -Drive $selectedDrive -SpaceFreed $spaceChangeFormatted -RestartRequired $script:needsRestart -Choices $script:choices -Details $script:log
try {
    $reportPath = Save-YaugerMaintenanceReport -ReportText $reportText -Timestamp $timestamp
    Write-Host ""
    Write-Host "Your complete maintenance report: $reportPath" -ForegroundColor Green
} catch {
    Write-Host "Unable to save maintenance report: $_" -ForegroundColor Red
}
Write-Host ""
$thankYouMessage = "Thanks for trying out my Windows AIO Maintenance Tool. For feature requests or bug reports, please feel welcome to reach out or open an issue at https://github.com/Graytools/YaugerAIO."
Write-Host (Wrap-Text -Text $thankYouMessage -Width 130) -ForegroundColor Blue
Write-Host ""

try {
    Stop-Transcript
} catch {
    # A transcript isn't started on every launch.
}



