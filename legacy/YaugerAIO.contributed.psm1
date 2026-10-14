# Set console buffer and window size using .NET methods for better performance
$desiredWidth = 130
$desiredHeight = 50

# Get current buffer size to ensure we don't exceed limits
$currentBuffer = $host.UI.RawUI.BufferSize

# Set window size first (must be smaller than buffer)
try {
    $windowSize = New-Object System.Management.Automation.Host.Size($desiredWidth, [Math]::Min($desiredHeight, $currentBuffer.Height))
    $host.UI.RawUI.WindowSize = $windowSize
} catch [System.Management.Automation.SetValueInvocationException] {
    # Silently continue if window size cannot be set
}

# Then set buffer size (must be larger than window)
try {
    $bufferSize = New-Object System.Management.Automation.Host.Size($desiredWidth, $desiredHeight)
    $host.UI.RawUI.BufferSize = $bufferSize
} catch [System.Management.Automation.SetValueInvocationException] {
    # Silently continue if buffer size cannot be set
}

# Set the default runspace for asynchronous handlers
$global:myRunspace = [runspace]::DefaultRunspace
[runspace]::DefaultRunspace = $global:myRunspace

# --- C# Type Definitions ---
Add-Type -AssemblyName System.Collections.Concurrent
Add-Type -AssemblyName System.Security.Cryptography

# Check if types already exist before adding them
$existingTypes = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
    ForEach-Object { $_.GetTypes() } | 
    Where-Object { $_.Name -in @('ThreadedFileProcessor', 'ThreadedHashCalculator') }

if (-not $existingTypes) {
    Add-Type @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

public class ThreadedFileProcessor {
    private readonly ConcurrentDictionary<string, (long Size, DateTime LastAccess)> _fileStats;
    private readonly ConcurrentBag<(string Path, string Error)> _errors;
    private readonly SemaphoreSlim _semaphore;
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly int _maxThreads;
    private readonly int _batchSize;

    public ThreadedFileProcessor(int maxThreads = 10, int batchSize = 1000) {
        _fileStats = new ConcurrentDictionary<string, (long Size, DateTime LastAccess)>();
        _errors = new ConcurrentBag<(string Path, string Error)>();
        _semaphore = new SemaphoreSlim(maxThreads);
        _cancellationTokenSource = new CancellationTokenSource();
        _maxThreads = maxThreads;
        _batchSize = batchSize;
    }

    public async Task ProcessFilesAsync(string[] files, Func<string, Task> processFile) {
        var batches = files.Select((file, index) => new { file, index })
                          .GroupBy(x => x.index / _batchSize)
                          .Select(g => g.Select(x => x.file).ToArray())
                          .ToArray();

        foreach (var batch in batches) {
            if (_cancellationTokenSource.Token.IsCancellationRequested) break;

            var tasks = batch.Select(async file => {
                await _semaphore.WaitAsync();
                try {
                    await processFile(file);
                }
                catch (Exception ex) {
                    _errors.Add((file, ex.Message));
                }
                finally {
                    _semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
        }
    }

    public void Cancel() {
        _cancellationTokenSource.Cancel();
    }

    public (string[] ProcessedFiles, (string Path, string Error)[] Errors) GetResults() {
        return (_fileStats.Keys.ToArray(), _errors.ToArray());
    }
}

public class ThreadedHashCalculator {
    private readonly ConcurrentDictionary<string, string> _hashes;
    private readonly SemaphoreSlim _semaphore;
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly int _maxThreads;

    public ThreadedHashCalculator(int maxThreads = 10) {
        _hashes = new ConcurrentDictionary<string, string>();
        _semaphore = new SemaphoreSlim(maxThreads);
        _cancellationTokenSource = new CancellationTokenSource();
        _maxThreads = maxThreads;
    }

    public async Task CalculateHashesAsync(string[] files) {
        var tasks = files.Select(async file => {
            await _semaphore.WaitAsync();
            try {
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(file)) {
                    var hash = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "");
                    _hashes.TryAdd(file, hash);
                }
            }
            catch { }
            finally {
                _semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
    }

    public void Cancel() {
        _cancellationTokenSource.Cancel();
    }

    public Dictionary<string, string> GetHashes() {
        return _hashes.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }
}
"@
}

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
    $quotedScriptPath = '"' + $scriptPath + '"'
    Start-Process $psCmd -Verb RunAs -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $quotedScriptPath
    exit
}
# --- Auto-Elevation Snippet End ---

# Define Next Steps for the overall workflow using a hashtable for O(1) lookup
$script:NextStepFor = @{
    'DISM' = 'SFC Scan'
    'SFC'  = 'Windows Updates'
}

$DebugDism = $false

# Global variables for scan summaries with StringBuilder for better memory management
$global:DISMSummary = New-Object System.Text.StringBuilder
$global:SFCSummary = New-Object System.Text.StringBuilder

# --- Function to Bring Console to Foreground using P/Invoke ---
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
    # Use HashSet for O(1) lookups
    $commonAppsMapping = @{
        "chrome"            = "Google Chrome"
        "firefox"           = "Mozilla Firefox"
        "msedge"            = "Microsoft Edge"
        "opera"             = "Opera"
        "brave"             = "Brave"
        "iexplore"          = "Internet Explorer"
        "outlook"           = "Microsoft Outlook"
        "winword"           = "Microsoft Word"
        "excel"             = "Microsoft Excel"
        "powerpnt"          = "Microsoft PowerPoint"
        "onenote"           = "Microsoft OneNote"
        "skype"             = "Skype"
        "teams"             = "Microsoft Teams"
        "onedrive"          = "OneDrive"
        "discord"           = "Discord"
        "slack"             = "Slack"
        "steam"             = "Steam"
        "epicgameslauncher" = "Epic Games Launcher"
        "origin"            = "Origin"
        "uplay"             = "Uplay"
        "battlenet"         = "Battle.net"
        "leagueclient"      = "League of Legends"
        "riotclient"        = "Riot Client"
        "valorant"          = "Valorant"
        "spotify"           = "Spotify"
        "itunes"            = "iTunes"
        "vlc"               = "VLC Media Player"
        "winamp"            = "Winamp"
        "pandora"           = "Pandora"
        "skypeforbusiness"  = "Skype for Business"
        "zoom"              = "Zoom"
        "teamspeak"         = "TeamSpeak"
        "minecraft"         = "Minecraft"
        "roblox"            = "Roblox"
        "fortnite"          = "Fortnite"
        "gog"               = "GOG Galaxy"
    }
    
    # Use HashSet for unique process names
    $uniqueProcesses = New-Object System.Collections.Generic.HashSet[string]
    $result = @()
    
    # Get processes in a single call and filter
    Get-Process | Where-Object { $commonAppsMapping.ContainsKey($_.ProcessName.ToLower()) } | ForEach-Object {
        $key = $_.ProcessName.ToLower()
        if ($uniqueProcesses.Add($key)) {
            $result += [PSCustomObject]@{
                ProcessName = $key
                FriendlyName = $commonAppsMapping[$key]
            }
        }
    }
    
    return $result | Sort-Object FriendlyName
}

# --- Determine Primary Drive ---
$selectedDrive = $env:SystemDrive
if (-not $selectedDrive -or -not ($selectedDrive -match "^[A-Z]:$")) {
    Write-Host "SystemDrive environment variable is not set or invalid. Determining primary drive..." -ForegroundColor Yellow
    $selectedDrive = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Sort-Object -Property Name | Select-Object -First 1).Name + ":"
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
}
else {
    Write-Host "System drive: ${selectedDrive}" -ForegroundColor White
}

# Store initial free space for accurate total space freed calculation
$initialFreeSpace = (Get-PSDrive -Name $selectedDrive.Substring(0, 1)).Free

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

$timestamp = Get-Date -Format "yyyyMMdd"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $desktopPath "YAIO_$timestamp.log"
$script:log = New-Object System.Collections.Generic.List[string]
$script:foundAndFixedCorruption = $false
$script:StartTime = Get-Date
$script:runDiskCleanup = $false
$script:needsRestart = $false

function Log {
    param([string]$message, [string]$color = "Cyan")
    $script:log.Add($message)
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
        }
        else {
            Log "No [SR] lines found in CBS.log" "Red"
        }
    }
    else {
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

# --- Error Handling and Circuit Breaker Configuration ---
$script:ErrorThreshold = 3
$script:ErrorCount = 0
$script:CircuitBreakerState = @{
    IsOpen = $false
    LastFailureTime = $null
    FailureCount = 0
    CooldownPeriod = New-TimeSpan -Minutes 5
}

function Test-CircuitBreaker {
    if ($script:CircuitBreakerState.IsOpen) {
        if ((Get-Date) - $script:CircuitBreakerState.LastFailureTime -gt $script:CircuitBreakerState.CooldownPeriod) {
            $script:CircuitBreakerState.IsOpen = $false
            $script:CircuitBreakerState.FailureCount = 0
            return $true
        }
        return $false
    }
    return $true
}

function Update-CircuitBreaker {
    param([bool]$Success)
    if (-not $Success) {
        $script:CircuitBreakerState.FailureCount++
        if ($script:CircuitBreakerState.FailureCount -ge $script:ErrorThreshold) {
            $script:CircuitBreakerState.IsOpen = $true
            $script:CircuitBreakerState.LastFailureTime = Get-Date
        }
    }
    else {
        $script:CircuitBreakerState.FailureCount = 0
    }
}

# --- Defensive Value Validation ---
function Test-ValidDrive {
    param([string]$Drive)
    if ([string]::IsNullOrWhiteSpace($Drive)) { return $false }
    if (-not ($Drive -match "^[A-Z]:$")) { return $false }
    if (-not (Test-Path $Drive)) { return $false }
    return $true
}

function Test-ValidPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path $Path)) { return $false }
    return $true
}

# --- Enhanced Logging with Error Context ---
function Log-Error {
    param(
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Operation
    )
    $errorContext = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operation = $Operation
        ErrorType = if ($ErrorRecord) { $ErrorRecord.Exception.GetType().Name } else { "Unknown" }
        Message = $Message
        StackTrace = if ($ErrorRecord) { $ErrorRecord.ScriptStackTrace } else { "No stack trace available" }
    }
    
    $errorLog = "[$($errorContext.Timestamp)] $($errorContext.Operation) - $($errorContext.ErrorType): $($errorContext.Message)"
    $script:log.Add($errorLog)
    Write-Host $errorLog -ForegroundColor Red
    
    if ($script:DebugMode) {
        Write-Host "Stack Trace: $($errorContext.StackTrace)" -ForegroundColor DarkRed
    }
}

# --- Safe Process Management ---
function Start-SafeProcess {
    param(
        [string]$FilePath,
        [string]$Arguments,
        [System.Collections.Generic.List[string]]$Output
    )
    try {
        # Check for system executables in Windows directory
        if ($FilePath -in @('dism.exe', 'sfc.exe')) {
            $systemPath = Join-Path $env:SystemRoot 'System32'
            $fullPath = Join-Path $systemPath $FilePath
            if (Test-Path $fullPath) {
                $FilePath = $fullPath
            }
        }

        if (-not (Test-Path $FilePath)) {
            throw [System.IO.FileNotFoundException]::new("Process executable not found: $FilePath")
        }

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $FilePath
        $processInfo.Arguments = $Arguments
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null

        $outputBuilder = New-Object System.Text.StringBuilder
        $errorBuilder = New-Object System.Text.StringBuilder

        while (-not $process.StandardOutput.EndOfStream) {
            $line = $process.StandardOutput.ReadLine()
            $outputBuilder.AppendLine($line) | Out-Null
            if ($Output -ne $null) {
                $Output.Add($line)
            }
        }

        while (-not $process.StandardError.EndOfStream) {
            $errorBuilder.AppendLine($process.StandardError.ReadLine()) | Out-Null
        }

        $process.WaitForExit()
        
        if ($process.ExitCode -ne 0) {
            throw [System.ComponentModel.Win32Exception]::new($process.ExitCode, "Process exited with code $($process.ExitCode)")
        }

        return @{
            Success = $true
            Output = $outputBuilder.ToString()
            Error = $errorBuilder.ToString()
        }
    }
    catch {
        Log-Error "Failed to execute process: $FilePath" $_ "Start-SafeProcess"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# --- Enhanced System Checks with Circuit Breaker ---
function Check-SystemHealth {
    param([string]$Operation)
    
    if (-not (Test-CircuitBreaker)) {
        Log "Circuit breaker is open. Skipping $Operation" "Yellow"
        return $false
    }

    try {
        switch ($Operation) {
            "DiskSpace" {
                $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'" -ErrorAction Stop
                if ($null -eq $disk) { throw "Failed to retrieve disk information" }
                
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $totalGB = [math]::Round($disk.Size / 1GB, 2)
                $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                
                Log "${selectedDrive} Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
                Update-CircuitBreaker $true
                return $true
            }
            
            "CPUUsage" {
                $cpu = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total")
                $cpu.NextValue() | Out-Null
                $usage = [math]::Round($cpu.NextValue(), 2)
                
                Log "CPU Usage: $usage%" "Cyan"
                Update-CircuitBreaker $true
                return $true
            }
            
            "RAMUsage" {
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                if ($null -eq $os) { throw "Failed to retrieve OS information" }
                
                $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                $used = [math]::Round($total - $free, 2)
                $percentUsed = [math]::Round(($used / $total) * 100, 2)
                
                Log "RAM Usage: $used GB of $total GB ($percentUsed%)" "Cyan"
                Update-CircuitBreaker $true
                return $true
            }
            
            default {
                throw "Unknown operation: $Operation"
            }
        }
    }
    catch {
        Log-Error "System health check failed for $Operation" $_ "Check-SystemHealth"
        Update-CircuitBreaker $false
        return $false
    }
}

# --- Safe File Operations ---
function Remove-SafeFile {
    param([string]$Path)
    try {
        if (-not (Test-ValidPath $Path)) {
            throw [System.IO.FileNotFoundException]::new("Invalid or inaccessible path: $Path")
        }

        $fileInfo = New-Object System.IO.FileInfo($Path)
        if ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $fileInfo.Attributes = $fileInfo.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
        }

        Remove-Item -Path $Path -Force -ErrorAction Stop
        return $true
    }
    catch {
        Log-Error "Failed to remove file: $Path" $_ "Remove-SafeFile"
        return $false
    }
}

# --- Enhanced Browser Cache Clearing ---
function Clear-BrowserCaches {
    try {
        $browserPaths = @{
            "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
            "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
            "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
            "Opera" = @(
                "$env:LOCALAPPDATA\Opera Software\Opera Stable\Cache",
                "$env:APPDATA\Opera Software\Opera Stable\Cache",
                "$env:LOCALAPPDATA\Opera Software\Opera GX\Cache",
                "$env:APPDATA\Opera Software\Opera GX\Cache"
            )
            "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
        }

        $results = @()
        $browserPaths.GetEnumerator() | ForEach-Object -ThrottleLimit 5 -Parallel {
            $browser = $_.Key
            $paths = $_.Value
            $success = $true
            $errors = @()

            try {
                if ($paths -is [Array]) {
                    foreach ($path in $paths) {
                        if (Test-Path $path) {
                            Get-ChildItem -Path $path -Recurse -ErrorAction Stop | 
                            ForEach-Object -ThrottleLimit 100 -Parallel {
                                try {
                                    if (Test-Path $_.FullName) {
                                        $fileInfo = [System.IO.FileInfo]$_.FullName
                                        if ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                            $fileInfo.Attributes = $fileInfo.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
                                        }
                                        Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                                    }
                                }
                                catch {
                                    $errors += "Failed to remove $($_.FullName): $($_.Exception.Message)"
                                }
                            }
                            Write-Host "✔ $browser cache cleared." -ForegroundColor Cyan
                        }
                    }
                }
                else {
                    if ($browser -eq "Firefox") {
                        if (Test-Path $paths) {
                            $profiles = Get-ChildItem -Path $paths -Directory -ErrorAction Stop
                            foreach ($profile in $profiles) {
                                $cache2Path = Join-Path $profile.FullName "cache2"
                                $cachePath = Join-Path $profile.FullName "cache"
                                if (Test-Path $cache2Path) { 
                                    try {
                                        Remove-Item -Path $cache2Path -Force -ErrorAction Stop
                                    }
                                    catch {
                                        $errors += "Failed to remove Firefox cache2: $($_.Exception.Message)"
                                    }
                                }
                                if (Test-Path $cachePath) { 
                                    try {
                                        Remove-Item -Path $cachePath -Force -ErrorAction Stop
                                    }
                                    catch {
                                        $errors += "Failed to remove Firefox cache: $($_.Exception.Message)"
                                    }
                                }
                            }
                            Write-Host "✔ Firefox cache cleared." -ForegroundColor Cyan
                        }
                    }
                    else {
                        if (Test-Path $paths) {
                            Get-ChildItem -Path $paths -Recurse -ErrorAction Stop | 
                            ForEach-Object -ThrottleLimit 100 -Parallel {
                                try {
                                    if (Test-Path $_.FullName) {
                                        $fileInfo = [System.IO.FileInfo]$_.FullName
                                        if ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                            $fileInfo.Attributes = $fileInfo.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
                                        }
                                        Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                                    }
                                }
                                catch {
                                    $errors += "Failed to remove $($_.FullName): $($_.Exception.Message)"
                                }
                            }
                            Write-Host "✔ $browser cache cleared." -ForegroundColor Cyan
                        }
                        else {
                            Write-Host "✔ User doesn't have $browser Browser." -ForegroundColor Cyan
                        }
                    }
                }
            }
            catch {
                $success = $false
                $errors += $_.Exception.Message
            }

            $results += [PSCustomObject]@{
                Browser = $browser
                Success = $success
                Errors = $errors
            }
        }

        $failedBrowsers = $results | Where-Object { -not $_.Success }
        if ($failedBrowsers.Count -gt 0) {
            Write-Host "Failed to clear cache for: $($failedBrowsers.Browser -join ', ')" -ForegroundColor Red
            foreach ($browser in $failedBrowsers) {
                Write-Host "Errors for $($browser.Browser): $($browser.Errors -join '; ')" -ForegroundColor Red
            }
        }
    }
    catch {
        Log-Error "Failed to clear browser caches" $_ "Clear-BrowserCaches"
    }
}

# --- System Check Functions ---
function Check-DiskSpace {
    try {
        # Use WMI for better performance
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'" -ErrorAction Stop
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        Log "${selectedDrive} Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
    }
    catch {
        Log "Failed to retrieve disk space info for ${selectedDrive}: $_" "Red"
    }
}

function Check-CPUUsage {
    try {
        # Use WMI for CPU usage
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $usage = $cpu.LoadPercentage
        Log "CPU Usage: $usage%" "Cyan"
    }
    catch {
        Log "Failed to retrieve CPU usage: $_" "Red"
    }
}

function Flush-DNSCache {
    try {
        Write-Host "Flushing DNS cache..." -ForegroundColor Cyan
        $before = (Get-DnsClientCache).Count
        # Use .NET method for DNS flush
        [System.Diagnostics.Process]::Start("ipconfig", "/flushdns") | Wait-Process
        $after = (Get-DnsClientCache).Count
        $flushed = $before - $after
        Write-Host "✔ DNS cache flushed." -ForegroundColor Cyan
        Write-Host "Entries removed: $flushed" -ForegroundColor Cyan
        Write-Host ""
    }
    catch {
        Log "Failed to flush DNS cache: $_" "Red"
    }
}

function Check-RAMUsage {
    try {
        # Use WMI for better performance
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
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
    }
    catch {
        Log "Failed to retrieve RAM usage: $_" "Red"
    }
}

function Check-GPUDrivers {
    try {
        # Use WMI for better performance
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop
        foreach ($gpu in $gpus) {
            if ($gpu.DriverDate) {
                $driverDate = [datetime]$gpu.DriverDate
                $formattedDate = $driverDate.ToString("MMddyyyy")
            }
            else {
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
    }
    catch {
        Log "Failed to retrieve GPU driver info: $_" "Red"
    }
}

function Check-SystemUptime {
    try {
        # Use WMI for better performance
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
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
    }
    catch {
        Log "Failed to retrieve system uptime: $_" "Red"
    }
}

function Install-WindowsUpdates {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping Windows updates" "Yellow"
            return $false
        }

        Write-Host "Checking for Windows updates..." -ForegroundColor Cyan
        
        # Use COM object for Windows Update with proper cleanup
        $updateSession = $null
        $updateSearcher = $null
        $searchResult = $null
        $updatesToDownload = $null
        $downloader = $null
        $installer = $null

        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            
            if ($searchResult.Updates.Count -eq 0) {
                Write-Host "Windows Updates are current." -ForegroundColor Green
                Update-CircuitBreaker $true
                return $true
            }
            
            Write-Host "Updates found:" -ForegroundColor Gray
            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            
            # Process updates in parallel with proper error handling
            $updateResults = @()
            $searchResult.Updates | ForEach-Object -ThrottleLimit 10 -Parallel {
                $update = $_
                $result = @{
                    Title = $update.Title
                    Success = $true
                    Error = $null
                }

                try {
                    Write-Host "Update: $($update.Title)" -ForegroundColor Gray
                    if (-not $update.EulaAccepted) {
                        $update.AcceptEula() | Out-Null
                    }
                    $updatesToDownload.Add($update) | Out-Null
                }
                catch {
                    $result.Success = $false
                    $result.Error = $_.Exception.Message
                }

                $updateResults += $result
            }
            
            if ($updatesToDownload.Count -gt 0) {
                Write-Host "Downloading updates..." -ForegroundColor Cyan
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updatesToDownload
                $downloadResult = $downloader.Download()
                
                if ($downloadResult.ResultCode -ne 2) {
                    throw "Download failed with result code: $($downloadResult.ResultCode)"
                }
                
                Write-Host "Installing updates..." -ForegroundColor Cyan
                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updatesToDownload
                $installationResult = $installer.Install()
                
                Write-Host "Updates Installed: $($installationResult.UpdatesInstalled)" -ForegroundColor Gray
                if ($installationResult.RebootRequired) {
                    $script:needsRestart = $true
                    Write-Host "A restart is required to complete the update installation." -ForegroundColor Yellow
                }
            }

            Update-CircuitBreaker $true
            return $true
        }
        finally {
            # Cleanup COM objects
            if ($installer) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($installer) }
            if ($downloader) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($downloader) }
            if ($updatesToDownload) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($updatesToDownload) }
            if ($searchResult) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($searchResult) }
            if ($updateSearcher) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($updateSearcher) }
            if ($updateSession) { [System.Runtime.Interopservices.Marshal]::ReleaseComObject($updateSession) }
        }
    }
    catch {
        Log-Error "Windows update process failed" $_ "Install-WindowsUpdates"
        Update-CircuitBreaker $false
        return $false
    }
}

# --------------------------------------------------------------
# Function to execute a DISM /CheckHealth scan.
# Instead of showing all details, it logs full output and displays only a final alert message.
# --------------------------------------------------------------
function Run-DISMCheckHealth {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping DISM check" "Yellow"
            return $false
        }

        $outputBuilder = New-Object System.Text.StringBuilder
        $result = Start-SafeProcess -FilePath "dism.exe" -Arguments "/Online /Cleanup-Image /CheckHealth" -Output $null

        if (-not $result.Success) {
            throw [System.ComponentModel.Win32Exception]::new($result.Error)
        }

        $dismOutput = $result.Output
        $dismOutputLines = $dismOutput -split "`n"
        $script:log.Add("DISM /CheckHealth Output:`n" + ($dismOutputLines -join "`n") + "`n")
        
        Write-Host ""
        if ($dismOutput -match "No component store corruption detected") {
            Write-Host "No component store corruption found, so we're moving onto the SFC Scan." -ForegroundColor Yellow
            Update-CircuitBreaker $true
            return $true
        }
        else {
            $fixCount = ($dismOutputLines | Where-Object { $_ -match "Beginning Verify and Repair transaction" }).Count
            Write-Host "DISM Scan identified and repaired $fixCount items in Windows Component Store." -ForegroundColor Yellow
            Update-CircuitBreaker $true
            return $true
        }
    }
    catch {
        Log-Error "DISM check health failed" $_ "Run-DISMCheckHealth"
        Update-CircuitBreaker $false
        return $false
    }
}

# -------------------------------
# SFC Scan Function: Output native SFC results in real time.
# -------------------------------
function Run-SFCScan {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping SFC scan" "Yellow"
            return $false
        }

        Write-Host "Executing SFC Scan..." -ForegroundColor Cyan
        $outputBuilder = New-Object System.Text.StringBuilder
        $result = Start-SafeProcess -FilePath "sfc.exe" -Arguments "/scannow" -Output $null

        if (-not $result.Success) {
            throw [System.ComponentModel.Win32Exception]::new($result.Error)
        }

        $outputBuilder.Append($result.Output) | Out-Null
        $outputBuilder.ToString()
        Update-CircuitBreaker $true
        return $true
    }
    catch {
        Log-Error "SFC scan failed" $_ "Run-SFCScan"
        Update-CircuitBreaker $false
        return $false
    }
}

# --------------------------------------------------------------
# Functions for clearing browser caches, disk cleanup, and temporary files.
# --------------------------------------------------------------
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
    }
    catch {
        Log "Disk Cleanup failed on ${selectedDrive}: $_" "Red"
    }
}

function Get-WindowsTempSize {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping temp size check" "Yellow"
            return 0
        }

        $tempPath = $env:TEMP
        if (-not (Test-ValidPath $tempPath)) {
            throw [System.IO.DirectoryNotFoundException]::new("Invalid temp path: $tempPath")
        }

        $files = Get-ChildItem -Path $tempPath -Recurse -ErrorAction SilentlyContinue | 
                 Where-Object { $_.PSIsContainer -eq $false }

        $results = Process-FilesWithHash -Files $files.FullName -MaxThreads 10 -BatchSize 1000

        $totalSize = ($results.FileStats.Values | Measure-Object -Property Size -Sum).Sum
        $oldFiles = $results.FileStats.Where({ $_.Value.LastAccess -lt (Get-Date).AddDays(-7) })

        if ($oldFiles.Count -gt 0) {
            Log "Found $($oldFiles.Count) files older than 7 days" "Yellow"
        }

        Update-CircuitBreaker $true
        return [math]::Round($totalSize / 1MB, 2)
    }
    catch {
        Log-Error "Failed to calculate Windows Temp size" $_ "Get-WindowsTempSize"
        Update-CircuitBreaker $false
        return 0
    }
}

function Clear-WindowsTemp {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping temp file cleanup" "Yellow"
            return $false
        }

        $tempPath = $env:TEMP
        if (-not (Test-ValidPath $tempPath)) {
            throw [System.IO.DirectoryNotFoundException]::new("Invalid temp path: $tempPath")
        }

        $dirInfo = New-Object System.IO.DirectoryInfo($tempPath)
        $errorCount = 0
        $maxErrors = 50
        $successCount = 0

        # Delete files in parallel with error handling
        Get-ChildItem -Path $tempPath -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.PSIsContainer -eq $false } |
        ForEach-Object -ThrottleLimit 100 -Parallel {
            try {
                if (Remove-SafeFile $_.FullName) {
                    $successCount++
                }
            }
            catch {
                $errorCount++
                if ($errorCount -ge $maxErrors) {
                    throw "Too many errors while clearing temp files"
                }
            }
        }

        Log "Cleared $successCount temp files with $errorCount errors" "Cyan"
        Update-CircuitBreaker $true
        return $true
    }
    catch {
        Log-Error "Failed to clear Windows Temp files" $_ "Clear-WindowsTemp"
        Update-CircuitBreaker $false
        return $false
    }
}

# New function to wrap text without breaking words.
function Wrap-Text {
    param(
        [Parameter(Mandatory = $true)]
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
        }
        else {
            $line += $word + " "
        }
    }
    if ($line) {
        $result += $line.TrimEnd()
    }
    return $result
}

# --- Enhanced Error Handling and Retry Logic ---
function Invoke-WithRetry {
    param(
        [scriptblock]$Action,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 1,
        [string]$OperationName = "Operation",
        [System.Collections.Generic.List[string]]$Errors
    )

    $attempt = 0
    $success = $false
    $lastError = $null

    while (-not $success -and $attempt -lt $MaxAttempts) {
        $attempt++
        try {
            $result = & $Action
            $success = $true
            return $result
        }
        catch {
            $lastError = $_
            if ($Errors) {
                $Errors.Add("Attempt $attempt failed: $($_.Exception.Message)")
            }
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    if (-not $success) {
        throw "Operation '$OperationName' failed after $MaxAttempts attempts. Last error: $($lastError.Exception.Message)"
    }
}

# --- Enhanced Performance Monitoring ---
function Start-PerformanceMonitoring {
    param(
        [string[]]$CounterNames = @(
            "CPU",
            "Memory",
            "Disk"
        ),
        [int]$DurationSeconds = 60,
        [int]$SampleIntervalMs = 1000
    )

    $metrics = @()
    $endTime = (Get-Date).AddSeconds($DurationSeconds)

    while ((Get-Date) -lt $endTime) {
        try {
            # CPU Usage
            $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
            $metrics += [PSCustomObject]@{
                Name = "CPU"
                Value = $cpu.LoadPercentage
                Timestamp = Get-Date
            }

            # Memory Usage
            $os = Get-CimInstance Win32_OperatingSystem
            $totalMemory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            $freeMemory = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            $usedMemory = $totalMemory - $freeMemory
            $memoryUsage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
            $metrics += [PSCustomObject]@{
                Name = "Memory"
                Value = $memoryUsage
                Timestamp = Get-Date
            }

            # Disk Usage
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'"
            $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
            $totalSpace = [math]::Round($disk.Size / 1GB, 2)
            $diskUsage = [math]::Round((($totalSpace - $freeSpace) / $totalSpace) * 100, 2)
            $metrics += [PSCustomObject]@{
                Name = "Disk"
                Value = $diskUsage
                Timestamp = Get-Date
            }
        }
        catch {
            # Silently continue on errors
        }

        Start-Sleep -Milliseconds $SampleIntervalMs
    }

    return $metrics
}


# --- Enhanced File Processing with Hashing ---
function Process-FilesWithHash {
    param(
        [string[]]$Files,
        [int]$MaxThreads = 10,
        [int]$BatchSize = 1000
    )

    $processor = [ThreadedFileProcessor]::new($MaxThreads, $BatchSize)
    $hasher = [ThreadedHashCalculator]::new($MaxThreads)

    try {
        $processTask = $processor.ProcessFilesAsync($Files, {
            param($file)
            $fileInfo = [System.IO.FileInfo]$file
            $processor._fileStats.TryAdd($file, ($fileInfo.Length, $fileInfo.LastAccessTime))
        })

        $hashTask = $hasher.CalculateHashesAsync($Files)

        [System.Threading.Tasks.Task]::WaitAll($processTask, $hashTask)
    }
    finally {
        $processor.Cancel()
        $hasher.Cancel()
    }

    # Convert ConcurrentDictionary to regular Dictionary using PowerShell syntax
    $fileStatsDict = @{}
    foreach ($kvp in $processor._fileStats.GetEnumerator()) {
        $fileStatsDict[$kvp.Key] = $kvp.Value
    }

    return @{
        FileStats = $fileStatsDict
        Hashes = $hasher.GetHashes()
        Errors = $processor._errors.ToArray()
    }
}

# --- Enhanced System Health Check with Threading ---
function Get-SystemHealthThreaded {
    try {
        if (-not (Test-CircuitBreaker)) {
            Log "Circuit breaker is open. Skipping system health check" "Yellow"
            return $false
        }

        $errors = New-Object System.Collections.Generic.List[string]
        $tasks = @{
            "Processes" = {
                Start-ProcessMonitoring -ProcessNames @("chrome", "firefox", "msedge") -DurationSeconds 5
            }
            "Disk" = {
                Start-DiskAnalysis -DrivePath $selectedDrive
            }
            "Network" = {
                Start-NetworkMonitoring -DurationSeconds 5
            }
            "Performance" = {
                Start-PerformanceMonitoring -DurationSeconds 5
            }
        }

        $results = @{}
        foreach ($task in $tasks.GetEnumerator()) {
            $results[$task.Key] = Invoke-WithRetry -Action $task.Value -OperationName $task.Key -Errors $errors
        }

        # Process results
        foreach ($result in $results.GetEnumerator()) {
            if ($result.Value -is [System.Exception]) {
                Log "Errors in $($result.Key): $($result.Value.Message)" "Red"
            }
        }

        if ($errors.Count -gt 0) {
            Log "System health check completed with $($errors.Count) errors" "Yellow"
        }
        else {
            Log "System health check completed successfully" "Green"
        }

        Update-CircuitBreaker $true
        return $true
    }
    catch {
        Log-Error "System health check failed" $_ "Get-SystemHealthThreaded"
        Update-CircuitBreaker $false
        return $false
    }
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
}
else {
    Log "✖ User has opted not to run Disk Cleanup." "Yellow"
}
Write-Host ""

# --- 2. Clear Windows Temp Files (Optional) ---
$tempSize = Get-WindowsTempSize
if ($tempSize -gt 0) {
    if ($tempSize -gt 1000) {
        $displaySize = ("{0:N2} GB" -f ($tempSize / 1024))
    }
    else {
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
            }
            else {
                Log "✖ User chose not to close running applications. Proceeding to clear available temp files." "Yellow"
            }
        }
        Clear-WindowsTemp
        Log "✔ Windows Temp Files have been cleared." "Yellow"
    }
    else {
        Log "✖ User chose not to clear Windows Temp files." "Yellow"
    }
}
else {
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
Write-Host "We're about to run DISM Scan to check for component store corruption. If we find and fix anything, we'll let you know." -ForegroundColor Yellow
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
$finalFree = (Get-PSDrive -Name $selectedDrive.Substring(0, 1)).Free
$spaceFreedBytes = $finalFree - $initialFreeSpace
if ($spaceFreedBytes -lt 0) { $spaceFreedBytes = 0 }
if ($spaceFreedBytes -ge 1GB) {
    $spaceFreedFormatted = ("{0:N2} GB" -f ($spaceFreedBytes / 1GB))
}
else {
    $spaceFreedFormatted = ("{0:N2} MB" -f ($spaceFreedBytes / 1MB))
}
Log "✔ Total space freed during this session: $spaceFreedFormatted" "Cyan"

$duration = (Get-Date) - $script:StartTime
Log "⏱ Total script runtime: $($duration.ToString())" "Cyan"

$script:log | Out-File -FilePath $logFile -Encoding UTF8

Log "=============================================" "Cyan"
Log "YaugerAIO tasks completed." "Blue"
Write-Host ""

$thankYouMessage = "Thank you so much for trying out YaugerAIO. If you have any questions, comments, feedback, or feature requests, please send inquiries to rick.yauger@outlook.com."
$wrappedThankYou = Wrap-Text -Text $thankYouMessage -Width 130
Log $wrappedThankYou "Blue"
Write-Host ""

$feedbackMessage = "Check the log file on your desktop for details. For bugs or feedback, email rick.yauger@outlook.com."
$wrappedFeedback = Wrap-Text -Text $feedbackMessage -Width 130
Log $wrappedFeedback "Blue"
Write-Host ""

try {
    Stop-Transcript
}
catch {
    # No transcript active.
}

# Export all functions that are being tested
Export-ModuleMember -Function @(
    'Test-ValidDrive',
    'Test-ValidPath',
    'Wrap-Text',
    'Remove-SafeFile',
    'Get-WindowsTempSize',
    'Process-FilesWithHash',
    'Check-DiskSpace',
    'Check-CPUUsage',
    'Check-RAMUsage',
    'Test-CircuitBreaker',
    'Update-CircuitBreaker',
    'Invoke-WithRetry',
    'Start-PerformanceMonitoring',
    'Get-TempLockingProcesses',
    'Clear-BrowserCaches',
    'Get-SystemHealthThreaded'
)