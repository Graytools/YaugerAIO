# Pester 5 smoke tests for the PowerShell Gallery release.
# These tests must be safe to run on macOS, Windows, or CI.
# IMPORTANT: Do not dot-source or invoke YaugerAIO.ps1 here; it runs system maintenance.

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $manifestPath = Join-Path $repoRoot 'YaugerAIO.psd1'
    $modulePath = Join-Path $repoRoot 'YaugerAIO.psm1'
    $scriptPath = Join-Path $repoRoot 'YaugerAIO.ps1'
}

Describe 'YaugerAIO release smoke tests' {
    It 'parses both the maintenance script and the module without syntax errors' {
        foreach ($path in @($scriptPath, $modulePath)) {
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile(
                $path,
                [ref]$tokens,
                [ref]$parseErrors
            )
            $parseErrors | Should -BeNullOrEmpty
        }
    }

    It 'has the expected Gallery module identity' {
        $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        $manifest.Name | Should -Be 'YaugerAIO'
        $manifest.Version.ToString() | Should -Be '1.5.1'
        $manifest.Guid.ToString() | Should -Be '61202a7e-012b-4a64-888e-5dbacee33014'
    }

    It 'imports the module without running the maintenance workflow' {
        $module = Import-Module -Name $manifestPath -Force -PassThru -ErrorAction Stop
        $module.Name | Should -Be 'YaugerAIO'
    }

    It 'exports an explicit maintenance entry point' {
        Import-Module -Name $manifestPath -Force -ErrorAction Stop
        $command = Get-Command -Name 'Start-YaugerAIOWorkflow' -Module 'YaugerAIO' -ErrorAction Stop
        $command.CommandType | Should -Be 'Function'
    }

    It 'retains the functions required by the original maintenance workflow' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$null,
            [ref]$null
        )
        $functions = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object Name)

        foreach ($name in @(
            'Run-CleanMgr', 'Clear-WindowsTemp', 'Check-DiskSpace',
            'Check-CPUUsage', 'Flush-DNSCache', 'Check-RAMUsage',
            'Check-GPUDrivers', 'Check-SystemUptime', 'Clear-BrowserCaches',
            'Run-DISMCheckHealth', 'Run-SFCScan', 'Install-WindowsUpdates'
        )) {
            $functions | Should -Contain $name
        }
    }

    It 'launches maintenance in a separate elevated Windows PowerShell process with process-scoped execution policy' {
        $moduleSource = Get-Content -LiteralPath $modulePath -Raw
        $moduleSource | Should -Match "Start-Process -FilePath 'powershell.exe' -Verb RunAs"
        $moduleSource | Should -Match "'-ExecutionPolicy', 'Bypass'"
    }

    It 'checks admin privileges before doing cosmetic console setup' {
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $uacCheck = $source.IndexOf('[Security.Principal.WindowsPrincipal]')
        $consoleResize = $source.IndexOf('$host.UI.RawUI.BufferSize')
        $uacCheck | Should -BeGreaterThan 0
        $consoleResize | Should -BeGreaterThan $uacCheck
        $source | Should -Match 'Start-Process -FilePath \\$psCmd -Verb RunAs'
        $source | Should -Match 'No maintenance was started'
    }

    It 'refuses to run Windows maintenance on a non-Windows system' -Skip:($env:OS -eq 'Windows_NT') {
        Import-Module -Name $manifestPath -Force -ErrorAction Stop
        { Start-YaugerAIOWorkflow } | Should -Throw '*requires Windows*'
    }
}
