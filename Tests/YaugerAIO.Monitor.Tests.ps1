# Use harmless child processes; never start DISM or SFC during automated tests.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $errorsFound = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errorsFound)
    if ($errorsFound) { throw 'The script has syntax errors.' }

    foreach ($name in @('Get-YaugerNativePercent', 'Read-YaugerSharedText', 'Stop-YaugerNativeProcess', 'Test-YaugerSpacePressed', 'Invoke-YaugerNativeTask')) {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        if (-not $fn) { throw "Missing monitor function: $name" }
        . ([scriptblock]::Create($fn.Extent.Text))
    }
}

Describe 'Native scan progress and skipping' {
    BeforeEach {
        $script:log = @()
    }

    It 'shows a percent only when the native command reports one' {
        Get-YaugerNativePercent -Output "SFC: Verification 12% complete." | Should -Be '12%'
        Get-YaugerNativePercent -Output "DISM 17.1% done" | Should -Be '17.1%'
        Get-YaugerNativePercent -Output "stage 12%`rstage 82% complete" | Should -Be '82%'
        Get-YaugerNativePercent -Output 'No output yet' | Should -BeNullOrEmpty
    }

    It 'does not invent a percentage from elapsed time' {
        Get-YaugerNativePercent -Output 'Still running after 49 minutes' | Should -BeNullOrEmpty
    }

    It 'completes a harmless command and records its exit code and output' {
        $result = Invoke-YaugerNativeTask -FilePath 'ping.exe' -Arguments @('-n', '1', '127.0.0.1') -Label 'Progress test' -NextStep 'Test finished' -SkipRequested { $false }
        $result.State | Should -Be 'Completed'
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match '127.0.0.1'
        $script:log -join "`n" | Should -Match 'Progress test \| outcome: Completed'
    }

    It 'stops a harmless running command on a simulated Spacebar press and records the skip' {
        $result = Invoke-YaugerNativeTask -FilePath 'ping.exe' -Arguments @('-n', '10', '127.0.0.1') -Label 'Skip test' -NextStep 'Next check' -SkipRequested { $true }
        $result.State | Should -Be 'Skipped'
        $script:log -join "`n" | Should -Match 'Spacebar skip requested'
        $script:log -join "`n" | Should -Match 'process stopped: True'
    }

    It 'returns Failed instead of hanging if the executable cannot start' {
        $result = Invoke-YaugerNativeTask -FilePath 'YaugerAIO_no_such_executable.exe' -Arguments @('/x') -Label 'Missing test' -NextStep 'Next check' -SkipRequested { $false }
        $result.State | Should -Be 'Failed'
        $script:log -join "`n" | Should -Match 'could not run or monitor'
    }
}
