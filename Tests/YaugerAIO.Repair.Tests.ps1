# DISM and SFC results are faked here; the tests should never run either tool.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors) { throw 'Cannot test repair status parsing while the script has syntax errors.' }

    foreach ($functionName in @('Get-DISMCheckHealthStatus', 'Get-DISMRepairVerificationStatus', 'Get-SFCScanStatus')) {
        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        }, $true)
        if ($null -eq $functionAst) { throw "$functionName is missing." }
        . ([scriptblock]::Create($functionAst.Extent.Text))
    }
}

Describe 'DISM /CheckHealth status classification' {
    It 'classifies a healthy component store without claiming repairs' {
        Get-DISMCheckHealthStatus -Output 'No component store corruption detected.' -ExitCode 0 |
            Should -Be 'Healthy'
    }

    It 'recognizes corruption requiring a separate repair operation' {
        Get-DISMCheckHealthStatus -Output 'The component store is repairable.' -ExitCode 0 |
            Should -Be 'Repairable'
    }

    It 'distinguishes a non-repairable component store from repairable corruption' {
        Get-DISMCheckHealthStatus -Output 'The component store is not repairable.' -ExitCode 0 |
            Should -Be 'NotRepairable'
    }

    It 'does not treat a native executable failure as success' {
        Get-DISMCheckHealthStatus -Output 'No component store corruption detected.' -ExitCode 5 |
            Should -Be 'Failed'
    }

    It 'does not invent a healthy status for unrecognized output' {
        Get-DISMCheckHealthStatus -Output 'Unknown status text' -ExitCode 0 |
            Should -Be 'Unknown'
    }
}

Describe 'DISM repair confirmation' {
    It 'confirms repair only when DISM exits successfully and the follow-up check reports healthy' {
        Get-DISMRepairVerificationStatus -RepairExitCode 0 -CheckStatus 'Healthy' |
            Should -Be 'Repaired'
    }

    It 'does not report a successful repair after a failed DISM operation' {
        Get-DISMRepairVerificationStatus -RepairExitCode 87 -CheckStatus 'Healthy' |
            Should -Be 'Failed'
    }

    It 'warns when Windows still reports repairable damage afterward' {
        Get-DISMRepairVerificationStatus -RepairExitCode 0 -CheckStatus 'Repairable' |
            Should -Be 'Unresolved'
    }

    It 'warns when Windows reports the damage cannot be repaired' {
        Get-DISMRepairVerificationStatus -RepairExitCode 0 -CheckStatus 'NotRepairable' |
            Should -Be 'Unresolved'
    }

    It 'does not claim the repair worked if the follow-up check failed or was unrecognized' {
        Get-DISMRepairVerificationStatus -RepairExitCode 0 -CheckStatus 'Failed' |
            Should -Be 'Unverified'
        Get-DISMRepairVerificationStatus -RepairExitCode 0 -CheckStatus 'Unknown' |
            Should -Be 'Unverified'
    }

    It 'prompts before repair and keeps the operation behind the repairable-result case' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $runner = $ast.Find({
            param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Run-DISMCheckHealth'
        }, $true)
        $source = $runner.Extent.Text
        $source | Should -Match "'Repairable'[\s\S]*\[Console\]::ReadKey"
        $source | Should -Match "if \(\$choice\.KeyChar"
        $source | Should -Match 'Invoke-DISMRestoreHealth'
    }
}

Describe 'SFC /scannow status classification' {
    It 'recognizes a scan with no integrity violations' {
        Get-SFCScanStatus -Output 'Windows Resource Protection did not find any integrity violations.' -ExitCode 0 |
            Should -Be 'Healthy'
    }

    It 'recognizes a successful repair report' {
        Get-SFCScanStatus -Output 'Windows Resource Protection found corrupt files and successfully repaired them.' -ExitCode 0 |
            Should -Be 'Repaired'
    }

    It 'warns when corrupt files remain unresolved' {
        Get-SFCScanStatus -Output 'Windows Resource Protection found corrupt files but was unable to fix some of them.' -ExitCode 0 |
            Should -Be 'Unresolved'
    }

    It 'recognizes failure to run the repair operation' {
        Get-SFCScanStatus -Output 'Windows Resource Protection could not perform the requested operation.' -ExitCode 0 |
            Should -Be 'Failed'
    }

    It 'prioritizes a nonzero native exit code over a success message' {
        Get-SFCScanStatus -Output 'Windows Resource Protection found corrupt files and successfully repaired them.' -ExitCode 1 |
            Should -Be 'Failed'
    }

    It 'does not claim success for unknown or localized text' {
        Get-SFCScanStatus -Output 'Unknown localized output' -ExitCode 0 |
            Should -Be 'Unknown'
    }
}
