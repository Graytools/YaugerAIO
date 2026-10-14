# Functional tests for one original YaugerAIO maintenance function.
# SAFETY: Never dot-source YaugerAIO.ps1: its top-level code runs maintenance.
# Load only the Clear-WindowsTemp function from the syntax tree.
# Real removals in this file are restricted to Pester's disposable TestDrive.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors) { throw 'Cannot test temp cleanup while the original script has syntax errors.' }

    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Clear-WindowsTemp'
    }, $true)
    if ($null -eq $functionAst) { throw 'Clear-WindowsTemp is missing.' }

    . ([scriptblock]::Create($functionAst.Extent.Text))

    # Isolated logging stub; do not write a real desktop maintenance log.
    function Log {
        param($Message, $Color)
    }
}

Describe 'Clear-WindowsTemp functional safety tests' {
    BeforeEach {
        $previousTemp = $env:TEMP
        $fixtureTemp = Join-Path $TestDrive 'temp-fixture'
        New-Item -ItemType Directory -Path $fixtureTemp -Force | Out-Null
        $env:TEMP = $fixtureTemp
    }

    AfterEach {
        $env:TEMP = $previousTemp
    }

    It 'clears only sample TEMP contents and preserves neighboring files' {
        $nested = Join-Path $env:TEMP 'nested'
        New-Item -ItemType Directory -Path $nested | Out-Null
        Set-Content -LiteralPath (Join-Path $nested 'stale.txt') -Value 'temporary'
        Set-Content -LiteralPath (Join-Path $env:TEMP 'cached.txt') -Value 'temporary'
        $outsideFile = Join-Path $TestDrive 'keep.txt'
        Set-Content -LiteralPath $outsideFile -Value 'important'

        Clear-WindowsTemp

        (Test-Path -LiteralPath $env:TEMP -PathType Container) | Should -BeTrue
        (Get-ChildItem -LiteralPath $env:TEMP -Force) | Should -BeNullOrEmpty
        (Test-Path -LiteralPath $outsideFile -PathType Leaf) | Should -BeTrue
    }

    It 'never attempts removal when TEMP is unset' {
        $env:TEMP = ''
        Mock Remove-Item { throw 'Unsafe deletion attempted' }

        Clear-WindowsTemp

        Should -Invoke Remove-Item -Exactly -Times 0
    }

    It 'never attempts removal when TEMP is a filesystem root' {
        $env:TEMP = [System.IO.Path]::GetPathRoot($TestDrive)
        Mock Remove-Item { throw 'Unsafe deletion attempted' }

        Clear-WindowsTemp

        Should -Invoke Remove-Item -Exactly -Times 0
    }

    It 'never attempts removal when TEMP does not exist' {
        $env:TEMP = Join-Path $TestDrive 'missing-directory'
        Mock Remove-Item { throw 'Unsafe deletion attempted' }

        Clear-WindowsTemp

        Should -Invoke Remove-Item -Exactly -Times 0
    }
}
