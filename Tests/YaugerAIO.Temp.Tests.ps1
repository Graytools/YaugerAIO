# Load the temp cleanup functions without starting the main script.
# Any files actually deleted in these tests are under Pester's TestDrive.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors) { throw 'Cannot test temp functions while the original script has syntax errors.' }

    foreach ($functionName in @('Clear-WindowsTemp', 'Get-WindowsTempSize')) {
        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        }, $true)
        if ($null -eq $functionAst) { throw "$functionName is missing." }

        . ([scriptblock]::Create($functionAst.Extent.Text))
    }

    # Keep test messages here instead of writing to someone's Desktop.
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

    It 'accurately counts nested and hidden test files in megabytes' {
        $nested = Join-Path $env:TEMP 'nested'
        New-Item -ItemType Directory -Path $nested | Out-Null

        $normalPath = Join-Path $nested 'normal.bin'
        $hiddenPath = Join-Path $env:TEMP '.hidden.bin'
        [System.IO.File]::WriteAllBytes($normalPath, ([byte[]]::new(1MB)))
        [System.IO.File]::WriteAllBytes($hiddenPath, ([byte[]]::new(512KB)))
        if ($env:OS -eq 'Windows_NT') {
            $hiddenItem = Get-Item -LiteralPath $hiddenPath -Force
            $hiddenItem.Attributes = $hiddenItem.Attributes -bor [System.IO.FileAttributes]::Hidden
        }

        Get-WindowsTempSize | Should -Be 1.5
    }

    It 'returns zero when the TEMP directory is missing' {
        $env:TEMP = Join-Path $TestDrive 'nonexistent-temp'
        Get-WindowsTempSize | Should -Be 0
    }
}
