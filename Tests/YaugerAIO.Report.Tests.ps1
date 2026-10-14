# Test human-readable report creation only. No maintenance executable runs.
# The reporting functions are loaded individually from the script AST,
# because dot-sourcing YaugerAIO.ps1 would execute the maintenance workflow.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors) { throw 'Cannot test reports while YaugerAIO.ps1 has syntax errors.' }

    foreach ($name in @('Add-MaintenanceResult', 'Format-YaugerMaintenanceReport', 'Save-YaugerMaintenanceReport')) {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
        }, $true)
        if ($null -eq $fn) { throw "Reporting function $name was not found." }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    $startedAt = [datetime]'2026-10-13T10:00:00'
    $finishedAt = [datetime]'2026-10-13T10:05:00'
}

Describe 'YaugerAIO readable reporting' {
    It 'puts actionable issues ahead of the checklist' {
        $results = @(
            [PSCustomObject]@{ Name = 'Memory'; Status = 'PASS'; Summary = 'Using 40%.'; Action = '' }
            [PSCustomObject]@{ Name = 'DISM'; Status = 'WARN'; Summary = 'Repairable corruption detected.'; Action = 'Run DISM RestoreHealth.' }
            [PSCustomObject]@{ Name = 'SFC'; Status = 'FAIL'; Summary = 'Scan failed.'; Action = 'Read CBS.log.' }
            [PSCustomObject]@{ Name = 'Browser cache'; Status = 'CHECK'; Summary = 'Cleanup unverified.'; Action = 'Close browsers and retry.' }
            [PSCustomObject]@{ Name = 'Disk Cleanup'; Status = 'SKIP'; Summary = 'User skipped.'; Action = '' }
        )
        $report = Format-YaugerMaintenanceReport -Results $results -StartedAt $startedAt -FinishedAt $finishedAt -ComputerName 'TESTPC' -Drive 'C:' -SpaceFreed '25 MB' -TechnicalFile 'YaugerAIO_Technical_test.txt'

        $report | Should -Match 'WHAT TO DO NEXT'
        $report | Should -Match '1. \[WARN\] DISM'
        $report | Should -Match '2. \[FAIL\] SFC'
        $report | Should -Match '3. \[CHECK\] Browser cache'
        $report | Should -Match 'CHECK RESULTS'
        $report | Should -Match '1 passed \| 1 warnings \| 1 failed \| 1 unverified \| 1 skipped'
        $report | Should -Match 'Run DISM RestoreHealth'
        $report | Should -Match 'YaugerAIO_Technical_test.txt'
        $actionsPosition = $report.IndexOf('WHAT TO DO NEXT')
        $resultsPosition = $report.IndexOf('CHECK RESULTS')
        $actionsPosition | Should -BeLessThan $resultsPosition
    }

    It 'reports a required restart as a next step' {
        $report = Format-YaugerMaintenanceReport -Results @() -StartedAt $startedAt -FinishedAt $finishedAt -RestartRequired $true
        $report | Should -Match 'Restart required by Windows Update: YES'
        $report | Should -Match 'Restart Windows when you have saved your work'
    }

    It 'does not invent successful checks when none were recorded' {
        $report = Format-YaugerMaintenanceReport -Results @() -StartedAt $startedAt -FinishedAt $finishedAt
        $report | Should -Match 'No maintenance results were recorded'
        $report | Should -Match '0 passed \| 0 warnings \| 0 failed \| 0 unverified \| 0 skipped'
    }

    It 'keeps multiline technical content out of the concise report' {
        $results = @(
            [PSCustomObject]@{ Name = 'SFC'; Status = 'CHECK'; Summary = "Result unknown.$([Environment]::NewLine)Review logs."; Action = 'See technical output.' }
        )
        $report = Format-YaugerMaintenanceReport -Results $results -StartedAt $startedAt -FinishedAt $finishedAt
        $report | Should -Match 'Result unknown. Review logs.'
        $report | Should -Not -Match 'CBS raw scan output begins'
    }

    It 'writes readable and technical files to a disposable location' {
        $reportContent = 'Readable summary and action list'
        $detailContent = 'Technical error code: 1234'
        $saved = Save-YaugerMaintenanceReport -ReportText $reportContent -TechnicalText $detailContent -Timestamp 'test-session' -Destinations @($TestDrive)

        (Test-Path -LiteralPath $saved.ReportPath -PathType Leaf) | Should -BeTrue
        (Test-Path -LiteralPath $saved.TechnicalPath -PathType Leaf) | Should -BeTrue
        (Get-Content -LiteralPath $saved.ReportPath -Raw) | Should -Match 'Readable summary'
        (Get-Content -LiteralPath $saved.TechnicalPath -Raw) | Should -Match 'Technical error code'
    }

    It 'skips unavailable destinations and falls back to an existing directory' {
        $missing = Join-Path $TestDrive 'no-such-folder'
        $saved = Save-YaugerMaintenanceReport -ReportText 'Summary' -TechnicalText 'Details' -Timestamp 'fallback-test' -Destinations @($missing, $TestDrive)
        (Split-Path -Parent $saved.ReportPath) | Should -Be $TestDrive
        (Test-Path -LiteralPath $saved.ReportPath -PathType Leaf) | Should -BeTrue
    }

    It 'raises an error when no report destination is available' {
        $missing = Join-Path $TestDrive 'still-missing'
        { Save-YaugerMaintenanceReport -ReportText 'Summary' -TechnicalText 'Details' -Timestamp 'none' -Destinations @($missing) } |
            Should -Throw '*Unable to save the maintenance report*'
    }
}
