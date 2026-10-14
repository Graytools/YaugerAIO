# Load reporting functions without starting the maintenance program.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'YaugerAIO.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) { throw 'YaugerAIO.ps1 has syntax errors.' }

    foreach ($name in @('Add-MaintenanceResult', 'Format-YaugerMaintenanceReport', 'Save-YaugerMaintenanceReport')) {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        if ($null -eq $fn) { throw "Missing reporting function $name." }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    $startedAt = [datetime]'2026-10-13T10:00:00'
    $finishedAt = [datetime]'2026-10-13T10:05:00'
}

Describe 'One readable YaugerAIO report' {
    It 'puts next steps ahead of choices, results and technical details' {
        $results = @(
            [PSCustomObject]@{ Name = 'Memory'; Status = 'PASS'; Summary = 'Using 40%.'; Action = ''; DurationSeconds = 1 }
            [PSCustomObject]@{ Name = 'DISM repair'; Status = 'WARN'; Summary = 'Repair incomplete.'; Action = 'Ask a technician.'; DurationSeconds = 80 }
            [PSCustomObject]@{ Name = 'SFC'; Status = 'SKIP'; Summary = 'Spacebar pressed.'; Action = 'Recheck Windows later.'; DurationSeconds = 9 }
            [PSCustomObject]@{ Name = 'Browser cache'; Status = 'CHECK'; Summary = 'Cleanup unverified.'; Action = 'Close browser and retry.'; DurationSeconds = 2 }
        )
        $report = Format-YaugerMaintenanceReport -Results $results -StartedAt $startedAt -FinishedAt $finishedAt -ComputerName 'TESTPC' -Drive 'C:' -SpaceFreed '25 MB more free' -Choices @('10:00:00 - Disk Cleanup: declined.', '10:00:01 - DISM repair: accepted.') -Details @('SFC scan | Spacebar skip requested.', 'DISM raw output 41%')

        $report | Should -Match 'YAUGERAIO 1.5.3'
        $report | Should -Match 'Total time: 5 minutes'
        $report | Should -Match 'Passed: 1 \| Warnings: 1 \| Failed: 0 \| Unverified: 1 \| Skipped: 1'
        $report | Should -Match '1. \[WARN\] DISM repair'
        $report | Should -Match '2. \[SKIP\] SFC'
        $report | Should -Match 'YOUR CHOICES'
        $report | Should -Match 'Disk Cleanup: declined'
        $report | Should -Match 'EACH MAINTENANCE STEP'
        $report | Should -Match 'SFC scan \| Spacebar skip requested'
        $report | Should -Match 'DISM raw output 41%'
        $report | Should -Not -Match 'YaugerAIO_Technical_'
        $report.IndexOf('WHAT TO DO NEXT') | Should -BeLessThan $report.IndexOf('YOUR CHOICES')
        $report.IndexOf('YOUR CHOICES') | Should -BeLessThan $report.IndexOf('DETAILED ACTIVITY')
    }

    It 'shows reduced available space instead of claiming it was reclaimed' {
        $results = @([PSCustomObject]@{ Name='Windows repair'; Status='WARN'; Summary='Damage remains.'; Action='Review details.' })
        $report = Format-YaugerMaintenanceReport -Results $results -StartedAt $startedAt -FinishedAt $finishedAt -SpaceFreed '250 MB less free'
        $report | Should -Match 'Change in available drive space: 250 MB less free'
        $report | Should -Match 'not an exact amount deleted'
    }

    It 'reports a required restart' {
        $report = Format-YaugerMaintenanceReport -Results @() -StartedAt $startedAt -FinishedAt $finishedAt -RestartRequired $true
        $report | Should -Match 'Restart requested by Windows Update: YES'
        $report | Should -Match 'Save your work and restart Windows'
    }

    It 'never invents checks or choices' {
        $report = Format-YaugerMaintenanceReport -Results @() -StartedAt $startedAt -FinishedAt $finishedAt
        $report | Should -Match 'No completed checks were recorded'
        $report | Should -Match 'No interactive choices were recorded'
        $report | Should -Match 'No maintenance results were recorded'
    }

    It 'stores multi-line technical output in the same file, below the summary' {
        $detail = "DISM exited with code 87.$([Environment]::NewLine)Windows repair source unavailable."
        $report = Format-YaugerMaintenanceReport -Results @() -StartedAt $startedAt -FinishedAt $finishedAt -Details @($detail)
        $report.IndexOf('DETAILED ACTIVITY') | Should -BeLessThan $report.IndexOf('Windows repair source unavailable')
    }

    It 'writes exactly one file with the complete report' {
        $saved = Save-YaugerMaintenanceReport -ReportText 'Readable summary and detailed diagnostic output' -Timestamp 'test-session' -Destinations @($TestDrive)
        (Test-Path -LiteralPath $saved -PathType Leaf) | Should -BeTrue
        (Get-Content -LiteralPath $saved -Raw) | Should -Match 'detailed diagnostic'
        @(Get-ChildItem -LiteralPath $TestDrive -File -Filter 'YaugerAIO_*.txt').Count | Should -Be 1
    }

    It 'uses Documents or TEMP when the Desktop is unavailable' {
        $missing = Join-Path $TestDrive 'missing'
        $saved = Save-YaugerMaintenanceReport -ReportText 'Test report' -Timestamp 'fallback' -Destinations @($missing, $TestDrive)
        (Split-Path -Parent $saved) | Should -Be $TestDrive
    }

    It 'raises a clear error when all destinations fail' {
        $missing = Join-Path $TestDrive 'still-missing'
        { Save-YaugerMaintenanceReport -ReportText 'Test' -Timestamp 'none' -Destinations @($missing) } |
            Should -Throw '*Unable to save the maintenance report*'
    }
}
