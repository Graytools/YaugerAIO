# YaugerAIO module entry point.
# Importing this module must never execute system maintenance.

function Start-YaugerAIOWorkflow {
    [CmdletBinding()]
    param()

    if ($env:OS -ne 'Windows_NT') {
        throw 'YaugerAIO maintenance requires Windows.'
    }

    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'YaugerAIO.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Maintenance script was not found: $scriptPath"
    }

    # The original workflow performs privileged Windows maintenance.
    # Launch it only on explicit request, in a separate elevated console.
    $arguments = @('-NoProfile', '-NoExit', '-File', ('"{0}"' -f $scriptPath))
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -ErrorAction Stop
}

Export-ModuleMember -Function 'Start-YaugerAIOWorkflow'
