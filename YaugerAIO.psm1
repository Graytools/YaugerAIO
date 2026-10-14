# Loading the module only registers commands. Maintenance starts when the user runs one.

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

    # Open a separate elevated console so the prompts and results remain visible.
    $arguments = @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $scriptPath))
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -ErrorAction Stop
}

function YaugerAIO {
    [CmdletBinding()]
    param()

    Start-YaugerAIOWorkflow
}

Export-ModuleMember -Function 'YaugerAIO', 'Start-YaugerAIOWorkflow'
