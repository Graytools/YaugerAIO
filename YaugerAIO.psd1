@{
    RootModule = 'YaugerAIO.psm1'

    ModuleVersion = '1.5.1'

    GUID = '61202a7e-012b-4a64-888e-5dbacee33014'

    Author = 'Rick Yauger'

    CompanyName = 'Rick Yauger'

    Copyright = '(c) 2024 Rick Yauger. All rights reserved.'

    Description = 'A comprehensive Windows system maintenance and optimization tool'

    PowerShellVersion = '5.1'

    FunctionsToExport = @('YaugerAIO', 'Start-YaugerAIOWorkflow')

    CmdletsToExport = @()

    VariablesToExport = @()

    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('Windows', 'Maintenance', 'System', 'Optimization', 'Cleanup')

            LicenseUri = 'https://github.com/Graytools/YaugerAIO/blob/main/LICENSE'

            ProjectUri = 'https://github.com/Graytools/YaugerAIO'

            ReleaseNotes = 'Windows maintenance launcher with guided workflow and readable completion reports.'
        }
    }
} 