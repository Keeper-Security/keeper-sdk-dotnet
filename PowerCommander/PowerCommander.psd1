#
# Module manifest for module 'module'
#
# Generated by: Keeper Security Inc.
#
# Generated on: 10/11/2019 5:18:11 PM
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'PowerCommander.psm1'

    # Version number of this module.
    ModuleVersion        = '1.0.3'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop')

    # ID used to uniquely identify this module
    GUID                 = 'aa8a313b-fdb6-41ea-9eed-b7441d7392a1'

    # Author of this module
    Author               = 'Keeper Security Inc.'

    # Company or vendor of this module
    CompanyName          = 'Keeper Security Inc.'

    # Copyright statement for this module
    Copyright            = '(c) 2025 Keeper Security Inc. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'PowerShell Commander'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies   = @('KeeperSdk.dll')

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess       = @('PowerCommander.types.ps1xml', 'Library.types.ps1xml', 'Enterprise.types.ps1xml',
        'Record.types.ps1xml', 'SecretsManager.types.ps1xml')

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess     = @('PowerCommander.format.ps1xml', 'Library.format.ps1xml', 'Enterprise.format.ps1xml',
        'Record.format.ps1xml', 'SecretsManager.format.ps1xml')

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules        = @('AuthCommands.ps1', 'VaultCommands.ps1', 'RecordCommands.ps1', 'SharedFolderCommands.ps1',
        'FolderCommands.ps1', 'Enterprise.ps1', 'ManagedCompany.ps1', 'Sharing.ps1', 'SecretsManager.ps1', 'AttachmentCommands.ps1')

    # Functions to export from this module
    FunctionsToExport    = @('Connect-Keeper', 'Sync-Keeper', 'Disconnect-Keeper', 'Get-KeeperLocation', 'Set-KeeperLocation',
        'Get-KeeperChildItem',	'Get-KeeperObject', 'Get-KeeperRecord', 'Copy-KeeperToClipboard', 'Show-TwoFactorCode',
        'Add-KeeperRecord', 'Remove-KeeperRecord', 'Move-RecordToFolder', 'Get-KeeperPasswordVisible', 'Set-KeeperPasswordVisible',
        'Get-KeeperSharedFolder', 'Add-KeeperFolder', 'Edit-KeeperFolder', 'Remove-KeeperFolder', 'Get-KeeperRecordType',
        'Get-KeeperEnterpriseUser', 'Get-KeeperEnterpriseTeam', 'Sync-KeeperEnterprise', 'Get-KeeperEnterpriseNode', 
        'Get-KeeperNodeName', 'Get-KeeperRoleName', 'New-KeeperEnterpriseTeam',
        'Add-KeeperEnterpriseUser', 'Lock-KeeperEnterpriseUser', 'Unlock-KeeperEnterpriseUser', 'Move-KeeperEnterpriseUser', 
        'Remove-KeeperEnterpriseUser', 'New-KeeperEnterpriseNode', 'Get-KeeperEnterpriseRole', 'Get-KeeperEnterpriseRoleUsers',
        'Get-KeeperEnterpriseRoleTeams', 'Get-KeeperEnterpriseAdminRole',
        'Get-KeeperManagedCompany', 'New-KeeperManagedCompany', 'Remove-KeeperManagedCompany', 'Edit-KeeperManagedCompany', 'Get-MspBillingReport',
        'Switch-KeeperMC', 'Switch-KeeperMSP', 'Get-KeeperEnterpriseTeamUser', 'Get-KeeperInformation', 'Get-KeeperDeviceSettings',
        'Set-KeeperDeviceSettings', 'New-KeeperRecordType', 'Edit-KeeperRecordType', 'Remove-KeeperRecordType', 'Import-KeeperRecordTypes',
        'Add-KeeperEnterpriseTeamMember', 'Remove-KeeperEnterpriseTeamMember',
        #'Test-Keeper',
        'Show-KeeperRecordShare', 'Grant-KeeperRecordAccess', 'Revoke-KeeperRecordAccess', 'Grant-KeeperSharedFolderAccess',
        'Revoke-KeeperSharedFolderAccess', 'Get-KeeperAvailableTeam', 'Move-KeeperRecordOwnership', 'Get-KeeperSecretManagerApp',
        'Add-KeeperSecretManagerApp', 'Remove-KeeperSecretManagerApp', 'Grant-KeeperSecretManagerFolderAccess', 'Revoke-KeeperSecretManagerFolderAccess',
        'Add-KeeperSecretManagerClient', 'Remove-KeeperSecretManagerClient', 'New-KeeperOneTimeShare', 'Get-KeeperOneTimeShare',
        'Remove-KeeperOneTimeShare', 'Copy-KeeperFileAttachment', 'Copy-KeeperFileAttachmentToStream', 'Copy-FileToKeeperRecord',
        'Grant-KeeperAppAccess', 'Revoke-KeeperAppAccess'
    )

    # Cmdlets to export from this module
    CmdletsToExport      = @( )

    # Variables to export from this module
    # VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport      = @('kc', 'ks', 'kq', 'kpwd', 'kcd', 'kdir', 'ko', 'kr', 'ksf', 'kcc', '2fa', 'kadd', 'kdel', 'kmv', 'kmkdir', 'krmdir', 'krti',
        'ked', 'keu', 'ken', 'ket', 'ker', 'keta', 'ketu', 'keru', 'kert', 'kerap', 'kmc', 'kamc', 'krmc', 'kemc', 'kena', 'msp-license', 
        'switch-to-mc', 'switch-to-msp', 'invite-user', 'lock-user', 'unlock-user', 'transfer-user', 'delete-user', 
        'kshrsh', 'kshr', 'kushr', 'kshf', 'kushf', 'kat', 'ktr', 'kotsr', 'kotsg', 'kotsn', 'kwhoami', 'this-device',
        'ksm', 'ksm-create', 'ksm-delete', 'ksm-share', 'ksm-unshare', 'ksm-addclient', 'ksm-rmclient', 'kda')

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData          = @{
        PSData = @{
            Tags         = @('PowerCommander', 'Keeper', 'Vault', 'PSEdition_Desktop')
            LicenseUri   = 'https://github.com/Keeper-Security/keeper-sdk-dotnet/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/Keeper-Security/keeper-sdk-dotnet'
            IconUri      = 'https://keeper-email-images.s3.amazonaws.com/common/powershell.png'
            ReleaseNotes = @('Shared folder user list misses Name property')
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
