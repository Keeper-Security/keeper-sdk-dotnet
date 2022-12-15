#
# Module manifest for module 'module'
#
# Generated by: Keeper Security Inc.
#
# Generated on: 10/11/2019 5:18:11 PM
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PowerCommander.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# ID used to uniquely identify this module
GUID = 'aa8a313b-fdb6-41ea-9eed-b7441d7392a1'

# Author of this module
Author = 'Keeper Security Inc.'

# Company or vendor of this module
CompanyName = 'Keeper Security Inc.'

# Copyright statement for this module
Copyright = '(c) 2022 Keeper Security Inc. All rights reserved.'

# Description of the functionality provided by this module
# Description = ''

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

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
RequiredAssemblies = @('KeeperSdk.dll')

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @('PowerCommander.types.ps1xml', 'Library.types.ps1xml', 'Enterprise.types.ps1xml',
                   'SecretsManager.types.ps1xml')

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('PowerCommander.format.ps1xml', 'Library.format.ps1xml', 'Enterprise.format.ps1xml',
					 'SecretsManager.format.ps1xml')

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('AuthCommands.ps1', 'VaultCommands.ps1', 'RecordCommands.ps1', 'SharedFolderCommands.ps1', 
				  'FolderCommands.ps1', 'Enterprise.ps1', 'Sharing.ps1', 'SecretsManager.ps1')

# Functions to export from this module
FunctionsToExport = @('Connect-Keeper', 'Sync-Keeper', 'Disconnect-Keeper', 'Get-KeeperLocation', 'Set-KeeperLocation', 
'Get-KeeperChildItems',	'Get-KeeperObject', 'Get-KeeperRecords', 'Copy-KeeperToClipboard', 'Show-TwoFactorCode', 
'Add-KeeperRecord', 'Remove-KeeperRecord', 'Move-RecordToFolder', 'Get-KeeperPasswordVisible',
'Get-KeeperSharedFolders', 'Add-KeeperFolder', 'Remove-KeeperFolder', 
'Get-KeeperEnterpriseUsers', 'Get-KeeperEnterpriseTeams', 'Sync-KeeperEnterprise', 'Get-KeeperEnterpriseNodes', 'Get-KeeperNodeName',
'Lock-KeeperEnterpriseUser', 'Unlock-KeeperEnterpriseUser', 'Move-KeeperEnterpriseUser', 'Remove-KeeperEnterpriseUser',
'Get-KeeperManagedCompanies', 'New-KeeperManagedCompany', 'Remove-KeeperManagedCompany','Edit-KeeperManagedCompany', 
'Get-KeeperEnterpriseTeamUsers',
# 'Test-Keeper',
'Show-KeeperRecordShares', 'Grant-KeeperRecordAccess', 'Revoke-KeeperRecordAccess', 'Grant-KeeperSharedFolderAccess', 
'Revoke-KeeperSharedFolderAccess', 'Get-KeeperAvailableTeams', 'Get-KeeperSecretManagerApps', 'New-KeeperSecretManagerApp', 
'Grant-KeeperSecretManagerFolderAccess', 'Revoke-KeeperSecretManagerFolderAccess', 'Add-KeeperSecretManagerClient', 
'Remove-KeeperSecretManagerClient'
)

# Cmdlets to export from this module
CmdletsToExport = @( )

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = @('kc', 'ks', 'kq', 'kpwd', 'kcd', 'kdir', 'ko', 'kr', 'ksf', 'kcc', '2fa', 'kadd', 'kdel', 'kmv', 'kmkdir', 'krmdir', 
	'ked', 'keu', 'ken', 'ket', 'ketu', 'kmc', 'kamc', 'krmc', 'kemc', 'msp-license', 'lock-user', 'unlock-user', 'transfer-user', 
	'delete-user', 'kshrsh', 'kshr', 'kushr', 'kshf', 'kushf', 'kat', 
	'ksm', 'ksm-create', 'ksm-share', 'ksm-unshare', 'ksm-addclient', 'ksm-rmclient')

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
# PrivateData =''

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

