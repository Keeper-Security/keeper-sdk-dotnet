# Keeper SDK Sample Applications

This folder contains sample applications demonstrating various features of the Keeper .NET SDK.

## Prerequisites

* .NET Core 8.0 SDK or later
* A Keeper Security account

## Building the Samples

From the repository root:

```bash
dotnet build Sample/Sample.csproj
```

## Running the Samples

Navigate to the build output directory:

```bash
cd Sample/bin/Debug/net8.0
dotnet Sample.dll
```

Or run directly from the project directory:

```bash
dotnet run --project Sample/Sample.csproj
```

## Available Examples

The Sample project contains comprehensive examples organized by feature category. All examples can be uncommented and executed from `Program.cs`.

### Authentication Examples

#### AuthenticateAndGetVault.cs
Basic authentication and vault synchronization example:
* **Authentication**: Master password, 2FA, and device approval using `AuthSync`
* **Input Management**: Using `SimpleInputManager` for console input
* **Configuration Storage**: Using `JsonConfigurationStorage` for persisting settings
* **Vault Sync**: Download and decrypt vault using `VaultOnline`
* **Methods**: 
  - `GetVault()` - Authenticates and returns synced vault
  - `ShowFolders()` - Demonstrates basic vault access

**View the code**: [AuthenticateAndGetVault.cs](AuthenticateAndGetVault.cs)

#### LoginExamples/
* **Login.cs** - Complete authentication flow with `AuthSync`
* **Logout.cs** - Logout from authenticated session
* **Whoami.cs** - Display current user information

### Record Management Examples

#### RecordsExamples/
* **AddRecord.cs** - Create new records with various types (login, bankCard, serverCredentials, etc.)
* **UpdateRecord.cs** - Update existing record title and type
* **DeleteRecord.cs** - Delete records from vault
* **ListRecord.cs** - List all records in the vault
* **GetRecord.cs** - Retrieve detailed information about a specific record
* **RecordHistory.cs** - Access record revision history

### File Attachments Examples

#### AttachmentsExamples/
* **UploadAttachment.cs** - Upload files and thumbnails to records
* **DownloadAttachment.cs** - Download attachments by ID, name, or title
* **RemoveAttachment.cs** - Delete attachments from records

### Folder Management Examples

#### FoldersExample/
* **CreateFolder.cs** - Create new folders and shared folders with permissions
* **ListFolder.cs** - List all folders in the vault
* **MoveFolder.cs** - Move folders to different parent folders
* **RemoveFolder.cs** - Delete folders from the vault

### Shared Folder Examples

#### SharedFolderExamples/
* **ListSharedFolder.cs** - List all shared folders
* **SharedFolderPermissions.cs** - Manage record permissions within shared folders
* **ShareFolderToUser.cs** - Share folders with users and teams
* **OneTimeShare.cs** - Create one-time share links for records
* **OneTimeShareList.cs** - List active one-time shares
* **RemoveOneTimeShare.cs** - Remove one-time share links

### Record Sharing Examples

#### ShareRecordExamples/
* **ShareRecordToUSer.cs** - Share individual records with users
* **RevokeShareRecordToUser.cs** - Remove user access from specific records
* **RevokeAllSharesToUser.cs** - Remove user from all shared records
* **TransferOwnership.cs** - Transfer record ownership to another user

### Record Type Examples

#### RecordTypeExamples/
* **RecordTypeInfo.cs** - Get information about record types (all or specific)
* **AddRecordType.cs** - Create custom record types
* **UpdateRecordType.cs** - Update existing record type definitions
* **DeleteRecordType.cs** - Delete custom record types

### Import/Export Examples

#### ImportExportExamples/
* **ImportExample.cs** - Import records from JSON format
* **ExportToJsonExample.cs** - Export records to JSON format
* **ExportToFileExample.cs** - Export records to file
* **DownloadMembershipToFileObject.cs** - Download folder/record membership to object
* **DownloadMembershipToJson.cs** - Download membership to JSON
* **DownloadMembershipToFile.cs** - Download membership to file
* **DownloadMembershipMerge.cs** - Merge membership data with existing file
* **LoadRecordTypeExample.cs** - Load record type definitions from JSON

### Secrets Manager Examples

#### SecretManagerExamples/
* **AppListExample.cs** - List all Secret Manager applications
* **AppCreateExample.cs** - Create new Secret Manager applications
* **AppViewExample.cs** - View application details
* **AppDeleteExample.cs** - Delete applications
* **AppShareExample.cs** - Share folders/records with applications
* **AppUnShareExample.cs** - Remove application access
* **AddClientExample.cs** - Add clients to applications
* **RemoveClientExample.cs** - Remove clients from applications
* **SecretManagerShareExample.cs** - Share folders/records to applications
* **SecretManagerUnshareExample.cs** - Unshare from applications

### BreachWatch Examples

#### BreachWatchExamples/
* **BreachWatchList.cs** - List all breach records
* **BreachWatchScan.cs** - Scan records for breaches
* **BreatchWatchPassword.cs** - Scan passwords for breaches
* **BreachWatchIgnore.cs** - Ignore or check ignored breach records

### Enterprise Management Examples

#### EnterpriseManagementExamples/
Comprehensive enterprise administration examples (requires enterprise admin role):

**Enterprise Data:**
* **EnterpriseDownExample.cs** - Load and access enterprise data
* **EnterpriseAuditReportExample.cs** - Get available audit events

**User Management:**
* **EnterpriseUserExamples/EnterpriseUserViewExample.cs** - View user details
* **EnterpriseUserExamples/EnterpriseAddUserExample.cs** - Invite users to enterprise
* **EnterpriseUserExamples/EnterpriseEditUserExamples.cs** - Edit user properties, add/remove from teams
* **EnterpriseUserExamples/EnterpriseDeleteUserExample.cs** - Delete users
* **EnterpriseUserExamples/EnterpriseUserAction.cs** - Lock/unlock user accounts

**Node Management:**
* **EnterpriseNodeExamples/EnterpriseNodeView.cs** - View node details
* **EnterpriseNodeExamples/EnterpriseNodeAdd.cs** - Create new nodes
* **EnterpriseNodeExamples/EnterpriseNodeEdit.cs** - Update node properties
* **EnterpriseNodeExamples/EnterpriseNodeDelete.cs** - Delete nodes

**Role Management:**
* **EnterpriseRoleExamples/EnterpriseRoleView.cs** - View role details
* **EnterpriseRoleExamples/EnterpriseRoleAdd.cs** - Create new roles
* **EnterpriseRoleExamples/EnterpriseRoleUpdate.cs** - Update role properties
* **EnterpriseRoleExamples/EnterpriseRoleDelete.cs** - Delete roles
* **EnterpriseRoleExamples/EnterpriseRoleAdmin.cs** - Manage role administrators
* **EnterpriseRoleExamples/EnterpriseRoleMembership.cs** - Manage role membership
* **EnterpriseRoleExamples/EnterpriseRoleTeamManagement.cs** - Add/remove teams from roles
* **EnterpriseRoleExamples/RoleManagedNode.cs** - Manage node assignments, privileges, and enforcements

**Team Management:**
* **EnterpriseTeamExamples/EnterpriseTeamViewExample.cs** - View team details
* **EnterpriseTeamExamples/EnterpriseTeamAddExample.cs** - Create new teams
* **EnterpriseTeamExamples/EnterpriseTeamUpdateExample.cs** - Update team properties
* **EnterpriseTeamExamples/EnterpriseTeamDeleteExample.cs** - Delete teams
* **EnterpriseTeamExamples/EnterpriseTeamMembershipExample.cs** - Add/remove users from teams
* **EnterpriseTeamExamples/EnterpriseListTeams.cs** - List all enterprise teams

### Trash Examples

#### TrashExamples/
* **TrashList.cs** - List all records in trash
* **TrashRestore.cs** - Restore records from trash

### Program.cs - Main Entry Point

The `Program.cs` file contains commented-out examples for all the above features. To run a specific example:
1. Uncomment the desired example call in `Program.cs`
2. Update any placeholder values (like `<recordUid_here>`, `<userEmail_here>`, etc.)
3. Run the project

This structure allows you to easily test and learn individual SDK features.

## Usage Tips

### Running Examples

All examples in this project follow a consistent pattern:
1. Examples are organized in folders by feature category
2. Each example is a static class with static methods
3. Examples can be called from `Program.cs` by uncommenting the relevant lines
4. Replace placeholder values (e.g., `<recordUid_here>`, `<userEmail_here>`) with actual values

Example usage:
```csharp
// In Program.cs, uncomment and modify:
await RecordsExamples.AddRecordExample.AddRecord(
    name: "My New Record", 
    type: "login", 
    folderUid: null
);
```

### Configuration Storage

All examples use `JsonConfigurationStorage` which stores configuration data in the current directory as a JSON file (`config.json`). This includes:
* Last login username
* Device token (to avoid repeated device approvals)
* Server settings

For production use, consider implementing `IConfigurationStorage` to store this data securely according to your application's requirements.

### Authentication

Most examples require authentication first. The `AuthenticateAndGetVault.cs` class provides a helper method:
```csharp
var vault = await AuthenticateAndGetVault.GetVault();
```

Alternatively, use the `LoginExamples` for more control over the authentication process.

### Authentication UI

The examples use `SimpleInputManager` (implements `IInputManager`) for console input. For GUI applications:
* Implement `IInputManager` with dialog boxes for password/2FA prompts
* Use the same authentication flow (`AuthSync`) with your custom input manager
* See the [WPFSample](../WPFSample) project for a GUI example

### Error Handling

In production applications, add proper error handling around:
* Authentication failures
* Network connectivity issues
* Invalid vault operations
* Permission errors for enterprise operations
* Missing or invalid record/folder UIDs

## Next Steps

* **For CLI functionality**: See the [Commander CLI](../Commander) project for a full-featured command-line interface
* **For PowerShell**: See the [PowerCommander](../PowerCommander) module
* **For GUI applications**: See the [WPFSample](../WPFSample) project
* **For API documentation**: Visit the [Keeper SDK Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)

