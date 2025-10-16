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

### Program.cs - Comprehensive SDK Example

The main program demonstrates advanced SDK features including:

* **Authentication**: Login with master password, 2FA, and device approval
* **Vault Operations**: Sync and access vault records
* **Record Management**: Create, read, update typed records (Login type)
* **Custom Fields**: Add and update custom fields on records
* **Non-Shared Data**: Store and retrieve record-specific non-shared data
* **File Attachments**: Upload, download, and delete file attachments
* **Shared Folders**: Create shared folders and manage folder permissions
* **User Management**: Add users to shared folders with specific permissions
* **Enterprise Features**: Load enterprise data, create teams, and manage team members (requires enterprise admin role)

This is a complete example showing most SDK capabilities in action.

### BasicAuthExample.cs - Simple Authentication Example

A minimal example demonstrating the basic authentication flow:

* **Authentication**: Master password, 2FA, and device approval using `AuthSync`
* **Input Management**: Using `SimpleInputManager` for console input
* **Configuration Storage**: Using `JsonConfigurationStorage` for persisting settings
* **Vault Sync**: Download and decrypt vault using `VaultOnline`
* **Basic Vault Stats**: Display record, folder, and shared folder counts

This example is ideal for:
* Understanding the authentication flow with AuthSync
* Learning the minimal SDK setup required
* Getting started with basic vault operations
* Building console applications with Keeper SDK
* Quick integration testing

**View the code**: [BasicAuthExample.cs](BasicAuthExample.cs)

To run just this example, call `await BasicAuthExample.Run();` from the Main method.

## Usage Tips

### Configuration Storage

Both examples use `JsonConfigurationStorage` which stores configuration data in the current directory as a JSON file. This includes:
* Last login username
* Device token (to avoid repeated device approvals)
* Server settings

For production use, consider implementing `IConfigurationStorage` to store this data securely according to your application's requirements.

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

## Next Steps

* **For CLI functionality**: See the [Commander CLI](../Commander) project for a full-featured command-line interface
* **For PowerShell**: See the [PowerCommander](../PowerCommander) module
* **For GUI applications**: See the [WPFSample](../WPFSample) project
* **For API documentation**: Visit the [Keeper SDK Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)

