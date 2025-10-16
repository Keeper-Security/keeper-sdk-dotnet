# Keeper .NET SDK

[![NuGet](https://img.shields.io/nuget/v/KeeperSdk.svg)](https://www.nuget.org/packages/KeeperSdk/)
[![License](https://img.shields.io/github/license/Keeper-Security/keeper-sdk-dotnet)](../LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)

> Enterprise-grade Password Management SDK for .NET applications

##  Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Capabilities](#core-capabilities)
- [Code Examples](#code-examples)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Sample Applications](#sample-applications)
- [Support](#support)

##  Overview

The Keeper .NET SDK is a comprehensive library that provides programmatic access to Keeper Password Manager's vault and administrative features. Built for .NET 8.0 and .NET Standard 2.0, it enables seamless integration of enterprise password management into your applications.

> **Note:** All code examples in this README use the current SDK API (v16+). The authentication flow uses `AuthSync`, `JsonConfigurationStorage`, and `SimpleInputManager` for console applications. For working examples, see the [Sample Applications](#sample-applications) section.

##  Features

-  **Authentication** - Secure authentication with support for 2FA/MFA
-  **Vault Access** - Complete access to records, folders, and shared folders
-  **CRUD Operations** - Full lifecycle management for:
  - Password records and custom fields
  - File attachments
  - Folders and shared folders
-  **Team Management** - Administrative functions for enterprise accounts
-  **Sync Operations** - Real-time vault synchronization
-  **BreachWatch** - Monitor and detect compromised credentials
-  **Extensible** - Customize integration with your backend systems
-  **Audit Logging** - Track vault and administrative activities

##  Installation

### Via NuGet Package Manager

```bash
dotnet add package KeeperSdk
```

### Via Package Manager Console

```powershell
Install-Package KeeperSdk
```

### Via .csproj Reference

```xml
<PackageReference Include="KeeperSdk" Version="16.*" />
```

##  Quick Start

### Basic Authentication and Vault Access

```csharp
using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

// Initialize configuration storage
var configStorage = new JsonConfigurationStorage("config.json");
var configuration = configStorage.Get();

// Use SimpleInputManager for console input
var inputManager = new SimpleInputManager();

// Login to Keeper using AuthSync
var auth = new AuthSync(configStorage);
await Utils.LoginToKeeper(auth, inputManager, "your-email@company.com");

// Create vault instance and sync
var vault = new VaultOnline(auth);
await vault.SyncDown();

// Access records
foreach (var record in vault.KeeperRecords)
{
    Console.WriteLine($"Record: {record.Title}");
    if (record is PasswordRecord passwordRecord)
    {
        Console.WriteLine($"  Login: {passwordRecord.Login}");
        Console.WriteLine($"  URL: {passwordRecord.Link}");
    }
}
```

### Creating a New Record

```csharp
using System.Linq;
using KeeperSecurity.Vault;

// Create a typed login record
var loginRecord = new TypedRecordFacade<LoginRecordType>();
loginRecord.Fields.Login = "admin@myapp.com";
loginRecord.Fields.Password = "SecurePassword123!";
loginRecord.Fields.Url = "https://myapp.com";

var typedRecord = loginRecord.TypedRecord;
typedRecord.Title = "My Application";
typedRecord.Notes = "Production credentials";

var createdRecord = await vault.CreateRecord(typedRecord);
Console.WriteLine($"Record created with UID: {createdRecord.Uid}");
```

##  Core Capabilities

### Authentication (`KeeperSecurity.Authentication`)

- **AuthSync** - Synchronous authentication flow
- **Email/password** - Master password authentication
- **Two-factor authentication (2FA)** - TOTP, SMS, and push notifications
- **Device approval** - Email and admin approval flows
- **Device token management** - Persistent device tokens
- **Session management** - Automatic session handling
- **SSO integration** - Enterprise SSO support
- **Biometric authentication** - WebAuthn/FIDO2 support
- **Input management** - Console and GUI input handlers via `IInputManager`

### Vault Operations (`KeeperSecurity.Vault`)

- **Records**: Create, read, update, delete password records
- **Attachments**: Upload and download file attachments
- **Folders**: Organize records in folders
- **Shared Folders**: Collaborate with team members
- **Search**: Find records by title, URL, or custom fields

### Enterprise Management (`KeeperSecurity.Enterprise`)

- User management
- Team management
- Role-based access control (RBAC)
- Audit log retrieval
- Device approval
- Managed company operations

### Configuration (`KeeperSecurity.Configuration`)

- JSON-based configuration
- Secure storage options
- Custom storage providers

##  Code Examples

### Password Change

```csharp
using System;
using System.Linq;

// Find record by title
var record = vault.KeeperRecords
    .FirstOrDefault(x => x.Title == "Database");

if (record != null)
{
    if (record is PasswordRecord passwordRecord)
    {
        // Update legacy password record
        passwordRecord.Password = "NewSecurePassword123!";
        await vault.UpdateRecord(passwordRecord);
        Console.WriteLine("Password rotated successfully");
    }
    else if (record is TypedRecord typedRecord)
    {
        // Update typed record password field
        var passwordField = typedRecord.FindTypedField(new RecordTypeField("password", "Password"));
        if (passwordField != null)
        {
            passwordField.ObjectValue = "NewSecurePassword123!";
            await vault.UpdateRecord(typedRecord);
            Console.WriteLine("Password rotated successfully");
        }
    }
}
```

### Working with Attachments

```csharp
using System.IO;
using System.Linq;
using KeeperSecurity.Commands;

// Upload attachment from file
using (var stream = File.OpenRead("config.json"))
{
    var uploadTask = new FileAttachmentUploadTask("config.json")
    {
        Title = "Configuration File",
        MimeType = "application/json"
    };
    await vault.UploadAttachment(record, uploadTask);
}

// Or upload from memory stream
using (var stream = new MemoryStream(fileContent))
{
    var uploadTask = new AttachmentUploadTask(stream)
    {
        Title = "Configuration File",
        Name = "config.json",
        MimeType = "application/json"
    };
    await vault.UploadAttachment(record, uploadTask);
}

// Download attachment
var attachment = vault.RecordAttachments(record).FirstOrDefault();
if (attachment != null)
{
    using (var stream = File.Create(attachment.Title))
    {
        await vault.DownloadAttachment(record, attachment.Id, stream);
    }
}

// Delete attachment
if (attachment != null)
{
    await vault.DeleteAttachment(record, attachment.Id);
}
```

### Shared Folder Management

```csharp
using System;
using System.Linq;
using KeeperSecurity.Vault;

// Get shared folder
var sharedFolder = vault.SharedFolders
    .FirstOrDefault(x => x.Name == "Team Credentials");

if (sharedFolder != null)
{
    // Add user to shared folder with permissions
    await vault.PutUserToSharedFolder(
        sharedFolder.Uid,
        "user@company.com",
        UserType.User,
        new SharedFolderUserOptions
        {
            ManageRecords = true,
            ManageUsers = false
        }
    );
    
    // Move record to shared folder
    await vault.MoveRecords(
        new[] { new RecordPath { RecordUid = recordUid } },
        sharedFolder.Uid,
        link: true  // true to link, false to move
    );
}
```

### Enterprise User Management

```csharp
using System;
using System.Linq;
using KeeperSecurity.Enterprise;

// Check if user has enterprise admin privileges
if (auth.AuthContext.IsEnterpriseAdmin)
{
    // Load enterprise data
    var enterprise = new EnterpriseData();
    var enterpriseLoader = new EnterpriseLoader(auth, new[] { enterprise });
    await enterpriseLoader.Load();
    
    // List users
    foreach (var user in enterprise.Users)
    {
        Console.WriteLine($"User: {user.Email} - Status: {user.Status}");
    }
    
    // Find or create team
    var team = enterprise.Teams
        .FirstOrDefault(x => x.Name == "Engineering");
    
    if (team == null)
    {
        team = await enterprise.CreateTeam(new EnterpriseTeam
        {
            Name = "Engineering",
            RestrictEdit = false,
            RestrictSharing = true,
            RestrictView = false
        });
    }
    
    // Add users to team
    await enterprise.AddUsersToTeams(
        new[] { "user1@company.com", "user2@company.com" },
        new[] { team.Uid },
        Console.WriteLine  // Progress callback
    );
}
```



##  Requirements

### Target Frameworks
- **.NET 8.0** - Latest .NET version with improved performance
- **.NET Standard 2.0** - Broad compatibility with .NET Framework and .NET Core

### Dependencies
- BouncyCastle.Cryptography (>= 2.2.1) - Cryptographic operations
- Google.Protobuf (>= 3.25.0) - Protocol buffer serialization
- Newtonsoft.Json (>= 13.0.3) - JSON serialization
- System.Data.SQLite.Core (>= 1.0.118) - SQLite storage

### Supported Platforms
- ✅ Windows (10+, Server 2019+)
- ✅ macOS (11.0+)
- ✅ Linux (Ubuntu 20.04+, RHEL 8+)

##  Documentation

### Official Resources
-  [User Guide](https://docs.keeper.io/en/v/secrets-manager/commander-cli/commander-installation-setup/net-developer-sdk) - Comprehensive SDK guide
-  [API Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm) - Complete API reference
-  [Secrets Manager](https://docs.keeper.io/secrets-manager/) - Enterprise secrets management
-  [Keeper Docs](https://docs.keeper.io/) - General documentation


##  Sample Applications

### Working Examples

| Sample | Description | Path |
|--------|-------------|------|
| **Basic Auth** | Simple authentication and vault sync | [BasicAuthExample.cs](../Sample/BasicAuthExample.cs) |
| **Full Featured** | Comprehensive SDK feature demonstration | [Program.cs](../Sample/Program.cs) |
| **Commander CLI** | Command-line application | [Commander/](../Commander/) |
| **WPF Desktop** | Windows desktop application | [WPFSample/](../WPFSample/) |

### Running the Samples

```bash
# Clone repository
git clone https://github.com/Keeper-Security/keeper-sdk-dotnet.git
cd keeper-sdk-dotnet/Sample

# Run basic example
dotnet run
```

##  Testing

```bash
# Run unit tests
cd Tests
dotnet test

# Run with coverage
dotnet test /p:CollectCoverage=true
```

##  Security Best Practices

1. **Never hardcode credentials** - Use configuration files or environment variables
2. **Secure storage** - Use encrypted storage for device tokens and configuration
3. **Handle secrets carefully** - Clear sensitive data from memory after use
4. **Validate input** - Always validate user input before operations
5. **Keep updated** - Regularly update to the latest SDK version for security patches


### Development Setup

```bash
# Clone the repository
git clone https://github.com/Keeper-Security/keeper-sdk-dotnet.git
cd keeper-sdk-dotnet

# Restore dependencies
dotnet restore

# Build the project
dotnet build

# Run tests
dotnet test
```

##  License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.