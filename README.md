<div align="center">
  <img src="https://github.com/Keeper-Security/Commander/blob/master/images/commander-black.png" alt="Keeper Commander" height="167"/>
  
  # Keeper .NET SDK & PowerCommander
  
  ### Enterprise Password Management SDK for .NET and PowerShell
  
  [![NuGet](https://img.shields.io/nuget/v/KeeperSdk.svg)](https://www.nuget.org/packages/KeeperSdk/)
  [![License](https://img.shields.io/github/license/Keeper-Security/keeper-sdk-dotnet)](LICENSE)
  [![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
  [![PowerShell Gallery](https://img.shields.io/powershellgallery/v/PowerCommander.svg)](https://www.powershellgallery.com/packages/PowerCommander)
  
  [Documentation](https://docs.keeper.io/) • [API Reference](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm) • [Support](#support)
</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
- [Components](#components)
- [Usage Examples](#usage-examples)
- [Documentation](#documentation)
- [Platform Support](#platform-support)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

##  Overview

The Keeper .NET SDK and PowerCommander module provide comprehensive vault and administrative level automation for [Keeper Password Manager](https://keepersecurity.com). This SDK enables seamless integration of enterprise-grade password management into your .NET applications and PowerShell workflows.

##  Features

-  **Authentication** - Secure authentication to Keeper vault
-  **Vault Access** - Complete access to records, folders, and shared folders
-  **CRUD Operations** - Full create, read, update, delete operations for:
  - Records and custom fields
  - File attachments
  - Folders and shared folders
-  **Team Management** - Administrative functions for enterprise users
-  **Password Rotation** - Automated password updates and rotation
-  **Backend Integration** - Customizable integration with your systems
-  **BreachWatch** - Monitor compromised passwords
-  **Secrets Manager** - Enterprise secrets management capabilities

##  Getting Started

### Prerequisites

#### For .NET SDK
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download) or later
- .NET Standard 2.0 compatible runtime
- Visual Studio 2022 or VS Code (recommended)

#### For PowerCommander
- PowerShell 5.1 or PowerShell Core 7.0+
- Windows, macOS, or Linux

### Installation

#### .NET SDK via NuGet

```bash
dotnet add package KeeperSdk
```

Or via Package Manager Console:
```powershell
Install-Package KeeperSdk
```

#### PowerCommander via PowerShell Gallery

```powershell
Install-Module -Name PowerCommander -Scope CurrentUser
```

### Quick Start

#### .NET SDK Example

```csharp
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

// Connect to Keeper
var auth = new AuthImpl();
await auth.Login("your-email@company.com");

// Sync vault
var vault = new VaultOnline(auth);
await vault.SyncDown();

// Access records
foreach (var record in vault.KeeperRecords)
{
    Console.WriteLine($"Title: {record.Title}");
}
```

#### PowerShell Example

```powershell
# Import module
Import-Module PowerCommander

# Connect to vault
Connect-Keeper -Username "your-email@company.com"

# Sync and list records
Sync-Keeper
Get-KeeperRecords | Select-Object Title, RecordType
```

##  Components

### .NET SDK

The core SDK for integrating Keeper into your .NET applications.

**Resources:**
-  [User Guide](https://docs.keeper.io/en/v/secrets-manager/commander-cli/commander-installation-setup/net-developer-sdk)
-  [API Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)
- 💻 [Source Code](KeeperSdk/)

**Target Frameworks:**
- .NET 8.0
- .NET Standard 2.0

### Commander CLI

Command-line interface for vault management and automation.

```bash
# Example commands
keeper login your-email@company.com
keeper sync-down
keeper list
keeper get-record <uid>
```

 [Full CLI Documentation](Commander/README.md)

### PowerCommander Module

PowerShell module for administrative automation and scripting.

```powershell
# Core cmdlets
Connect-Keeper
Sync-Keeper
Get-KeeperRecords
Add-KeeperRecord
Update-KeeperRecord
Remove-KeeperRecord
```

 [Complete Cmdlet Reference](PowerCommander/README.md)

### Sample Applications

Working examples to help you get started:

| Sample | Description |
|--------|-------------|
| [BasicAuthExample.cs](Sample/BasicAuthExample.cs) | Simple authentication and vault sync |
| [Program.cs](Sample/Program.cs) | Comprehensive SDK features demo |
| [WPFSample](WPFSample/) | Windows desktop application example |

 [Sample Documentation](Sample/README.md)

##  Usage Examples

### Creating a Record

```csharp
var record = new PasswordRecord
{
    Title = "My Application",
    Login = "admin",
    Password = "secure-password",
    Link = "https://myapp.com"
};

await vault.CreateRecord(record);
```

### Rotating a Password

```csharp
var record = vault.GetRecord("record-uid");
record.Password = GenerateSecurePassword();
await vault.UpdateRecord(record);
```

### Managing Shared Folders

```csharp
var sharedFolder = vault.GetSharedFolder("folder-uid");
await sharedFolder.AddUser("user@company.com", 
    SharePermissions.CanEdit | SharePermissions.CanShare);
```

##  Documentation

### Official Documentation
- [Keeper Security Documentation](https://docs.keeper.io/)
- [.NET SDK User Guide](https://docs.keeper.io/en/v/secrets-manager/commander-cli/commander-installation-setup/net-developer-sdk)
- [API Reference](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)
- [Secrets Manager Portal](https://docs.keeper.io/secrets-manager/)

### Component Documentation
- [Commander CLI Guide](Commander/README.md)
- [PowerCommander Guide](PowerCommander/README.md)
- [Sample Applications](Sample/README.md)

##  Platform Support

| Platform | .NET SDK | PowerCommander | Commander CLI |
|----------|----------|----------------|---------------|
| Windows  | ✅       | ✅             | ✅            |
| macOS    | ✅       | ✅             | ✅            |
| Linux    | ✅       | ✅             | ✅            |

**Tested Environments:**
- Windows 10/11, Windows Server 2019+
- macOS 11.0+
- Ubuntu 20.04+, RHEL 8+

##  Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Support

### Community & Help
-  **Email:** commander@keepersecurity.com
-  **Documentation:** [docs.keeper.io](https://docs.keeper.io/)
-  **Website:** [keepersecurity.com](https://keepersecurity.com)

### Reporting Issues
If you encounter bugs or have feature requests, please [open an issue](https://github.com/Keeper-Security/keeper-sdk-dotnet/issues).

### Enterprise Support
For enterprise support and custom integrations, contact our team at commander@keepersecurity.com.

---

##  About Keeper Security

Keeper Security is the leading cybersecurity platform for preventing password-related data breaches and cyberthreats. Trusted by millions of individuals and thousands of organizations worldwide.

**Learn more:** [keepersecurity.com](https://keepersecurity.com)

