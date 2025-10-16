# Commander CLI

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/github/license/Keeper-Security/keeper-sdk-dotnet)](../LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/Keeper-Security/keeper-sdk-dotnet)

> Command-line interface for Keeper Password Manager vault management and automation

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running](#running)
- [Quick Start Guide](#quick-start-guide)
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Examples](#examples)
- [SDK Integration](#sdk-integration)
- [Support](#support)

## Overview

Commander CLI is a full-featured command-line application built on the Keeper .NET SDK. It provides interactive and scriptable access to your Keeper vault, enabling record management, folder operations, sharing, enterprise administration, and more.

## Features

- **Vault Management** - Full access to records, folders, and shared folders
- **Record Operations** - Create, read, update, delete records with attachments
- **Folder Management** - Organize your vault with folders and subfolders
- **Sharing** - Manage shared folders and record permissions
- **Enterprise Administration** - User, team, role, and device management
- **BreachWatch Integration** - Monitor compromised credentials
- **Secrets Manager** - KSM commands for application secrets
- **Security Reports** - Generate password security reports
- **Audit Logs** - Access enterprise audit trail
- **Import/Export** - Bulk operations with JSON files
- **Interactive Shell** - Tab completion and command history
- **Cross-Platform** - Works on Windows, macOS, and Linux

## Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download) or later
- .NET Framework 4.7.2+ (Windows only)
- A Keeper Security account ([sign up here](https://keepersecurity.com))

### Building

#### Clone the Repository

```bash
git clone https://github.com/Keeper-Security/keeper-sdk-dotnet.git
cd keeper-sdk-dotnet
```

#### Build the Commander CLI

```bash
# Build Commander project only
dotnet build Commander/Commander.csproj

# Or build entire solution
dotnet build KeeperSdk.sln
```

#### Build Output Locations

- **.NET 8.0**: `Commander/bin/Debug/net8.0/`
- **.NET Framework 4.7.2** (Windows): `Commander/bin/Debug/net472/`

### Running

#### Option 1: Run from Build Directory

```bash
# .NET 8.0
cd Commander/bin/Debug/net8.0
dotnet Commander.dll

# Windows with .NET Framework
cd Commander\bin\Debug\net472
Commander.exe
```

#### Option 2: Run Directly from Project

```bash
dotnet run --project Commander/Commander.csproj
```

## Quick Start Guide

### First Time Setup

1. **Launch Commander** - You'll see the interactive prompt:
   ```
   My Vault>
   ```

2. **Login to Keeper**:
   ```bash
   My Vault> login
   ```
   
   Enter your credentials when prompted:
   - Email address
   - Master password
   - Two-factor authentication code (if enabled)
   - Approve device if required

3. **Sync Your Vault**:
   ```bash
   My Vault> sync-down
   # or use the alias
   My Vault> d
   ```

4. **List Your Records**:
   ```bash
   My Vault> list
   # or
   My Vault> ls -l
   ```

5. **Get Record Details**:
   ```bash
   My Vault> get <record-uid-or-title>
   ```

### Basic Workflow Example

```bash
# Login and sync
My Vault> login
My Vault> sync-down

# Navigate folders
My Vault> ls
My Vault> cd Work/Production
Work/Production> tree

# Search for records
Work/Production> search database
Work/Production> list password:.*123.*

# Get record information
Work/Production> get "MySQL Database"

# Create a new record
Work/Production> add-record
Title: API Server
Login: admin
Password: <generated>
URL: https://api.example.com

# Update existing record
Work/Production> update-record "API Server" --password <new-password>

# Upload attachment
Work/Production> upload-attachment "API Server" ~/config.json

# Share a record
Work/Production> share-record "API Server" --email user@company.com --write
```

## Command Reference

### Authentication Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `login` | | Login to your Keeper account |
| `sync-down` | `d` | Download & decrypt vault data |
| `logout` | | Logout and clear session |
| `whoami` | | Display current user information |

### Vault Navigation & Search

| Command | Alias | Description |
|---------|-------|-------------|
| `search` | `list` | Search vault (supports regex patterns) |
| `ls` | | List current folder contents |
| `cd` | | Change current folder |
| `tree` | | Display folder structure as tree |

### Record Management

| Command | Alias | Description |
|---------|-------|-------------|
| `get` | | Get detailed information about records, folders, teams, etc. |
| `add-record` | `add` | Create a new record |
| `update-record` | `edit` | Update existing record |
| `rm` | | Remove record(s) |
| `mv` | | Move record or folder to different location |
| `record-history` | | Display record version history |
| `record-type-info` | `rti` | Get record type information |
| `share-record` | | Manage record sharing permissions |

### Attachment Management

| Command | Alias | Description |
|---------|-------|-------------|
| `download-attachment` | | Download file attachment(s) from record |
| `upload-attachment` | | Upload file attachment to record |
| `delete-attachment` | | Delete attachment from record |

### Folder Management

| Command | Alias | Description |
|---------|-------|-------------|
| `mkdir` | | Create new folder |
| `rmdir` | | Remove folder |
| `update-dir` | | Update folder properties |

### Shared Folder Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `sf-list` | | List all shared folders |
| `sf-user` | | Manage shared folder user permissions |
| `sf-record` | | Manage shared folder record permissions |

### Trash Management

| Command | Alias | Description |
|---------|-------|-------------|
| `trash` | | Manage deleted records in trash |

### Device Management

| Command | Alias | Description |
|---------|-------|-------------|
| `devices` | | Manage other devices |
| `this-device` | | Manage current device settings |

### Enterprise Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `enterprise-get-data` | `eget` | Retrieve enterprise data |
| `enterprise-node` | `en` | Manage enterprise organizational nodes |
| `enterprise-user` | `eu` | Manage enterprise users |
| `enterprise-team` | `et` | Manage enterprise teams |
| `enterprise-role` | `er` | Manage enterprise roles |
| `enterprise-device` | `ed` | Manage user devices |
| `transfer-user` | | Transfer user account ownership |
| `extend-account-share-expiration` | | Extend account share expiration |
| `audit-report` | | Run audit trail reports |

### Record Type Management

| Command | Alias | Description |
|---------|-------|-------------|
| `record-type-add` | | Add a new custom record type |
| `record-type-update` | | Update existing record type |
| `record-type-delete` | | Delete custom record type |
| `load-record-types` | | Bulk load record types from JSON file |
| `download-record-types` | | Export record types to JSON file |

### Security & Reporting

| Command | Alias | Description |
|---------|-------|-------------|
| `password-report` | | Generate comprehensive password security report |
| `breachwatch` | | BreachWatch security monitoring commands |

### Other Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `ksm` | | Keeper Secrets Manager commands |
| `one-time-share` | | Manage one-time secure shares |
| `import` | | Import records from JSON file |
| `clear` | `c` | Clear the screen |
| `help` | `?` | Display help information |
| `quit` | `q` | Exit Commander |

## Configuration

### Configuration Storage

Commander stores configuration data securely on your local system:

- **Device token** - Avoids repeated two-factor authentication
- **Last login email** - Pre-fills login prompt
- **Session data** - Maintains authentication state

**Storage Locations:**
- **Windows**: `%APPDATA%\Keeper\`
- **macOS/Linux**: `~/.keeper/`

This configuration is shared across all Keeper .NET SDK applications, allowing seamless switching between Commander CLI, PowerCommander, and custom applications.

### Environment Variables

Configure Commander behavior with environment variables:

```bash
# Set custom configuration directory
export KEEPER_CONFIG_DIR=/path/to/config

# Enable debug logging
export KEEPER_DEBUG=true
```

## Examples

### Password Change Script

```bash
# Login and sync
login
sync-down

# Find database record
search "Production Database"

# Update password
update-record "Production Database" --password <new-secure-password>

# Verify update
get "Production Database"
```

### Bulk Record Import

```bash
# Prepare records.json file with your data
# Then import
import --file records.json --folder "Imported Records"
```

### Enterprise User Management

```bash
# Get enterprise data
enterprise-get-data

# List users
enterprise-user list

# Add user to team
enterprise-user add-to-team user@company.com "Engineering Team"

# Assign role
enterprise-role assign user@company.com "Administrator"
```

### Security Audit

```bash
# Generate password report
password-report --output report.csv

# Check BreachWatch status
breachwatch scan

# Generate audit report
audit-report --report-type=raw --report-format=csv --target=user@company.com
```

## SDK Integration

Commander CLI is a reference implementation built on the Keeper .NET SDK. For integrating Keeper into your own applications, see the [Sample Applications](../Sample/) which demonstrate:

### Example Applications

| Sample | Description | Features |
|--------|-------------|----------|
| [BasicAuthExample.cs](../Sample/BasicAuthExample.cs) | Simple authentication example | Master password auth, 2FA, device approval, basic vault sync |
| [Program.cs](../Sample/Program.cs) | Comprehensive SDK example | Advanced auth flows, typed records, attachments, shared folders, enterprise features |
| [WPFSample](../WPFSample/) | Desktop GUI application | Windows Presentation Foundation (WPF) integration |

### Key SDK Features Demonstrated

- **Authentication Flows**:
  - Master password authentication
  - Two-factor authentication (2FA)
  - Device approval workflow
  - Session management
  
- **Vault Operations**:
  - Creating and updating typed records
  - File attachment operations (upload/download/delete)
  - Folder and shared folder management
  - Non-shared data storage

- **Enterprise Features**:
  - User and team management
  - Role-based access control (RBAC)
  - Device management
  - Audit log retrieval

For complete SDK documentation, see:
- [.NET SDK README](../KeeperSdk/README.md)
- [Sample Applications README](../Sample/README.md)
- [API Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)

## Troubleshooting

### Common Issues

**Issue: Login fails with "Invalid credentials"**
- Verify email and password are correct
- Check if 2FA code is required
- Ensure account is not locked

**Issue: Device approval required**
- Check your email for approval link
- Use `this-device` command to manage device settings
- Contact administrator if device approval is blocked

**Issue: "Vault out of sync" error**
- Run `sync-down` to refresh vault data
- Logout and login again if issue persists

**Issue: Permission denied on record operations**
- Verify you have appropriate permissions for the record/folder
- Check shared folder permissions with `sf-list`

## Support

### Get Help

- **Email**: commander@keepersecurity.com
- **Documentation**: [docs.keeper.io](https://docs.keeper.io/)
- **GitHub Issues**: [Report bugs or request features](https://github.com/Keeper-Security/keeper-sdk-dotnet/issues)
- **Website**: [keepersecurity.com](https://keepersecurity.com)
