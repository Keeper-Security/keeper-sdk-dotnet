# Commander CLI

This folder contains a sample Commander CLI application using the .NET SDK. Commander provides a command-line interface for managing your Keeper vault, including record management, folder operations, sharing, and enterprise administration.

## Getting Started

### Prerequisites

* .NET Core 8.0 SDK or later
* .NET Framework 4.7.2 (for Windows)
* A Keeper Security account

### Building the Application

1. **Clone the repository** (if you haven't already):
   ```bash
   git clone https://github.com/Keeper-Security/keeper-sdk-dotnet.git
   cd keeper-sdk-dotnet
   ```

2. **Build the solution**:
   ```bash
   dotnet build Commander/Commander.csproj
   ```

   Or build the entire solution:
   ```bash
   dotnet build KeeperSdk.sln
   ```

3. **Build output** will be located in:
   * `Commander/bin/Debug/net8.0/` (for .NET 8.0)
   * `Commander/bin/Debug/net472/` (for .NET Framework 4.7.2)

### Running the Application

Navigate to the build output directory and run:

```bash
cd Commander/bin/Debug/net8.0
dotnet Commander.dll
```

Or on Windows with .NET Framework:
```bash
cd Commander\bin\Debug\net472
Commander.exe
```

Alternatively, run directly from the project directory:
```bash
dotnet run --project Commander/Commander.csproj
```

### First-Time Setup

1. **Launch Commander** and you'll see the prompt:
   ```
   My Vault>
   ```

2. **Login to your Keeper account**:
   ```
   My Vault> login
   ```
   
3. **Enter your credentials** when prompted:
   * Email address
   * Master password
   * Two-factor authentication code (if enabled)
   * Approve device if required

4. **Sync your vault**:
   ```
   My Vault> sync-down
   ```
   or simply:
   ```
   My Vault> d
   ```

5. **List your records**:
   ```
   My Vault> list
   ```
   or:
   ```
   My Vault> ls -l
   ```

### Configuration Storage

Commander stores configuration data (last login, device token, etc.) in same location no matter which SDK is used. This allows you to avoid re-entering credentials on subsequent launches.

## Command Reference

### Basic Commands

* ```login``` Login to Keeper

* ```logout``` Logout from Keeper

* ```sync-down``` or ```d``` Download, sync and decrypt vault

* ```list``` or ```ls``` List all records (try ```ls -l``` as well)

* ```tree``` Display entire folder structure as a tree

* ```cd``` Change current folder

* ```get``` Retrieve and display specified Keeper Record/Folder/Team in printable or JSON format

* ```mkdir``` Create a regular or shared folder in the vault

* ```rmdir``` Delete folder and its content

* ```mv``` Move record or folder to another location

* ```rm``` Remove record

### Shared Folder Commands

* ```sf-list``` Display all shared folders

* ```sf-user``` Manage user or team access for shared folder

* ```sf-record``` Change record permissions. Use `mv` or `rm` commands to add/remove record to/from shared folder

### Device Management Commands

* ```devices``` Manage device approval queue

* ```this-device``` Display or modify current device settings

### Record Management Commands

* ```add-record``` Add a record to the vault

* ```update-record``` Update a record contents such as the password

### Enterprise Commands

* ```enterprise-get-data``` Retrieve enterprise data structure

* ```enterprise-node``` Display enterprise node tree

* ```enterprise-user``` Display a list of enterprise users

* ```enterprise-team``` Display a list of enterprise users, manage team's users

* ```enterprise-role``` Display a list of enterprise roles, manage role's users and teams

* ```enterprise-device``` Manage admin approval queue. Cloud SSO only.

## SDK Integration Examples

For integrating the Keeper SDK into your own applications, see the [Sample folder](../Sample) which contains working examples:

* **[BasicAuthExample.cs](../Sample/BasicAuthExample.cs)** - Simple authentication example showing:
  - Master password authentication
  - Two-factor authentication (2FA)
  - Device approval flow
  - Basic vault synchronization
  - Using `AuthSync` and `SimpleInputManager` for console applications

* **[Program.cs](../Sample/Program.cs)** - Comprehensive SDK example demonstrating:
  - Advanced authentication flows
  - Creating and updating typed records
  - File attachment operations (upload/download/delete)
  - Shared folder management
  - Enterprise features (teams, users, roles)
  - Non-shared data storage

For complete documentation and usage instructions, see the [Sample README](../Sample/README.md).
