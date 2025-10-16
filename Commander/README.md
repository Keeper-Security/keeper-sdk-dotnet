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


### Commander CLI Commands Reference

#### Authentication Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `sync-down` | `d` | Download & decrypt data |
| `logout` | | Logout |
| `whoami` | | Display information about the currently logged in user |

#### Vault Navigation & Search
| Command | Alias | Description |
|---------|-------|-------------|
| `search` | `list` | Search the vault. Can use a regular expression |
| `ls` | | List folder content |
| `cd` | | Change current folder |
| `tree` | | Display folder structure |

#### Record Management
| Command | Alias | Description |
|---------|-------|-------------|
| `get` | | Get information about any Keeper object (record, folder, team, etc.) |
| `add-record` | `add` | Add record |
| `update-record` | `edit` | Update record |
| `rm` | | Remove record(s) |
| `mv` | | Move record or folder |
| `record-history` | | Display record history |
| `record-type-info` | `rti` | Get record type info |
| `share-record` | | Change the sharing permissions of an individual record |

#### Attachment Management
| Command | Alias | Description |
|---------|-------|-------------|
| `download-attachment` | | Download Attachment(s) |
| `upload-attachment` | | Upload file attachment |
| `delete-attachment` | | Delete attachment |

#### Folder Management
| Command | Alias | Description |
|---------|-------|-------------|
| `mkdir` | | Make folder |
| `rmdir` | | Remove folder |
| `update-dir` | | Update folder |

#### Shared Folder Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `sf-list` | | List shared folders |
| `sf-user` | | Change shared folder user permissions |
| `sf-record` | | Change shared folder record permissions |

#### Trash Management
| Command | Alias | Description |
|---------|-------|-------------|
| `trash` | | Manage deleted records in trash |

#### Device Management
| Command | Alias | Description |
|---------|-------|-------------|
| `devices` | | Devices (other than current) commands |
| `this-device` | | Current device command |

#### Enterprise Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `enterprise-get-data` | `eget` | Retrieve enterprise data |
| `enterprise-node` | `en` | Manage Enterprise Nodes |
| `enterprise-user` | `eu` | Manage Enterprise Users |
| `enterprise-team` | `et` | Manage Enterprise Teams |
| `enterprise-role` | `er` | Manage Enterprise Roles |
| `enterprise-device` | `ed` | Manage User Devices |
| `transfer-user` | | Transfer User Account |
| `extend-account-share-expiration` | | Extend Account Share Expiration |
| `audit-report` | | Run an audit trail report |

#### Record Type Management
| Command | Alias | Description |
|---------|-------|-------------|
| `record-type-add` | | Add a new Record Type |
| `record-type-update` | | Updates a Record Type of given ID |
| `record-type-delete` | | Deletes a Record Type of given ID |
| `load-record-types` | | Loads Record Types to keeper from given file |
| `download-record-types` | | Downloads Record Types from keeper to given file |

#### Security & Reporting
| Command | Alias | Description |
|---------|-------|-------------|
| `password-report` | | Generate comprehensive password security report |
| `breachwatch` | | BreachWatch commands |

#### Other Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `ksm` | | Keeper Secret Manager commands |
| `one-time-share` | | Manage One Time Shares |
| `import` | | Imports records from JSON file |
| `clear` | `c` | Clears the screen |
| `quit` | `q` | Quit |

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
