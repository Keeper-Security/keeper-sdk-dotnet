<img src="https://github.com/Keeper-Security/Commander/blob/master/images/commander-black.png" alt="Keeper Commander" height="167"/>

### .Net and PowerShell SDK for Keeper Password Manager

The Keeper .Net and PowerShell module ("PowerCommander") provides vault and administrative level automation. The current features of the .Net and PowerShell library include the following:

* Authenticate to Keeper
* Access the Keeper vault (records, folders, shared folders)
* Manage records (CRUD operations for Records, Attachments, Folders, Shared Folders)
* Administrative functions (Team Management)
* Customize integration into your backend systems
* Update/Rotate passwords in the vault

Additional development tools in Python and other languages is available at our [Secrets Manager](https://docs.keeper.io/secrets-manager/) portal.

## Components

### .Net SDK
For source integration into your .Net code, please utilize the [KeeperSDK Library source code](https://github.com/Keeper-Security/keeper-sdk-dotnet/tree/master/KeeperSdk).

**Resources:**
* [User Guide](https://docs.keeper.io/en/v/secrets-manager/commander-cli/commander-installation-setup/net-developer-sdk)
* [API Documentation](https://keeper-security.github.io/gitbook-keeper-sdk/CSharp/html/R_Project_Documentation.htm)

**Developer Requirements:**
* .Net Core 8.0
* .Net Standard 2.0

### Commander CLI
A command-line application built using the .Net SDK for vault management and automation.

* [Commander CLI Documentation](Commander/README.md) - Complete command reference and usage guide
* Features include login, vault sync, record management, shared folders, enterprise commands, and more

### PowerShell Module (PowerCommander)
PowerShell module for Keeper vault and administrative automation.

* [PowerCommander Documentation](PowerCommander/README.md) - Full cmdlet reference and examples
* Install from PowerShell Gallery: `Install-Module -Name PowerCommander`
* Includes cmdlets for vault operations, enterprise management, BreachWatch, and Secret Manager

### Sample Applications
Code examples demonstrating SDK integration:

* **[Sample Applications](Sample/README.md)** - Working code examples:
  - [BasicAuthExample.cs](Sample/BasicAuthExample.cs) - Simple authentication and vault sync
  - [Program.cs](Sample/Program.cs) - Comprehensive example with record management, attachments, sharing, and enterprise features
* **[Commander CLI](Commander/README.md)** - Full-featured command-line application for vault management
* **[WPFSample](WPFSample)** - Windows Presentation Foundation (WPF) GUI example

### About Keeper Security
Keeper is the leading cybersecurity platform for preventing password-related data breaches and cyberthreats.

Learn More at:
[https://keepersecurity.com](https://keepersecurity.com)

### Contact Us
If you need any assistance or require specific functionality not supported in Commander yet, please contact us at commander@keepersecurity.com.

