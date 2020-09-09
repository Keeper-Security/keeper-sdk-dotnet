### .Net and PowerShell SDK for Keeper Password Manager

The Keeper .Net and PowerShell module ("PowerCommander") provides basic vault API access. The current features of the .Net and PowerShell library include the following:

* Access your Keeper vault (records, folders, shared folders)
* Manage records (Retrieve/Add/Edit)
* Customize integration into your backend systems
* Update/Rotate passwords in the vault

### PowerShell Module
To use the PowerShell modules, see the [PowerCommander library](https://github.com/Keeper-Security/keeper-sdk-dotnet/tree/master/PowerCommander).

### .Net SDK
For integration into your .Net systems, please utilize the [KeeperSDK library](https://github.com/Keeper-Security/keeper-sdk-dotnet/tree/master/KeeperSdk).

### Sample App
For help with implementation of SDK features, please see the [Commander CLI Sample App](https://github.com/Keeper-Security/keeper-sdk-dotnet/tree/master/Commander).  This application contains several basic operations such as logging in, authentication with two-factor, loading and decrypting the vault and updating passwords.

### Developer Requirements for KeeperSDK Library

* .Net Framework 4.6.1
* .Net Core 2.1
* .Net Standard 2.0

If you need any assistance or require specific functionality not supported in Commander yet, please contact us at commander@keepersecurity.com.

### About Keeper Security

Keeper Security develops the world's most downloaded password manager and encrypted digital vault with millions of individual customers and thousands of enterprise customers worldwide.  Keeper is a zero-knowledge, native and cloud-based solution available on every mobile and desktop device platform. Learn more about Keeper by visiting the [Keeper Security](https://keepersecurity.com) website.

### Security

Keeper is a Zero Knowledge security provider. Zero Knowledge is a system architecture that guarantees the highest levels of security and privacy by adhering to the following principles:

- Data is encrypted and decrypted at the device level (not on the server)
- The application never stores plain text (human readable) data
- The server never receives data in plain text
- No Keeper employee or 3rd party can view the unencrypted data
- The keys to decrypt and encrypt data are derived from the user’s master password
- Multi-Layer encryption provides access control at the user, group and admin level
- Sharing of data uses Public Key Cryptography for secure key distribution

Data is encrypted locally on the user’s device before it is transmitted and stored in Keeper’s Cloud Security Vault. When data is synchronized to another device, the data remains encrypted until it is decrypted on the other device.

Keeper is the most secure, certified, tested and audited password security platform in the world. We are the only SOC 2 and ISO 27001 certified password management solution in the industry and Privacy Shield Compliant with the U.S. Department of Commerce's EU-U.S. Privacy Shield program, meeting the European Commission's Directive on Data Protection. Not only do we implement the most secure levels of encryption, we also adhere to very strict internal practices that are continually audited by third parties to help ensure that we continue to develop secure software and provide the world’s most secure cybersecurity platform.

If you have any questions, please email commander@keepersecurity.com.

