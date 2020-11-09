using System;
using System.Collections.Generic;
using System.Text;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Configuration
{
    /// <summary>
    /// Provides default implementation of <c>IConfigurationProtectionFactory</c> interface
    /// </summary>
    /// <seealso cref="IConfigurationProtectionFactory"/>
    public class ConfigurationProtectionFactory : IConfigurationProtectionFactory
    {
        private readonly Dictionary<string, IConfigurationProtection> _registeredProtection =
            new Dictionary<string, IConfigurationProtection>(StringComparer.InvariantCultureIgnoreCase);

        /// <summary>
        /// Finds registered <see cref="IConfigurationProtection"/> instance by name.
        /// </summary>
        /// <param name="protection"></param>
        /// <returns>Configuration protection</returns>
        public IConfigurationProtection Resolve(string protection)
        {
            return _registeredProtection.TryGetValue(protection, out var sp) ? sp : null;
        }

        /// <summary>
        /// Registers a <see cref="IConfigurationProtection"/> instance.
        /// </summary>
        /// <param name="protection">Name</param>
        /// <param name="configurationProtector">Configuration protection Instance</param>
        public void RegisterProtection(string protection, IConfigurationProtection configurationProtector)
        {
            _registeredProtection[protection] = configurationProtector;
        }
    }

    /// <summary>
    /// Provides <see cref="IConfigurationProtection"/> implementation that uses AES GCM encryption.
    /// </summary>
    /// <seealso cref="IConfigurationProtection"/>
    public class KeeperEncryptionAesV2Protector : IConfigurationProtection
    {
        private readonly byte[] _aesKey;

        /// <summary>
        /// Initializes a new instance on the <see cref="KeeperEncryptionAesV2Protector"/> class
        /// </summary>
        /// <param name="aesKey">32 bytes AES GCM encryption key.</param>
        public KeeperEncryptionAesV2Protector(byte[] aesKey)
        {
            _aesKey = aesKey;
        }

        /// <summary>
        /// Encrypts / Obfuscates text.
        /// </summary>
        /// <param name="data">Plain test</param>
        /// <returns>Encrypted text.</returns>
        public string Obscure(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var encryptedData = CryptoUtils.EncryptAesV2(Encoding.UTF8.GetBytes(data), _aesKey);
            return encryptedData.Base64UrlEncode();
        }

        /// <summary>
        /// Decrypts previously encrypted text.
        /// </summary>
        /// <param name="data">Encrypted text</param>
        /// <returns>Plain text.</returns>
        public string Clarify(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var decryptedData = CryptoUtils.DecryptAesV2(data.Base64UrlDecode(), _aesKey);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
