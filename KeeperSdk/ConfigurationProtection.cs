using System;
using System.Collections.Generic;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public class ConfigurationProtectionFactory : IStorageProtectionFactory
    {
        private readonly Dictionary<string, IStorageProtection> _registeredProtection =
            new Dictionary<string, IStorageProtection>(StringComparer.InvariantCultureIgnoreCase);

        public IStorageProtection Resolve(string protection)
        {
            return _registeredProtection.TryGetValue(protection, out var sp) ? sp : null;
        }

        public void RegisterProtection(string protection, IStorageProtection storageProtector)
        {
            _registeredProtection[protection] = storageProtector;
        }
    }

    public class KeeperEncryptionAesV2Protector : IStorageProtection
    {
        private byte[] _aesKey;
        public KeeperEncryptionAesV2Protector(byte[] aesKey)
        {
            _aesKey = aesKey;
        }

        public string Obscure(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var encryptedData = CryptoUtils.EncryptAesV2(Encoding.UTF8.GetBytes(data), _aesKey);
            return encryptedData.Base64UrlEncode();
        }

        public string Clarify(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var decryptedData = CryptoUtils.DecryptAesV2(data.Base64UrlDecode(), _aesKey);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
