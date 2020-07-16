using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Sdk;
using System.Security.Cryptography;

namespace Commander
{
    public class CommanderStorageProtection: IStorageProtectionFactory
    {
        public IStorageProtection Resolve(string protection)
        {
            if (string.IsNullOrEmpty(protection)) return null;
            var index = protection.IndexOf(':');
            var method = protection;
            var parameters = "";
            if (index > 0)
            {
                method = protection.Substring(0, index);
                parameters = protection.Substring(index + 1);
            }

            switch (method.ToLowerInvariant())
            {
                case "dpapi":
                    return new DpApiStorageProtection(Encoding.UTF8.GetBytes(parameters));
            }

            return null;
        }
    }

    internal class DpApiStorageProtection : IStorageProtection
    {
        private readonly byte[] _entropy;
        private readonly DataProtectionScope _scope;

        public DpApiStorageProtection(byte[] entropy) : this(entropy, DataProtectionScope.CurrentUser)
        {
        }

        public DpApiStorageProtection(byte[] entropy, DataProtectionScope scope)
        {
            _entropy = entropy;
            _scope = DataProtectionScope.CurrentUser;
        }

        public string Obscure(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var secured = ProtectedData.Protect(Encoding.UTF8.GetBytes(data), _entropy, _scope);
            return secured.Base64UrlEncode();
        }

        public string Clarify(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var cleared = ProtectedData.Unprotect(data.Base64UrlDecode(), _entropy, _scope);
            return Encoding.UTF8.GetString(cleared);
        }
    }
}
