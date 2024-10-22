using System.Text;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using System.Security.Cryptography;

namespace Commander
{
    public class CommanderConfigurationProtection : IConfigurationProtectionFactory
    {
        public IConfigurationProtection Resolve(string protection)
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

#if NET472_OR_GREATER
            switch (method.ToLowerInvariant())
            {

                case "dpapi":
                    return new DpApiConfigurationProtection(Encoding.UTF8.GetBytes(parameters));
            }
#endif

            return null;
        }
    }

#if NET472_OR_GREATER

    internal class DpApiConfigurationProtection : IConfigurationProtection
    {
        private readonly byte[] _entropy;
        private readonly DataProtectionScope _scope;

        public DpApiConfigurationProtection(byte[] entropy)
        {
            _entropy = entropy;
            _scope = DataProtectionScope.CurrentUser;
        }

        public string Obscure(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var secured = ProtectedData.Protect (Encoding.UTF8.GetBytes(data), _entropy, _scope);
            return secured.Base64UrlEncode();
        }

        public string Clarify(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var cleared = ProtectedData.Unprotect(data.Base64UrlDecode(), _entropy, _scope);
            return Encoding.UTF8.GetString(cleared);
        }
    }
#endif
}
