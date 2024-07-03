using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public static class EnterpriseUtils
    {

        public static string EncryptEncryptedData(EncryptedData encryptedData, byte[] encryptionKey)
        {
            return CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(encryptedData), encryptionKey).Base64UrlEncode();
        }

        public static void DecryptEncryptedData(string encryptedData, byte[] encryptionKey, IDisplayName entity)
        {
            if (string.IsNullOrEmpty(encryptedData)) return;

            try
            {
                var encryptedBytes = encryptedData.Base64UrlDecode();
                if (encryptedBytes != null && encryptedBytes.Length > 0)
                {
                    var jData = CryptoUtils.DecryptAesV1(encryptedBytes, encryptionKey);
                    var data = JsonUtils.ParseJson<EncryptedData>(jData);
                    entity.DisplayName = data.DisplayName;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }
    }
}
