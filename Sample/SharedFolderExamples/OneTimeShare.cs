using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.OneTimeShareExamples
{
    public static class OneTimeShare
    {
        public static async Task ShareRecordOneTime(VaultOnline vault, string recordUid, TimeSpan expireIn, string shareName = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = await ShareRecordOneTimeSimple(vault, recordUid, expireIn, shareName);
            Console.WriteLine("One-Time Share URL:");
            Console.WriteLine(result);
        }

        public static async Task<string> ShareRecordOneTimeSimple(
            VaultOnline vault,
            string recordUid,
            TimeSpan expireIn,
            string shareName = null)
        {
            try
            {
                var shareUrl = await vault.CreateExternalRecordShare(
                    recordUid,
                    expireIn,
                    shareName);
                return shareUrl;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
        }
    }
}