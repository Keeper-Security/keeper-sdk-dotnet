using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class ShareKeeperNSFRecord
    {
        public static async Task Share(
            VaultOnline vault,
            string recordUid,
            string userEmail,
            string role = "viewer")
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.ShareKeeperNSFRecord(recordUid, userEmail, role);
                Console.WriteLine($"Shared record {recordUid} with {userEmail} as {role}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sharing Keeper NSF record: {ex.Message}");
            }
        }
    }
}
