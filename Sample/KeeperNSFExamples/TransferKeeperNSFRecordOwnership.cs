using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class TransferKeeperNSFRecordOwnership
    {
        public static async Task Transfer(
            VaultOnline vault,
            IReadOnlyList<string> recordUidOrTitles,
            string newOwnerEmail)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                var results = await vault.TransferKeeperNSFRecordOwnership(recordUidOrTitles, newOwnerEmail);
                foreach (var r in results)
                {
                    Console.WriteLine(
                        $"Record {r.RecordUid}: {(r.Success ? "OK" : "FAILED")} — {r.Message ?? r.Status}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error transferring ownership: {ex.Message}");
            }
        }
    }
}
