using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;

namespace Sample.RemoveOneTimeShareExamples
{
    public static class RemoveOneTimeShare
    {
        public static async Task RemoveOneTimeShareRecord(string recordUid, IEnumerable<string> clientIds)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var result = await RemoveOneTimeShareSimple(vault, recordUid, clientIds);
            if (result)
            {
                Console.WriteLine("Successfully removed One Time Share");
            }
            else
            {
                Console.WriteLine("Failed to removed One Time Share");
            }
        }

        public static async Task<bool> RemoveOneTimeShareSimple(VaultOnline vault, string recordUid, IEnumerable<string> clientIds)
        {
            try
            {
                await vault.DeleteExernalRecordShares(
                   recordUid,
                   clientIds
                   );
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }

    }
}