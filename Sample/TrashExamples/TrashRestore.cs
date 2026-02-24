using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Linq;
using System.Collections.Generic;

namespace Sample.TrashExamples
{
    public static class TrashRestore
    {
        public static async Task TrashRestoreAsync(List<string> records)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                await TrashManagement.RestoreTrashRecords(vault, records.ToList());
                Console.WriteLine($"Successfully restored {records.Count} records");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to restore records: {ex.Message}");
            }
        }
    }
}