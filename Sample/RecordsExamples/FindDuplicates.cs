using Cli;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sample.RecordsExamples
{
    public static class FindDuplicatesExample
    {
        public static async Task FindDuplicates(VaultOnline vault = null,
            bool byTitle = true,
            bool byLogin = true,
            bool byPassword = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null)
            {
                Console.WriteLine("Failed to authenticate.");
                return;
            }

            var records = vault.KeeperRecords.ToList();
            Console.WriteLine($"Searching {records.Count} records for duplicates...");

            var fields = new List<string>();
            if (byTitle) fields.Add("Title");
            if (byLogin) fields.Add("Login");
            if (byPassword) fields.Add("Password");
            Console.WriteLine($"Comparing by: {string.Join(", ", fields)}");
            Console.WriteLine();

            var hashMap = new Dictionary<string, List<KeeperRecord>>();
            foreach (var record in records)
            {
                var hash = CreateHash(record, byTitle, byLogin, byPassword);
                if (string.IsNullOrEmpty(hash)) continue;

                if (!hashMap.ContainsKey(hash))
                    hashMap[hash] = new List<KeeperRecord>();
                hashMap[hash].Add(record);
            }

            var duplicates = hashMap.Where(g => g.Value.Count > 1).ToList();

            if (duplicates.Count == 0)
            {
                Console.WriteLine("No duplicate records found.");
                return;
            }

            Console.WriteLine($"Found {duplicates.Count} duplicate group(s):");
            Console.WriteLine();

            var table = new Tabulate(4);
            table.AddHeader("Group", "UID", "Title", "Login");

            var groupNum = 1;
            foreach (var group in duplicates)
            {
                var isFirst = true;
                foreach (var record in group.Value)
                {
                    table.AddRow(
                        isFirst ? groupNum.ToString() : "",
                        record.Uid,
                        record.Title,
                        record.ExtractLogin() ?? "N/A"
                    );
                    isFirst = false;
                }
                groupNum++;
            }

            table.Dump();

            var totalDuplicates = duplicates.Sum(g => g.Value.Count - 1);
            Console.WriteLine($"Total: {totalDuplicates} duplicate record(s) can be removed.");
        }

        private static string CreateHash(KeeperRecord record, bool byTitle, bool byLogin, bool byPassword)
        {
            var parts = new List<string>();

            if (byTitle)
                parts.Add(record.Title ?? "");
            if (byLogin)
                parts.Add(record.ExtractLogin() ?? "");
            if (byPassword)
                parts.Add(record.ExtractPassword() ?? "");

            var combined = string.Join("|", parts);
            if (string.IsNullOrWhiteSpace(combined))
                return null;

            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(combined);
                var hash = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
