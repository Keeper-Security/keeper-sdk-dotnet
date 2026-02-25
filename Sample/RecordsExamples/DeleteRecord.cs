using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;
using System.Collections.Generic;

namespace Sample.RecordsExamples
{
    class DeleteRecordExample
    {
        public static async Task DeleteRecord(string recordUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault reference is null.");
                return;
            }

            await DeleteRecordSimple(
                vault,
                recordUid
            );
        }

        private static async Task DeleteRecordSimple(
            VaultOnline vault,
            string recordUid)
        {
            if (vault == null)
            {
                Console.WriteLine("Vault reference is null.");
                return;
            }

            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                Console.WriteLine($"Record '{recordUid}' not found.");
                return;
            }

            var folders = Enumerable.Repeat(vault.RootFolder, 1)
                .Concat(vault.Folders)
                .Where(f => f.Records != null && f.Records.Contains(recordUid))
                .ToArray();

            if (folders.Length == 0)
            {
                Console.WriteLine($"Record '{recordUid}' not found in any folder. Using empty folder UID.");
                await vault.DeleteRecords(new[]
                {
                    new RecordPath { FolderUid = "", RecordUid = recordUid }
                });
                Console.WriteLine($"Record '{recordUid}' deleted successfully.");
                return;
            }

            var folder = folders.FirstOrDefault(f => string.IsNullOrEmpty(f.FolderUid))
                ?? folders.FirstOrDefault(f => f.FolderType == FolderType.UserFolder)
                ?? folders[0];


            await vault.DeleteRecords(new[]
            {
                new RecordPath { FolderUid = folder.FolderUid, RecordUid = recordUid }
            });

            Console.WriteLine($"Record '{recordUid}' deleted successfully from folder '{folder.Name}' ({folder.FolderUid}).");
        }



    }
}