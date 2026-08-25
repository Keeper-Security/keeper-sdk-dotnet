using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ActionExamples
{
    /// <summary>
    /// Schedules an on-demand PAM credential rotation via <see cref="ActionUtils.RotateAsync"/>.
    /// </summary>
    public static class RotateExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="recordUid">UID of the PAM user record to rotate. Ignored if folder <paramref name="folder"/> is provided.</param>
        /// <param name="folder"> Shared folder UID or title pattern. Rotates all PAM user records in matching folders.</param>
        /// <param name="dryRun">If set to true with <paramref name="folder"/>, only shows which records would be selected without rotating them.</param>
        public static async Task Rotate(
            VaultOnline vault,
            string recordUid = null,
            string folder = null,
            bool dryRun = false)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(recordUid) && string.IsNullOrWhiteSpace(folder))
                {
                    Console.WriteLine("Either recordUid or folder is required.");
                    return;
                }

                var result = await ActionUtils.RotateAsync(vault, new PamRotateOptions
                {
                    RecordUid = recordUid,
                    Folder = folder,
                    DryRun = dryRun,
                });

                if (result.IsFolderMode)
                {
                    var folderResult = result.FolderResult;
                    Console.WriteLine(
                        $"Selected for rotation - folders: {folderResult.FolderCount}, records: {folderResult.RecordCount}");

                    if (folderResult.DryRun)
                    {
                        return;
                    }

                    foreach (var item in folderResult.Results)
                    {
                        PrintResult(item);
                    }

                    foreach (var error in folderResult.Errors)
                    {
                        Console.WriteLine($"Record {error.RecordUid} skipped: {error.Message}");
                    }

                    return;
                }

                PrintResult(result.RecordResult);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static void PrintResult(PamGatewayActionResult result)
        {
            if (result == null)
            {
                return;
            }

            if (!result.IsOk)
            {
                Console.WriteLine(result.RawPayloadJson ?? "Rotate failed.");
                return;
            }

            if (result.IsScheduled)
            {
                Console.WriteLine($"Scheduled action id: {result.ConversationId}");
                Console.WriteLine(
                    $"Use JobInfoExample.GetJobInfo(vault, \"{result.ConversationId}\", \"{result.GatewayUid}\") to check status.");
                return;
            }

            if (!string.IsNullOrEmpty(result.RawPayloadJson))
            {
                Console.WriteLine(result.RawPayloadJson);
            }
        }
    }
}
