using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Deletes PAM workflow settings from a resource.</summary>
    public static class PamWorkflowDeleteExample
    {
        public static async Task DeleteWorkflow(VaultOnline vault, string recordUid)
        {
            if (vault == null)
                {
                    throw new ArgumentNullException(nameof(vault));
                }

                var record = PamVaultHelpers.ResolveRecord(
                    vault, recordUid?.Trim(), PamRecordTypes.Workflow);
                if (record == null)
                {
                    throw new InvalidOperationException(
                        $"PAM workflow record '{recordUid}' was not found.");
                }
            await WorkflowUtils.DeleteWorkflowConfigAsync(vault.Auth, record.Uid, record.Title);
            Console.WriteLine($"Workflow deleted for {record.Title} ({record.Uid}).");
        }
    }
}
