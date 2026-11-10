using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Starts a checked-out PAM workflow.</summary>
    public static class PamWorkflowStartExample
    {
        public static async Task Start(VaultOnline vault, string recordUid)
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
            await WorkflowUtils.StartWorkflowAsync(vault.Auth, new WorkflowState
            {
                Resource = WorkflowUtils.CreateRecordRef(record.Uid, record.Title),
            });
            Console.WriteLine($"Workflow started for {record.Title} ({record.Uid}).");
        }
    }
}
