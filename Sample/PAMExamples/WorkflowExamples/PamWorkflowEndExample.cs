using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Ends or force-checks-in a PAM workflow.</summary>
    public static class PamWorkflowEndExample
    {
        public static async Task End(VaultOnline vault, string recordUid, bool force = false)
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
            var state = await WorkflowUtils.GetWorkflowStateByRecordAsync(
                vault.Auth, record.Uid, record.Title);
            if (state == null || state.FlowUid.IsEmpty)
            {
                Console.WriteLine($"No active workflow found for {record.Title}.");
                return;
            }

            var workflowRef = WorkflowUtils.WorkflowRef(state.FlowUid.ToByteArray());
            if (force)
            {
                await WorkflowUtils.ForceCheckinAsync(vault.Auth, workflowRef);
            }
            else
            {
                await WorkflowUtils.EndWorkflowAsync(vault.Auth, workflowRef);
            }

            Console.WriteLine(force ? "Workflow force checked in." : "Workflow ended.");
        }
    }
}
