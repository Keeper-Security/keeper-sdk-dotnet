using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Reads the current state of a PAM workflow.</summary>
    public static class PamWorkflowStateExample
    {
        public static async Task<WorkflowState> GetState(VaultOnline vault, string recordUid)
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
            Console.WriteLine(state?.Status == null
                ? "No workflow state returned."
                : $"Workflow stage: {WorkflowUtils.FormatStage(state.Status)}");
            return state;
        }
    }
}
