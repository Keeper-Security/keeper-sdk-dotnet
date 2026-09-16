using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Reads PAM workflow settings for a resource.</summary>
    public static class PamWorkflowReadExample
    {
        public static async Task<WorkflowConfig> ReadWorkflow(VaultOnline vault, string recordUid)
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
            var config = await WorkflowUtils.ReadWorkflowConfigAsync(vault.Auth, record.Uid, record.Title);
            Console.WriteLine(config == null
                ? $"No workflow is configured for {record.Title}."
                : $"Workflow loaded for {record.Title} ({config.Approvers.Count} approver(s)).");
            return config;
        }
    }
}
