using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Adds users or teams to a PAM workflow approver list.</summary>
    public static class PamWorkflowAddApproverExample
    {
        public static async Task AddApprovers(
            VaultOnline vault,
            string recordUid,
            IEnumerable<string> userEmails = null,
            IEnumerable<string> teamUids = null,
            bool escalation = false,
            string escalationAfter = null)
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
            var delay = string.IsNullOrWhiteSpace(escalationAfter)
                ? 0
                : WorkflowUtils.ConvertToMilliseconds(escalationAfter);
            await WorkflowUtils.AddWorkflowApproversAsync(
                vault.Auth, record.Uid, record.Title, userEmails, teamUids, escalation, delay);
            Console.WriteLine($"Approvers added to {record.Title} ({record.Uid}).");
        }
    }
}
