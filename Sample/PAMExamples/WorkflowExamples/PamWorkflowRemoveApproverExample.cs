using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Removes users or teams from a PAM workflow approver list.</summary>
    public static class PamWorkflowRemoveApproverExample
    {
        public static async Task RemoveApprovers(
            VaultOnline vault,
            string recordUid,
            IEnumerable<string> userEmails = null,
            IEnumerable<string> teamUids = null)
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
            await WorkflowUtils.DeleteWorkflowApproversAsync(
                vault.Auth, record.Uid, record.Title, userEmails, teamUids);
            Console.WriteLine($"Approvers removed from {record.Title} ({record.Uid}).");
        }
    }
}
