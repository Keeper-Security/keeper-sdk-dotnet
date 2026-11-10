using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Updates PAM workflow settings for a resource.</summary>
    public static class PamWorkflowUpdateExample
    {
        public static async Task UpdateWorkflow(
            VaultOnline vault,
            string recordUid,
            int approvalsNeeded,
            bool checkout,
            bool startOnApproval,
            bool requireReason,
            bool requireTicket,
            bool requireMfa,
            string duration,
            string allowedDays = null,
            string timeRange = null)
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
            var parameters = new WorkflowParameters
            {
                Resource = WorkflowUtils.CreateRecordRef(record.Uid, record.Title),
                ApprovalsNeeded = approvalsNeeded,
                CheckoutNeeded = checkout,
                StartAccessOnApproval = startOnApproval,
                RequireReason = requireReason,
                RequireTicket = requireTicket,
                RequireMFA = requireMfa,
                AccessLength = WorkflowUtils.ConvertToMilliseconds(duration),
                AllowedTimes = WorkflowUtils.BuildTemporalFilter(allowedDays, timeRange),
            };
            await WorkflowUtils.UpdateWorkflowConfigAsync(vault.Auth, parameters);
            Console.WriteLine($"Workflow updated for {record.Title} ({record.Uid}).");
        }
    }
}
