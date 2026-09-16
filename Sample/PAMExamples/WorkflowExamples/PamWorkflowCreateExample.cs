using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Creates PAM workflow settings and optional approvers.</summary>
    public static class PamWorkflowCreateExample
    {
        public static async Task CreateWorkflow(
            VaultOnline vault,
            string recordUid,
            int approvalsNeeded = 1,
            IEnumerable<string> approverEmails = null,
            bool checkout = false,
            bool startOnApproval = false,
            bool requireReason = false,
            bool requireTicket = false,
            bool requireMfa = false,
            string duration = "1d",
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

            await WorkflowUtils.CreateWorkflowConfigAsync(vault.Auth, parameters);
            if (approverEmails != null)
            {
                await WorkflowUtils.AddWorkflowApproversAsync(
                    vault.Auth, record.Uid, record.Title, approverEmails);
            }

            Console.WriteLine($"Workflow created for {record.Title} ({record.Uid}).");
        }
    }
}
