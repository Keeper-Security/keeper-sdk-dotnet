using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Lists PAM workflow approval requests awaiting the current user.</summary>
    public static class PamWorkflowPendingExample
    {
        public static async Task ListPending(VaultOnline vault)
        {
            var requests = await WorkflowUtils.GetApprovalRequestsAsync(vault.Auth);
            var pending = await WorkflowUtils.FilterPendingApprovalsAsync(
                vault.Auth, requests?.Workflows, vault.Auth.Username);
            Console.WriteLine($"Pending approval requests: {pending.Count}.");
            foreach (var request in pending)
            {
                Console.WriteLine($"  {request.FlowUid.ToByteArray().Base64UrlEncode()} - {request.User}");
            }
        }
    }
}
