using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Approves a PAM workflow access request.</summary>
    public static class PamWorkflowApproveExample
    {
        public static async Task Approve(VaultOnline vault, string flowUid)
        {
            await WorkflowUtils.ApproveWorkflowAccessAsync(vault.Auth, flowUid.Base64UrlDecode());
            Console.WriteLine($"Workflow {flowUid} approved.");
        }
    }
}
