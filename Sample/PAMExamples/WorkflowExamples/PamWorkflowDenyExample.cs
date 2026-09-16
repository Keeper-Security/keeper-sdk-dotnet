using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Denies a PAM workflow access request.</summary>
    public static class PamWorkflowDenyExample
    {
        public static async Task Deny(VaultOnline vault, string flowUid, string reason = null)
        {
            var flowBytes = flowUid.Base64UrlDecode();
            var encryptedReason = string.IsNullOrWhiteSpace(reason)
                ? null
                : await WorkflowUtils.TryEncryptDenialReasonAsync(vault.Auth, flowBytes, reason);
            await WorkflowUtils.DenyWorkflowAccessAsync(vault.Auth, flowBytes, encryptedReason);
            Console.WriteLine($"Workflow {flowUid} denied.");
        }
    }
}
