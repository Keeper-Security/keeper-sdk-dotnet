using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Lists the authenticated user's active PAM workflow access.</summary>
    public static class PamWorkflowMyAccessExample
    {
        public static async Task<UserAccessState> GetMyAccess(VaultOnline vault)
        {
            var state = await WorkflowUtils.GetUserAccessStateAsync(vault.Auth);
            Console.WriteLine($"My active workflows: {state?.Workflows?.Count ?? 0}.");
            return state;
        }
    }
}
