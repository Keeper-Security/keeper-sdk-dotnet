using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;

namespace Sample.PAMExamples.WorkflowExamples
{
    /// <summary>Requests PAM workflow access, escalates, or cancels a request.</summary>
    public static class PamWorkflowRequestExample
    {
        public static async Task RequestAccess(
            VaultOnline vault,
            string recordUid,
            string reason = null,
            string ticket = null)
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
            await WorkflowUtils.RequestWorkflowAccessAsync(
                vault.Auth, record.Uid, record.Title, record.RecordKey, reason, ticket);
            Console.WriteLine($"Access requested for {record.Title} ({record.Uid}).");
        }
    }
}
