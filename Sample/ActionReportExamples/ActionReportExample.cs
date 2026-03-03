using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
using Sample.Helpers;

namespace Sample.ActionReportExamples
{
    /// <summary>
    /// Provides example for running enterprise action reports.
    /// </summary>
    public static class ActionReportExample
    {
        /// <summary>
        /// Runs an action report to identify users based on their status (e.g., NoLogon, Locked).
        /// Requires enterprise admin privileges.
        /// </summary>
        /// <param name="targetStatus">The target user status to filter by (default: NoLogon).</param>
        /// <param name="daysSince">Number of days since last activity (optional).</param>
        /// <param name="node">Filter by specific node name (optional).</param>
        public static async Task RunActionReport(VaultOnline vault = null,
            ActionReportTargetStatus targetStatus = ActionReportTargetStatus.NoLogon,
            int? daysSince = null,
            string node = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                var options = new ActionReportOptions
                {
                    TargetStatus = targetStatus,
                    DaysSince = daysSince,
                    Node = node,
                    ApplyAction = ActionReportAdminAction.None,
                    DryRun = true,
                    Force = false
                };

                var result = await enterpriseData.RunActionReport(vault.Auth, options);
                if (result == null)
                {
                    Console.WriteLine("Action report returned no result.");
                    return;
                }

                if (!string.IsNullOrEmpty(result.ErrorMessage))
                {
                    Console.WriteLine($"Action report error: {result.ErrorMessage}");
                    return;
                }

                var effectiveDays = daysSince ?? (targetStatus == ActionReportTargetStatus.Locked ? 90 : 30);
                var nodeInfo = string.IsNullOrWhiteSpace(node) ? "" : $" (Node: {node})";

                Console.WriteLine("======== Action Report ========");
                Console.WriteLine($"Target Status: {targetStatus}");
                Console.WriteLine($"Days Since:    {effectiveDays}{nodeInfo}");
                Console.WriteLine($"Matched Users: {result.Users?.Count ?? 0}");
                Console.WriteLine();

                if (result.Users == null || result.Users.Count == 0)
                {
                    Console.WriteLine("No users matched the specified criteria.");
                    return;
                }

                Console.WriteLine("{0,-30}  {1,-46} {2,-28} {3,-60}", "Email", "Status", "Name", "Node Path");
                Console.WriteLine(new string('-', 30) + "  " + new string('-', 46) + "  " + new string('-', 28) + "  " + new string('-', 60));
                foreach (var u in result.Users.OrderBy(x => x.Username, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine("{0,-30}  {1,-46} {2,-28} {3,-60}", u.Username, u.Status, u.DisplayName, u.NodePath);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}

