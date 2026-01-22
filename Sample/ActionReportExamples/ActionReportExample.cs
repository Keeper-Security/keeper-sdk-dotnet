using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;

namespace Sample.ActionReportExamples
{
    public static class ActionReportExample
    {
        public static async Task RunActionReport(
            ActionReportTargetStatus targetStatus = ActionReportTargetStatus.NoLogon,
            int? daysSince = null,
            string node = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Authentication failed. Vault is null.");
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
                Console.WriteLine($"Matched Users: {result.Users.Count}");
                Console.WriteLine();

                if (result.Users.Count == 0)
                {
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

