using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserReportExample
    {
        /// <summary>
        /// Builds the same columns as PowerCommander's Get-KeeperUserReport (Email, Name, Status,
        /// TransferStatus, LastLogin, Node, Roles, Teams) purely from SDK data:
        ///   - Email / DisplayName / UserStatus / TransferAcceptanceStatus: existing EnterpriseUser properties.
        ///   - LastLogin / TeamUids / TeamNames: new EnterpriseUser properties, populated below via
        ///     EnterpriseData.RefreshUserTeams() and AuditLogExtensions.LoadLastLogins().
        ///   - Node path: walked from EnterpriseData.TryGetNode/ParentNodeId.
        ///   - Roles: RoleData.GetRolesForUser + TryGetRole.
        /// </summary>
        public static async Task GetUserReport(VaultOnline vault, int days = 365)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
                await enterpriseLoader.Load();

                // New columns: team membership (sync) and last login (async, audit log query).
                enterpriseData.RefreshUserTeams();
                var failedLastLoginEmails = await vault.Auth.LoadLastLogins(enterpriseData, days);

                var nodePathCache = new Dictionary<long, string>();

                Console.WriteLine("======== Enterprise User Report ========");
                Console.WriteLine($"Lookback window for LastLogin: {days} day(s)");
                Console.WriteLine(
                    $"{"Email",-50} {"Name",-25} {"Status",-10} {"TransferStatus",-15} " +
                    $"{"LastLogin (UTC)",-20} {"Node",-24} {"Roles",-40} {"Teams"}");
                Console.WriteLine(new string('-', 170));

                foreach (var user in enterpriseData.Users.OrderBy(u => u.Email, StringComparer.OrdinalIgnoreCase))
                {
                    if (!nodePathCache.TryGetValue(user.ParentNodeId, out var nodePath))
                    {
                        nodePath = GetNodePath(enterpriseData, user.ParentNodeId);
                        nodePathCache[user.ParentNodeId] = nodePath;
                    }

                    var roleNames = roleData.GetRolesForUser(user.Id)
                        .Select(roleId => roleData.TryGetRole(roleId, out var role) ? role.DisplayName : null)
                        .Where(name => !string.IsNullOrEmpty(name))
                        .ToArray();

                    string lastLogin;
                    if (user.LastLogin.HasValue)
                    {
                        lastLogin = user.LastLogin.Value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                    else if (failedLastLoginEmails.Contains(user.Email))
                    {
                        lastLogin = "UNKNOWN (query failed)";
                    }
                    else if (user.UserStatus != UserStatus.Inactive)
                    {
                        lastLogin = $"> {days} DAYS AGO";
                    }
                    else
                    {
                        lastLogin = "N/A";
                    }
                    var teams = user.TeamNames != null && user.TeamNames.Length > 0
                        ? string.Join(",", user.TeamNames)
                        : "-";
                    var roles = roleNames.Length > 0 ? string.Join(",", roleNames) : "-";

                    Console.WriteLine(
                        $"{user.Email,-50} {user.DisplayName,-25} {user.UserStatus,-10} {user.TransferAcceptanceStatus,-15} " +
                        $"{lastLogin,-20} {nodePath,-24} {roles,-40} {teams}");
                }

                Console.WriteLine("==========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string GetNodePath(EnterpriseData enterpriseData, long nodeId)
        {
            var parts = new List<string>();
            var currentId = nodeId;
            var visited = new HashSet<long>();

            while (enterpriseData.TryGetNode(currentId, out var node) && visited.Add(currentId))
            {
                if (!string.IsNullOrEmpty(node.DisplayName))
                {
                    parts.Insert(0, node.DisplayName);
                }
                if (node.ParentNodeId <= 0) break;
                currentId = node.ParentNodeId;
            }

            return string.Join("\\", parts);
        }
    }
}
