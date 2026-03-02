using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspCopyRoleToManagedCompanyExample
    {
        /// <summary>
        /// Copies a role (with its enforcements) from the MSP enterprise
        /// to one or more managed companies. If the role doesn't exist in
        /// the target MC, it is created. Enforcements are synced to match
        /// the source role (adds missing, updates changed, removes extra).
        /// A separate authenticated session is created for each target MC.
        /// </summary>
        /// <param name="sourceRoleName">The display name of the role in the MSP enterprise to copy.</param>
        /// <param name="targetCompanyIds">Array of Managed Company Enterprise IDs to copy the role into.</param>
        public static async Task CopyRoleToManagedCompanies(string sourceRoleName, int[] targetCompanyIds)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Authentication failed. Vault is null.");
                    return;
                }

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(sourceRoleName))
                {
                    Console.WriteLine("Source role name is required.");
                    return;
                }

                if (targetCompanyIds == null || targetCompanyIds.Length == 0)
                {
                    Console.WriteLine("At least one target company ID is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var mspData = new ManagedCompanyData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, mspData, roleData });

                await enterpriseLoader.Load();

                var sourceRole = roleData.Roles
                    .FirstOrDefault(r => string.Equals(r.DisplayName?.Trim(), sourceRoleName.Trim(), StringComparison.OrdinalIgnoreCase));

                if (sourceRole == null)
                {
                    Console.WriteLine($"Role \"{sourceRoleName}\" not found in MSP enterprise.");
                    return;
                }

                var sourceEnforcements = BuildEnforcementDictionary(roleData, sourceRole.Id);
                Console.WriteLine($"Source role: \"{sourceRole.DisplayName}\" (ID: {sourceRole.Id}) with {sourceEnforcements.Count} enforcement(s).");

                foreach (var companyId in targetCompanyIds)
                {
                    var mc = mspData.ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == companyId);
                    if (mc == null)
                    {
                        Console.WriteLine($"  Managed Company ID {companyId} not found. Skipping.");
                        continue;
                    }

                    Console.WriteLine($"\n  Processing MC: {mc.EnterpriseName} (ID: {mc.EnterpriseId})...");

                    var mcAuth = new ManagedCompanyAuth();
                    await mcAuth.LoginToManagedCompany(enterpriseLoader, mc.EnterpriseId);

                    var mcEnterpriseData = new EnterpriseData();
                    var mcRoleData = new RoleData();
                    var mcLoader = new EnterpriseLoader(
                        mcAuth,
                        new EnterpriseDataPlugin[] { mcEnterpriseData, mcRoleData });

                    await mcLoader.Load();

                    var mcRoles = mcRoleData.Roles
                        .Where(r => string.Equals(r.DisplayName?.Trim(), sourceRoleName.Trim(), StringComparison.OrdinalIgnoreCase))
                        .ToArray();

                    if (mcRoles.Length > 1)
                    {
                        Console.WriteLine($"    Multiple roles named \"{sourceRoleName}\" in MC. Skipping.");
                        continue;
                    }

                    EnterpriseRole mcRole;
                    if (mcRoles.Length == 0)
                    {
                        mcRole = await mcRoleData.CreateRole(sourceRoleName, mcEnterpriseData.RootNode.Id, sourceRole.NewUserInherit);
                        if (mcRole == null)
                        {
                            Console.WriteLine($"    Failed to create role \"{sourceRoleName}\" in MC.");
                            continue;
                        }
                        Console.WriteLine($"    Created role \"{sourceRoleName}\" (ID: {mcRole.Id}).");
                    }
                    else
                    {
                        mcRole = mcRoles[0];
                        Console.WriteLine($"    Found existing role \"{mcRole.DisplayName}\" (ID: {mcRole.Id}).");
                    }

                    var mcEnforcements = BuildEnforcementDictionary(mcRoleData, mcRole.Id);

                    var toAdd = new Dictionary<RoleEnforcementPolicies, string>();
                    var toUpdate = new Dictionary<RoleEnforcementPolicies, string>();
                    var toRemove = new List<RoleEnforcementPolicies>();

                    foreach (var kvp in sourceEnforcements)
                    {
                        if (!mcEnforcements.ContainsKey(kvp.Key))
                        {
                            toAdd[kvp.Key] = kvp.Value;
                        }
                        else if (!string.Equals(kvp.Value, mcEnforcements[kvp.Key], StringComparison.OrdinalIgnoreCase))
                        {
                            toUpdate[kvp.Key] = kvp.Value;
                        }
                    }

                    foreach (var kvp in mcEnforcements)
                    {
                        if (!sourceEnforcements.ContainsKey(kvp.Key))
                        {
                            toRemove.Add(kvp.Key);
                        }
                    }

                    if (toRemove.Count > 0)
                    {
                        await mcRoleData.RoleEnforcementRemoveBatch(mcRole, toRemove);
                        Console.WriteLine($"    Removed {toRemove.Count} enforcement(s).");
                    }

                    if (toAdd.Count > 0)
                    {
                        await mcRoleData.RoleEnforcementAddBatch(mcRole, toAdd);
                        Console.WriteLine($"    Added {toAdd.Count} enforcement(s).");
                    }

                    if (toUpdate.Count > 0)
                    {
                        await mcRoleData.RoleEnforcementUpdateBatch(mcRole, toUpdate);
                        Console.WriteLine($"    Updated {toUpdate.Count} enforcement(s).");
                    }

                    if (toAdd.Count == 0 && toUpdate.Count == 0 && toRemove.Count == 0)
                    {
                        Console.WriteLine("    Enforcements already in sync.");
                    }
                }

                Console.WriteLine("\nRole copy operation completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static Dictionary<RoleEnforcementPolicies, string> BuildEnforcementDictionary(RoleData roleData, long roleId)
        {
            var dict = new Dictionary<RoleEnforcementPolicies, string>();
            foreach (var re in roleData.GetEnforcementsForRole(roleId))
            {
                if (Enum.TryParse<RoleEnforcementPolicies>(re.EnforcementType, true, out var policy))
                {
                    dict[policy] = re.Value ?? string.Empty;
                }
            }
            return dict;
        }
    }
}
