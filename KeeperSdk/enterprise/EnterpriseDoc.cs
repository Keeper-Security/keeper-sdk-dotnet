//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2021 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System.Runtime.CompilerServices;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    ///     Provides types for manipulating Keeper Enterprise data.
    /// </summary>
    /// <example>
    ///   <code>
    ///using System.Linq;
    ///using System.Threading.Tasks;
    ///using KeeperSecurity.Authentication;
    ///using KeeperSecurity.Enterprise;
    ///
    ///internal static class Program
    ///{
    ///    private static async Task Main()
    ///    {
    ///        IAuthentication auth = await ConnectToKeeperAs("username@company.com");
    ///        if (auth.AuthContext.IsEnterpriseAdmin)
    ///        {
    ///            // Load base enterprise data.
    ///            var enterprise = new EnterpriseData();
    ///            var enterpriseLoader = new EnterpriseLoader(auth, new[] { enterprise });
    ///            await enterpriseLoader.Load();
    ///
    ///            // Find team with name "Google".
    ///            var team = enterprise.Teams
    ///                .FirstOrDefault(x => string.Equals(x.Name, "Google", System.StringComparison.InvariantCultureIgnoreCase));
    ///           if (team == null)
    ///            {
    ///                // Create team.
    ///                team = await enterprise.CreateTeam(new EnterpriseTeam
    ///                {
    ///                    Name = "Google",
    ///                    RestrictEdit = false,
    ///                    RestrictSharing = true,
    ///                    RestrictView = false,
    ///                });
    ///            }
    ///
    ///            // Add users to the "Google" team.
    ///            await enterprise.AddUsersToTeams(
    ///                new[] { "username@company.com", "username1@company.com" },
    ///                new[] { team.Uid });
    ///        }
    ///    }
    ///}
    ///   </code>
    /// </example>
    /// <seealso cref="IEnterpriseLoader" />
    /// <seealso cref="EnterpriseData" />
    [CompilerGenerated]
    internal class NamespaceDoc
    {
    }
}
namespace KeeperSecurity.Enterprise.AuditLogCommands
{
    /// <summary>
    /// Provides Audit Report Commands
    /// </summary>
    [CompilerGenerated]
    internal class NamespaceDoc
    {
    }
}