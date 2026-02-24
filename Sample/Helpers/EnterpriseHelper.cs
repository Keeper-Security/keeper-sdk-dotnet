using System;
using KeeperSecurity.Vault;

namespace Sample.Helpers
{
    /// <summary>
    /// Provides helper methods for enterprise operations.
    /// </summary>
    public static class EnterpriseHelper
    {
        /// <summary>
        /// Checks if the authenticated user has enterprise admin privileges.
        /// Prints a message and returns false if not an admin.
        /// </summary>
        /// <param name="vault">The authenticated vault instance.</param>
        /// <returns>True if user is enterprise admin, false otherwise.</returns>
        public static bool RequireEnterpriseAdmin(VaultOnline vault)
        {
            if (vault?.Auth?.AuthContext == null)
            {
                Console.WriteLine("Authentication context is not available.");
                return false;
            }

            if (!vault.Auth.AuthContext.IsEnterpriseAdmin)
            {
                Console.WriteLine("Enterprise admin access is required for this operation.");
                return false;
            }

            return true;
        }
    }
}

