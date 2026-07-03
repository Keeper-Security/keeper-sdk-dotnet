using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
    /// <summary>
    /// PAM resource graph (DAG) operations for rotation edit (resource linking and user↔resource ACL).
    /// </summary>
    internal static class PamRotationDag
    {
        internal static bool IsAvailable => true;

        internal static async Task<bool> TryConfigureResourceAsync(
            IAuthentication auth,
            VaultOnline vault,
            TypedRecord resourceRecord,
            string configUid,
            string adminUserIdentifier,
            bool enable,
            bool disable)
        {
            await PamRotationGraphEdit.ConfigureResourceAsync(
                auth,
                vault,
                resourceRecord,
                configUid,
                adminUserIdentifier,
                enable,
                disable);
            return true;
        }

        internal static async Task ConfigureUserAsync(
            IAuthentication auth,
            VaultOnline vault,
            TypedRecord userRecord,
            string resourceUid,
            string configUid,
            bool noopRotation,
            bool scheduleOnly)
        {
            await PamRotationGraphEdit.ConfigureUserAsync(
                auth,
                vault,
                userRecord,
                resourceUid,
                configUid,
                noopRotation,
                scheduleOnly);
        }
    }
}
