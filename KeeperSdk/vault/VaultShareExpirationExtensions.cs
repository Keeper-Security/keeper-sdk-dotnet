using System;
using System.Collections.Generic;
using System.Linq;
using Folder;
using Records;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Time-limited access helpers for rotate-on-expiration (ROE)</c>.
    /// </summary>
    public static class VaultShareExpirationExtensions
    {
        /// <summary>
        /// Returns true if the record has a rotation configuration from sync-down (record rotation cache).
        /// </summary>
        public static bool RecordHasRotationConfigured(this VaultOnline vault, string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid) || vault?.Storage?.RecordRotations == null)
                return false;
            return vault.Storage.RecordRotations.GetEntity(recordUid) != null;
        }

        /// <summary>
        /// Returns true if the shared folder contains at least one pamUser record with rotation configured.
        /// Required for the server to accept rotate-on-expiration on a folder share grant.
        /// </summary>
        public static bool SharedFolderHasPamUserWithRotation(this VaultOnline vault, string sharedFolderUid)
        {
            if (!vault.TryGetSharedFolder(sharedFolderUid, out var sf))
                return false;

            foreach (var rp in sf.RecordPermissions)
            {
                if (!vault.TryGetKeeperRecord(rp.RecordUid, out var record))
                    continue;
                if (record is TypedRecord typed
                    && string.Equals(typed.TypeName, "pamUser", StringComparison.Ordinal)
                    && vault.RecordHasRotationConfigured(rp.RecordUid))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Searches shared folders by optional pattern (name or UID)<c>search_shared_folders</c>.
        /// </summary>
        public static IEnumerable<SharedFolder> SearchSharedFolders(this VaultOnline vault, string pattern = null)
        {
            var folders = vault.SharedFolders;
            if (string.IsNullOrEmpty(pattern))
                return folders;

            return folders.Where(sf =>
                (sf.Name != null && sf.Name.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                || (sf.Uid != null && sf.Uid.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0));
        }

        /// <summary>
        /// Shared folders eligible for <c>--rotate-on-expiration</c> (list-sf --roe-eligible).
        /// </summary>
        public static IEnumerable<SharedFolder> SearchRoeEligibleSharedFolders(this VaultOnline vault, string pattern = null)
        {
            return vault.SearchSharedFolders(pattern)
                .Where(sf => vault.SharedFolderHasPamUserWithRotation(sf.Uid));
        }

        /// <summary>
        /// Validates rotate-on-expiration for granting shared-folder access.
        /// </summary>
        public static void ValidateRotateOnExpirationForFolderGrant(
            this VaultOnline vault,
            string sharedFolderUid,
            IUserShareOptions options)
        {
            if (options?.RotateOnExpiration != true)
                return;

            var expirationMs = options.Expiration?.ToUnixTimeMilliseconds() ?? 0;
            if (expirationMs <= 0)
            {
                throw new VaultException(
                    "--rotate-on-expiration requires a positive --expire-at / --expire-in (cannot be \"never\").");
            }

            if (!vault.SharedFolderHasPamUserWithRotation(sharedFolderUid))
            {
                throw new VaultException(
                    "--rotate-on-expiration requires the folder to contain at least one pamUser record " +
                    "with rotation configured. Ineligible folder(s): " + sharedFolderUid);
            }
        }

        /// <summary>
        /// Validates rotate-on-expiration when updating a record inside a shared folder (share-folder record branch).
        /// </summary>
        public static void ValidateRotateOnExpirationForSharedFolderRecord(
            this VaultOnline vault,
            string sharedFolderUid,
            IRecordShareOptions options)
        {
            if (options?.RotateOnExpiration != true)
                return;

            vault.ValidateRotateOnExpirationForFolderGrant(sharedFolderUid,
                new SharedFolderUserOptions
                {
                    Expiration = options.Expiration,
                    RotateOnExpiration = true,
                });
        }

        /// <summary>
        /// Validates rotate-on-expiration for granting record share access.
        /// </summary>
        public static void ValidateRotateOnExpirationForRecordGrant(
            this VaultOnline vault,
            string recordUid,
            IRecordShareOptions options)
        {
            if (options?.RotateOnExpiration != true)
                return;

            var expirationMs = options.Expiration?.ToUnixTimeMilliseconds() ?? 0;
            if (expirationMs <= 0)
            {
                throw new VaultException(
                    "--rotate-on-expiration requires a positive --expire-at / --expire-in (cannot be \"never\").");
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record)
                || !(record is TypedRecord typed)
                || !string.Equals(typed.TypeName, "pamUser", StringComparison.Ordinal)
                || !vault.RecordHasRotationConfigured(recordUid))
            {
                throw new VaultException(
                    "--rotate-on-expiration requires a pamUser record with rotation configured. " +
                    "Ineligible record(s): " + recordUid);
            }
        }

        internal static void ApplyShareExpiration(IUserShareOptions options, SharedFolderUpdateUser target)
        {
            ApplyShareExpiration(GetShareExpirationMilliseconds(options), GetRotateOnExpiration(options), target);
        }

        internal static void ApplyShareExpiration(IUserShareOptions options, SharedFolderUpdateTeam target)
        {
            ApplyShareExpiration(GetShareExpirationMilliseconds(options), GetRotateOnExpiration(options), target);
        }

        internal static void ApplyShareExpiration(IRecordShareOptions options, SharedFolderUpdateRecord target)
        {
            ApplyShareExpiration(GetShareExpirationMilliseconds(options), GetRotateOnExpiration(options), target);
        }

        internal static void ApplyShareExpiration(IRecordShareOptions options, SharedRecord target)
        {
            ApplyShareExpiration(GetShareExpirationMilliseconds(options), GetRotateOnExpiration(options), target);
        }

        internal static void ApplyShareExpiration(
            long expirationMs,
            bool rotateOnExpiration,
            SharedFolderUpdateUser target)
        {
            ApplyShareExpirationCore(expirationMs, rotateOnExpiration,
                ms => target.Expiration = ms,
                n => target.TimerNotificationType = n,
                ro => target.RotateOnExpiration = ro);
        }

        internal static void ApplyShareExpiration(
            long expirationMs,
            bool rotateOnExpiration,
            SharedFolderUpdateTeam target)
        {
            ApplyShareExpirationCore(expirationMs, rotateOnExpiration,
                ms => target.Expiration = ms,
                n => target.TimerNotificationType = n,
                ro => target.RotateOnExpiration = ro);
        }

        internal static void ApplyShareExpiration(
            long expirationMs,
            bool rotateOnExpiration,
            SharedFolderUpdateRecord target)
        {
            ApplyShareExpirationCore(expirationMs, rotateOnExpiration,
                ms => target.Expiration = ms,
                n => target.TimerNotificationType = n,
                ro => target.RotateOnExpiration = ro);
        }

        internal static void ApplyShareExpiration(
            long expirationMs,
            bool rotateOnExpiration,
            SharedRecord target)
        {
            ApplyShareExpirationCore(expirationMs, rotateOnExpiration,
                ms => target.Expiration = ms,
                n => target.TimerNotificationType = n,
                ro => target.RotateOnExpiration = ro);
        }

        private static void ApplyShareExpirationCore(
            long expirationMs,
            bool rotateOnExpiration,
            Action<long> setExpiration,
            Action<TimerNotificationType> setNotification,
            Action<bool> setRotateOnExpiration)
        {
            if (expirationMs > 0)
            {
                setExpiration(expirationMs);
                setNotification(TimerNotificationType.NotifyOwner);
                if (rotateOnExpiration)
                    setRotateOnExpiration(true);
            }
            else if (expirationMs < 0)
            {
                setExpiration(-1);
            }
        }

        internal static long GetShareExpirationMilliseconds(IUserShareOptions options)
        {
            return options?.Expiration?.ToUnixTimeMilliseconds() ?? 0;
        }

        internal static long GetShareExpirationMilliseconds(IRecordShareOptions options)
        {
            return options?.Expiration?.ToUnixTimeMilliseconds() ?? 0;
        }

        internal static bool GetRotateOnExpiration(IUserShareOptions options)
        {
            return options?.RotateOnExpiration == true;
        }

        internal static bool GetRotateOnExpiration(IRecordShareOptions options)
        {
            return options?.RotateOnExpiration == true;
        }
    }
}
