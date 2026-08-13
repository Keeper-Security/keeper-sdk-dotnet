using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Diagnostics;

namespace KeeperSecurity.Authentication
{
    internal static class TeamKeyParser
    {
        /// <summary>
        /// <c>team_get_keys</c> public-key type for an EC (secp256r1) public key.
        /// Negative types mean the payload is public key material (not a wrapped team AES key).
        /// Positive types 1–4 on <c>key</c>/<c>type</c> remain the wrapped-team-key contract.
        /// </summary>
        public const int TeamPublicKeyTypeEc = -1;

        /// <summary>
        /// <c>team_get_keys</c> public-key type for an RSA public key.
        /// </summary>
        public const int TeamPublicKeyTypeRsa = -3;

        /// <summary>
        /// Parse the asymmetric keys from a <c>team_get_keys</c> response entry.
        /// Supports <c>team_public_key</c> + <c>team_public_key_type</c> and the legacy
        /// format where type <see cref="TeamPublicKeyTypeEc"/> / <see cref="TeamPublicKeyTypeRsa"/>
        /// appears on <c>key</c>/<c>type</c>.
        /// </summary>
        public static void ParseTeamAsymmetricKeyEntry(TeamKeyObject entry, out byte[] rsa, out byte[] ec)
        {
            rsa = null;
            ec = null;
            if (entry == null)
            {
                return;
            }

            if (!string.IsNullOrEmpty(entry.teamPublicKey))
            {
                try
                {
                    var pubBytes = entry.teamPublicKey.Base64UrlDecode();
                    switch (entry.teamPublicKeyType)
                    {
                        case TeamPublicKeyTypeEc:
                            ec = pubBytes;
                            break;
                        case TeamPublicKeyTypeRsa:
                            rsa = pubBytes;
                            break;
                        default:
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Trace.TraceWarning(
                        $"Failed to decode team_public_key for team '{entry.teamUid}': {ex.Message}");
                }
            }

            if ((rsa == null || rsa.Length == 0) && (ec == null || ec.Length == 0) && entry.key != null)
            {
                switch (entry.keyType)
                {
                    case TeamPublicKeyTypeEc:
                    case TeamPublicKeyTypeRsa:
                        try
                        {
                            var keyBytes = entry.key.Base64UrlDecode();
                            if (entry.keyType == TeamPublicKeyTypeEc)
                            {
                                ec = keyBytes;
                            }
                            else
                            {
                                rsa = keyBytes;
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.TraceWarning(
                                $"Failed to decode legacy team key for team '{entry.teamUid}': {ex.Message}");
                        }
                        break;
                }
            }
        }
    }
}
