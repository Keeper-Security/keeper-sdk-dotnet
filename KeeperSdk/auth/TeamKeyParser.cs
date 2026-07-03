using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Diagnostics;

namespace KeeperSecurity.Authentication
{
    internal static class TeamKeyParser
    {
        /// <summary>
        /// Returns RSA/EC public key bytes from a <c>team_get_keys</c> entry.
        /// Supports the legacy format (<c>type</c> -1/-3 with key in <c>key</c>) and the
        /// newer format (<c>team_public_key</c> + <c>team_public_key_type</c>).
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
                        case -1:
                            ec = pubBytes;
                            break;
                        case -3:
                            rsa = pubBytes;
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
                    case -1:
                    case -3:
                        try
                        {
                            var keyBytes = entry.key.Base64UrlDecode();
                            if (entry.keyType == -1)
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
