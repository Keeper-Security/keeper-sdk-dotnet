using KeeperSecurity.Vault;

namespace Commander
{
    internal static class AuditHelpers
    {
        internal static void LogRecordOpened(IVault vault, string recordUid, bool unmask, bool hasPassword)
        {
            vault.AuditLogRecordOpen(recordUid);
            LogPasswordRevealed(vault, recordUid, unmask && hasPassword);
        }

        internal static void LogPasswordRevealed(IVault vault, string recordUid, bool revealed)
        {
            if (revealed)
            {
                vault.AuditLogRecordRevealPassword(recordUid);
            }
        }
    }
}
