using System;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using KeeperSecurity.Storage;
using KeeperSecurity.Vault;

namespace PowerCommanderStorageUtils
{
    /// <summary>
    /// Creates vault storage for PowerCommander. Mirrors Commander's SQLite handling
    /// so all SQLitePCLRaw and schema logic stays in C#.
    /// </summary>
    public static class VaultStorageFactory
    {
        private static bool _sqliteInitialized;

        private static void EnsureSqliteInitialized()
        {
            if (_sqliteInitialized) return;
            SQLitePCL.Batteries_V2.Init();
            _sqliteInitialized = true;
        }

        /// <summary>
        /// Creates an SQLite-backed vault storage (same approach as Commander).
        /// Call this when PowerCommander -UseOfflineStorage is used.
        /// </summary>
        /// <param name="connectionString">SQLite connection string (e.g. "Data Source=path/to/vault.sqlite;Pooling=True;")</param>
        /// <param name="ownerUid">Account UID (Base64Url-encoded) for partition.</param>
        /// <returns>IKeeperStorage ready to pass to VaultOnline constructor.</returns>
        public static IKeeperStorage CreateSqliteStorage(string connectionString, string ownerUid)
        {
            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentNullException(nameof(connectionString));
            if (string.IsNullOrEmpty(ownerUid))
                throw new ArgumentNullException(nameof(ownerUid));

            EnsureSqliteInitialized();

            SqliteConnection GetConnection()
            {
                var c = new SqliteConnection(connectionString);
                c.Open();
                return c;
            }

            var vaultStorage = new SqlKeeperStorage(GetConnection, SqliteDialect.Instance, ownerUid);

            using (var connection = GetConnection())
            {
                var schemas = vaultStorage.GetStorages().Select(x => x.Schema).ToArray();
                var failed = DatabaseUtils.VerifyDatabase(connection, SqliteDialect.Instance, schemas);
                if (failed != null && failed.Count > 0)
                    System.Diagnostics.Trace.TraceWarning(string.Join(Environment.NewLine, failed));
            }

            return vaultStorage;
        }
    }
}
