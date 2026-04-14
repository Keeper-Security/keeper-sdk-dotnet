using System;
using System.Data;
using System.Diagnostics;
using System.Linq;
using Microsoft.Data.Sqlite;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Creates SQLite-backed vault storage (same wiring as Commander). Requires SQLitePCL / native SQLite at runtime.
    /// </summary>
    public static class SqliteVaultStorageFactory
    {
        private static bool _sqliteInitialized;

        private static void EnsureSqliteInitialized()
        {
            if (_sqliteInitialized) return;
            SQLitePCL.Batteries_V2.Init();
            _sqliteInitialized = true;
        }

        /// <summary>
        /// Builds <see cref="SqlKeeperStorage"/> for the given SQLite connection string and owner, and verifies schema.
        /// </summary>
        /// <param name="connectionString">SQLite connection string (e.g. <c>Data Source=path;Pooling=True;</c>).</param>
        /// <param name="ownerUid">Partition / owner uid for scoped storage.</param>
        public static IKeeperStorage Create(string connectionString, string ownerUid)
        {
            if (string.IsNullOrEmpty(connectionString)) throw new ArgumentNullException(nameof(connectionString));
            if (string.IsNullOrEmpty(ownerUid)) throw new ArgumentNullException(nameof(ownerUid));
            EnsureSqliteInitialized();

            IDbConnection GetConnection()
            {
                var c = new SqliteConnection(connectionString);
                c.Open();
                return c;
            }

            var vaultStorage = new SqlKeeperStorage(GetConnection, SqliteDialect.Instance, ownerUid);
            using var connection = new SqliteConnection(connectionString);
            connection.Open();
            var failedStmts = DatabaseUtils.VerifyDatabase(connection, SqliteDialect.Instance,
                vaultStorage.GetStorages().Select(x => x.Schema).ToArray());
            if (failedStmts.Any())
            {
                Trace.TraceError(string.Join("\n", failedStmts));
            }

            return vaultStorage;
        }
    }
}
