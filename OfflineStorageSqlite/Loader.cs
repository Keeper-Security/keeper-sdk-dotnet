using System;
using System.Data.Common;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.OfflineStorage.Sqlite
{
    public class DatabaseLoader : IExternalLoader
    {
        private readonly string _connectionString;
        private readonly Type _connectionType;

        public DatabaseLoader(Type connectionType, string connectionString)
        {
            _connectionType = connectionType;
            _connectionString = connectionString;
        }

        private DbConnection _connection;

        private DbConnection GetConnection()
        {
            lock (this)
            {
                if (_connection != null) return _connection;

                _connection = (DbConnection) Activator.CreateInstance(_connectionType, _connectionString);
                _connection.Open();
            }

            return _connection;
        }

        public bool VerifyDatabase()
        {
            var connection = GetConnection();
            var tables = new[]
            {
                typeof(ExternalRecord),
                typeof(ExternalSharedFolder),
                typeof(ExternalEnterpriseTeam),
                typeof(ExternalNonSharedData),
                typeof(ExternalRecordMetadata),
                typeof(ExternalSharedFolderKey),
                typeof(ExternalSharedFolderPermission),
                typeof(ExternalFolder),
                typeof(ExternalFolderRecordLink),
                typeof(InternalUserAccount),
                typeof(InternalConfiguration),
            };

            return DatabaseUtils.VerifyDatabase(true, connection, tables, null);
        }
        public IConfigurationStorage GetConfigurationStorage(string configurationName, IConfigurationProtectionFactory protection)
        {
            if (string.IsNullOrEmpty(configurationName)) configurationName = "default";
            var loader = new SqliteConfigurationLoader(GetConnection, configurationName);
            var cache = new JsonConfigurationCache(loader)
            {
                WriteTimeout = 1000, 
                ConfigurationProtection = protection
            };
            return new JsonConfigurationStorage(cache);
        }

        public IKeeperStorage GetKeeperStorage(string username)
        {
            return new SqliteKeeperStorage(GetConnection, username);
        }
    }
}
