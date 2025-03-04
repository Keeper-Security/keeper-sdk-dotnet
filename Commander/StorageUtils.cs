using System.Configuration;
using Microsoft.Data.Sqlite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    public interface IExternalLoader
    {
        IJsonConfigurationLoader GetConfigurationLoader();
        IKeeperStorage GetKeeperStorage(string username);
    }

    internal static class StorageUtils
    {
        public static IExternalLoader SetupCommanderStorage(string configFile)
        {
            if (string.IsNullOrEmpty(configFile))
            {
                configFile = "config.json";
            }

            var configValue = ConfigurationManager.AppSettings["useOfflineStorage"];
            if (!bool.TryParse(configValue, out var useOfflineStorage) || !useOfflineStorage)
            {
                return new InMemoryCommanderStorage(configFile);
            }

            return new SqliteCommanderStorage(configFile);
        }
    }

    internal abstract class ExternalLoader: IExternalLoader
    {
        protected readonly JsonConfigurationFileLoader Loader;
        protected ExternalLoader(string configFile)
        {
            Loader = new JsonConfigurationFileLoader(configFile);
        }

        public IJsonConfigurationLoader GetConfigurationLoader()
        {
            return Loader;
        }
        
        public abstract IKeeperStorage GetKeeperStorage(string ownerUid);
    }

    internal class SqliteCommanderStorage : ExternalLoader
    {
        private readonly string _databaseName;

        public SqliteCommanderStorage(string configFile): base(configFile)
        {
            var path = Path.GetDirectoryName(Loader.FilePath);
            Debug.Assert(path != null);
            _databaseName = Path.Combine(path, "keeper_db.sqlite");
        }

        private SqliteConnection _connection;

        private SqliteConnection GetSqliteConnection()
        {
            if (_connection == null)
            {
                _connection = new SqliteConnection($"Data Source={_databaseName};");
                _connection.Open();
            }

            return _connection;
        }

        public override IKeeperStorage GetKeeperStorage(string ownerUid)
        {
            var connection = GetSqliteConnection();
            var vaultStorage = new SqliteKeeperStorage(GetSqliteConnection, ownerUid);
            var failedStmts = DatabaseUtils.VerifyDatabase(connection,
                vaultStorage.GetStorages().Select(x => x.Schema).ToArray());
            return vaultStorage;
        }
    }

    internal class InMemoryCommanderStorage : ExternalLoader
    {
        public InMemoryCommanderStorage(string configFile) : base(configFile)
        {
        }

        public override IKeeperStorage GetKeeperStorage(string username)
        {
            return new InMemoryKeeperStorage();
        }
    }
}
