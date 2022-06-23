using System;
using System.Data;
using System.Text;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

namespace KeeperSecurity.OfflineStorage.Sqlite
{
    [SqlTable(Name = "Configuration")]
    internal class InternalConfiguration
    {
        [SqlColumn]
        public string JsonData { get; set; }
    }

    internal class SqliteConfigurationLoader : SqliteRecordStorage<InternalConfiguration>, IJsonConfigurationLoader
    {
        public SqliteConfigurationLoader(Func<IDbConnection> getConnection, Tuple<string, object> owner = null)
            : base(getConnection, owner)
        {
        }

        public byte[] LoadJson()
        {
            var conf = Get();
            return !string.IsNullOrEmpty(conf?.JsonData) ? Encoding.UTF8.GetBytes(conf.JsonData) : null;
        }

        public void StoreJson(byte[] json)
        {
            var conf = Get() ?? new InternalConfiguration();
            conf.JsonData = Encoding.UTF8.GetString(json);
            Put(conf);
        }
    }
}
