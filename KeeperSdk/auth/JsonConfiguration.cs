using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Diagnostics;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Configuration
{
    /// <summary>
    /// Defines JSON serialization methods
    /// </summary>
    /// <remarks>
    /// Keeper SDK library implements JSON serialization to file.
    /// </remarks>
    /// <seealso cref="JsonConfigurationFileLoader"/>
    public interface IJsonConfigurationLoader
    {
        /// <summary>
        /// Loads JSON data
        /// </summary>
        /// <returns>JSON data</returns>
        byte[] LoadJson();

        /// <summary>
        /// Stores JSON data.
        /// </summary>
        /// <param name="json">JSON data.</param>
        void StoreJson(byte[] json);
    }

    /// <summary>
    /// Provides implementation od <see cref="IJsonConfigurationLoader"/> that stores configuration to file.
    /// </summary>
    public class JsonConfigurationFileLoader : IJsonConfigurationLoader
    {
        /// <summary>
        /// Creates instance with default parameters.
        /// </summary>
        /// <remarks>
        /// Json file name is <c>config.json</c>
        /// If there is no such file in the current directory then it is created in the User Document's <c>.keeper</c> folder.
        /// </remarks>
        public JsonConfigurationFileLoader() : this("config.json")
        {
        }

        /// <summary>
        /// Creates instance.
        /// </summary>
        /// <param name="fileName">File name or full path.</param>
        public JsonConfigurationFileLoader(string fileName)
        {
            if (File.Exists(fileName))
            {
                FilePath = Path.GetFullPath(fileName);
            }
            else
            {
                var personalFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal),
                    ".keeper");
                if (!Directory.Exists(personalFolder))
                {
                    Directory.CreateDirectory(personalFolder);
                }

                FilePath = Path.Combine(personalFolder, fileName);
            }

            Debug.WriteLine($"JSON config path: \"{FilePath}\"");
        }

        /// <summary>
        /// Gets configuration file path.
        /// </summary>
        public string FilePath { get; }

        /// <inheritdoc/>>
        public byte[] LoadJson()
        {
            if (File.Exists(FilePath))
            {
                try
                {
                    return File.ReadAllBytes(FilePath);
                }
                catch (Exception e)
                {
                    Trace.TraceError("Read JSON configuration: File name: \"{0}\", Error: {1}", FilePath, e.Message);
                }
            }

            return null;
        }

        /// <inheritdoc/>>
        public void StoreJson(byte[] json)
        {
            try
            {
                File.WriteAllBytes(FilePath, json);
            }
            catch (Exception e)
            {
                Trace.TraceError("Store JSON configuration: File name: \"{0}\", Error: {1}", FilePath, e.Message);
            }
        }
    }

    /// <summary>
    /// Caches requests to load/store JSON configuration.
    /// </summary>
    public class JsonConfigurationStorage : IConfigurationStorage
    {
        private readonly IJsonConfigurationLoader _loader;
        private JsonConfiguration _configuration;

        public JsonConfigurationStorage() : this("config.json")
        {
        }

        /// <summary>
        /// Creates using provided configuration cache object.
        /// </summary>
        /// <param name="fileName">Configuration file name.</param>
        public JsonConfigurationStorage(string fileName) : this(new JsonConfigurationFileLoader(fileName))
        {
        }

        /// <summary>
        /// Creates JSON configuration cache instance.
        /// </summary>
        /// <param name="loader">JSON loader</param>
        public JsonConfigurationStorage(IJsonConfigurationLoader loader)
        {
            _loader = loader;
        }

        private long _readEpochMillis;

        public IKeeperConfiguration Get()
        {
            var nowMillis = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            if (_configuration != null)
            {
                if ((nowMillis - _readEpochMillis) > 2000)
                {
                    _configuration = null;
                }
            }

            if (_configuration != null)
            {
                return _configuration;
            }

            var data = _loader.LoadJson();
            if (data != null && data.Length > 0)
            {
                try
                {
                    _configuration = JsonUtils.ParseJson<JsonConfiguration>(data);
                    _readEpochMillis = nowMillis;
                    return _configuration;
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Load JSON configuration error: {e.Message}");
                }
            }

            return new KeeperConfiguration();
        }

        public void Put(IKeeperConfiguration configuration)
        {
            byte[] data;
            if (_configuration == null)
            {
                data = _loader.LoadJson();
                if (data != null && data.Length > 0)
                {
                    try
                    {
                        _configuration = JsonUtils.ParseJson<JsonConfiguration>(data);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Load JSON configuration error: {e.Message}");
                    }
                }

                if (_configuration == null)
                {
                    _configuration = new JsonConfiguration();
                }
            }

            _configuration.Assign(configuration);
            data = JsonUtils.DumpJson(configuration);
            _loader.StoreJson(data);
            _configuration = null;
        }
    }











    internal class ListConfigCollection<T, IT> : IConfigCollection<IT> where T : IT, IEntityCopy<IT>, new()
        where IT : class, IConfigurationId
    {
        private readonly Func<List<T>> _listFunc;

        public ListConfigCollection(Func<List<T>> listFunc)
        {
            _listFunc = listFunc;
        }

        public IT Get(string id)
        {
            var list = _listFunc();
            return list.FirstOrDefault(x => string.CompareOrdinal(x.Id, id) == 0);
        }

        public void Put(IT configuration)
        {
            var list = _listFunc();
            var conf = list.FirstOrDefault(x => string.CompareOrdinal(x.Id, configuration.Id) == 0);
            if (conf == null)
            {
                conf = new T();
                list.Add(conf);
            }

            conf.CopyFields(configuration);
        }

        public void Delete(string id)
        {
            var list = _listFunc();
            var item = list.FirstOrDefault(x => string.CompareOrdinal(x.Id, id) == 0);
            if (item != null)
            {
                list.Remove(item);
            }
        }

        public IEnumerable<IT> List => _listFunc().Cast<IT>();
    }

    [DataContract]
    internal class JsonUserDeviceConfiguration : IUserDeviceConfiguration, IEntityCopy<IUserDeviceConfiguration>,
        IExtensibleDataObject
    {
        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string device_token;

        public ExtensionDataObject ExtensionData { get; set; }

        void IEntityCopy<IUserDeviceConfiguration>.CopyFields(IUserDeviceConfiguration userDevConf)
        {
            if (string.IsNullOrEmpty(device_token))
            {
                device_token = userDevConf.DeviceToken;
            }
        }

        string IUserDeviceConfiguration.DeviceToken => device_token;
    }


    [DataContract]
    internal class JsonUserConfiguration : IUserConfiguration, IEntityCopy<IUserConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "user", EmitDefaultValue = false)]
        public string user;

        [DataMember(Name = "password", EmitDefaultValue = false)]
        //#pragma warning disable 0649
        public string user_password;
        //#pragma warning restore 0649

        [DataMember(Name = "mfa_token", EmitDefaultValue = false)]
        public string _mfa_token;

        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string _server;

        [DataMember(Name = "last_device", EmitDefaultValue = false)]
        public JsonUserDeviceConfiguration _last_device;

        public ExtensionDataObject ExtensionData { get; set; }

        void IEntityCopy<IUserConfiguration>.CopyFields(IUserConfiguration userConf)
        {
            if (string.IsNullOrEmpty(user))
            {
                user = userConf.Username;
            }

            _last_device = userConf.LastDevice != null
                ? new JsonUserDeviceConfiguration
                {
                    device_token = userConf.LastDevice.DeviceToken,
                }
                : _last_device = null;

            _mfa_token = userConf.TwoFactorToken;
            _server = userConf.Server;
        }

        string IUserConfiguration.Username => user;
        string IUserConfiguration.Password => user_password;
        string IUserConfiguration.TwoFactorToken => _mfa_token;
        string IUserConfiguration.Server => _server;
        IUserDeviceConfiguration IUserConfiguration.LastDevice => _last_device;
        string IConfigurationId.Id => user;
    }

    [DataContract]
    internal class JsonServerConfiguration : IServerConfiguration, IEntityCopy<IServerConfiguration>,
        IExtensibleDataObject
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "server_key_id", EmitDefaultValue = false)]
        public int serverKeyId;

        string IServerConfiguration.Server => server;
        int IServerConfiguration.ServerKeyId => serverKeyId;
        string IConfigurationId.Id => server;

        void IEntityCopy<IServerConfiguration>.CopyFields(IServerConfiguration serverConf)
        {
            if (string.IsNullOrEmpty(server))
            {
                server = serverConf.Server;
            }

            serverKeyId = serverConf.ServerKeyId;
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class JsonDeviceServerConfiguration : IDeviceServerConfiguration, IEntityCopy<IDeviceServerConfiguration>
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "clone_code", EmitDefaultValue = false)]
        public string cloneCode;

        string IDeviceServerConfiguration.Server => server;

        string IDeviceServerConfiguration.CloneCode => cloneCode;

        string IConfigurationId.Id => server;

        void IEntityCopy<IDeviceServerConfiguration>.CopyFields(IDeviceServerConfiguration entity)
        {
            if (string.IsNullOrEmpty(server))
            {
                server = entity.Server;
            }

            cloneCode = entity.CloneCode;
        }
    }

    [DataContract]
    internal class JsonDeviceConfiguration : IDeviceConfiguration, IEntityCopy<IDeviceConfiguration>,
        IExtensibleDataObject
    {
        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string deviceToken;

        [DataMember(Name = "private_key", EmitDefaultValue = false)]
        public string privateKey;

        [DataMember(Name = "server_info", EmitDefaultValue = false)]
        public List<JsonDeviceServerConfiguration> serverInfo;

        string IDeviceConfiguration.DeviceToken => deviceToken;
        byte[] IDeviceConfiguration.DeviceKey => string.IsNullOrEmpty(privateKey) ? null : privateKey.Base64UrlDecode();
        string IConfigurationId.Id => deviceToken;

        private IConfigCollection<IDeviceServerConfiguration> _serverInfo;

        public IConfigCollection<IDeviceServerConfiguration> ServerInfo
        {
            get
            {
                if (_serverInfo == null)
                {
                    _serverInfo = new ListConfigCollection<JsonDeviceServerConfiguration, IDeviceServerConfiguration>(
                        () => serverInfo ?? (serverInfo = new List<JsonDeviceServerConfiguration>()));
                }

                return _serverInfo;
            }
        }

        void IEntityCopy<IDeviceConfiguration>.CopyFields(IDeviceConfiguration deviceConf)
        {
            if (string.IsNullOrEmpty(deviceToken))
            {
                deviceToken = deviceConf.DeviceToken;
                if (deviceConf.DeviceKey != null)
                {
                    privateKey = deviceConf.DeviceKey.Base64UrlEncode();
                }
            }

            if (deviceConf.ServerInfo == null) return;

            var existing = new HashSet<string>();
            existing.UnionWith(ServerInfo.List.Select(x => x.Id));
            foreach (var si in deviceConf.ServerInfo.List)
            {
                existing.Remove(si.Id);
                ServerInfo.Put(si);
            }

            foreach (var id in existing)
            {
                ServerInfo.Delete(id);
            }
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class JsonConfiguration : IKeeperConfiguration, IExtensibleDataObject
    {
        private ListConfigCollection<JsonUserConfiguration, IUserConfiguration> _users;
        private ListConfigCollection<JsonServerConfiguration, IServerConfiguration> _servers;
        private ListConfigCollection<JsonDeviceConfiguration, IDeviceConfiguration> _devices;

        [DataMember(Name = "last_server", EmitDefaultValue = false)]
        public string LastServer { get; set; }

        [DataMember(Name = "last_login", EmitDefaultValue = false)]
        public string LastLogin { get; set; }

        [DataMember(Name = "users", EmitDefaultValue = false)]
        internal List<JsonUserConfiguration> users;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        internal List<JsonServerConfiguration> servers;

        [DataMember(Name = "devices", EmitDefaultValue = false)]
        internal List<JsonDeviceConfiguration> devices;

        public IConfigCollection<IUserConfiguration> Users
        {
            get
            {
                if (_users == null)
                {
                    _users = new ListConfigCollection<JsonUserConfiguration, IUserConfiguration>(
                        () => users ?? (users = new List<JsonUserConfiguration>()));
                }

                return _users;
            }
        }

        public IConfigCollection<IServerConfiguration> Servers
        {
            get
            {
                if (_servers == null)
                {
                    _servers = new ListConfigCollection<JsonServerConfiguration, IServerConfiguration>(
                        () => servers ?? (servers = new List<JsonServerConfiguration>()));
                }

                return _servers;
            }
        }

        public IConfigCollection<IDeviceConfiguration> Devices
        {
            get
            {
                if (_devices == null)
                {
                    _devices = new ListConfigCollection<JsonDeviceConfiguration, IDeviceConfiguration>(
                        () => devices ?? (devices = new List<JsonDeviceConfiguration>()));
                }

                return _devices;
            }
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }
}