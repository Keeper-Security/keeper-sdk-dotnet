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
    /// Defines the methods for protecting sensitive storage information.
    /// </summary>
    /// <seealso cref="KeeperEncryptionAesV2Protector"/>
    public interface IConfigurationProtection
    {
        /// <summary>
        /// Encrypts / Obfuscates text.
        /// </summary>
        /// <param name="data">Plain test</param>
        /// <returns>Encrypted text.</returns>
        string Obscure(string data);

        /// <summary>
        /// Decrypts previously encrypted text.
        /// </summary>
        /// <param name="data">Encrypted text</param>
        /// <returns>Plain text.</returns>
        string Clarify(string data);
    }

    /// <summary>
    /// Resolves a <see cref="IConfigurationProtection"/> instance by name.
    /// </summary>
    public interface IConfigurationProtectionFactory
    {
        /// <summary>
        /// Finds <c>IConfigurationProtection</c> instance by name.
        /// </summary>
        /// <param name="protection">Protection method name.</param>
        /// <returns>Configuration protection</returns>
        IConfigurationProtection Resolve(string protection);
    }

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
                    var configuration = JsonUtils.ParseJson<JsonConfiguration>(data);
                    DecryptConfiguration(configuration);
                    _configuration = configuration;
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

        private void DecryptConfiguration(JsonConfiguration configuration) {
            var algorithm = configuration.security;

            if (ConfigurationProtection != null && !string.IsNullOrEmpty(algorithm))
            {
                var protector = ConfigurationProtection.Resolve(algorithm);
                if (protector == null)
                {
                    Debug.WriteLine($"JSON configuration protector \"{algorithm}\" is not found");

                    protector = new WipeOutProtector();
                }
                if (configuration.devices != null)
                {
                    foreach (var d in configuration.devices)
                    {
                        if (d.secured == true)
                        {
                            d.secured = null;
                            try
                            {
                                d.privateKey = protector.Clarify(d.privateKey);
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                                d.privateKey = null;
                            }
                            if (d.serverInfo != null)
                            {
                                foreach (var si in d.serverInfo)
                                {
                                    if (!string.IsNullOrEmpty(si.cloneCode))
                                    {
                                        try
                                        {
                                            si.cloneCode = protector.Clarify(si.cloneCode);
                                        }
                                        catch (Exception e)
                                        {
                                            Debug.WriteLine(e);
                                            si.cloneCode = null;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (configuration.users != null)
                {
                    foreach (var u in configuration.users)
                    {
                        if (u.secured == true)
                        {
                            u.secured = null;
                            if (!string.IsNullOrEmpty(u.user_password))
                            {
                                try
                                {
                                    u.user_password = protector.Clarify(u.user_password);
                                }
                                catch (Exception e)
                                {
                                    Debug.WriteLine(e);
                                    u.user_password = null;
                                }
                            }
                        }
                    }
                }
                configuration.security = null;
            }
        }

        private void EncryptConfiguration(JsonConfiguration configuration)
        {
            if (ConfigurationProtection != null && !string.IsNullOrEmpty(SecurityAlgorithm) && !SkipSecurity)
            {
                var protector = ConfigurationProtection.Resolve(SecurityAlgorithm);
                if (protector != null)
                {
                    if (_configuration.devices != null)
                    {
                        foreach (var d in _configuration.devices)
                        {
                            try
                            {
                                d.privateKey = protector.Obscure(d.privateKey);
                                foreach (var si in d.serverInfo)
                                {
                                    if (!string.IsNullOrEmpty(si.cloneCode))
                                    {
                                        si.cloneCode = protector.Obscure(si.cloneCode);
                                    }
                                }
                                d.secured = true;
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                            }
                        }
                    }
                    if (_configuration.users != null)
                    {
                        foreach (var u in _configuration.users)
                        {
                            if (!string.IsNullOrEmpty(u.user_password))
                            {
                                try
                                {
                                    u.user_password = protector.Obscure(u.user_password);
                                    u.secured = true;
                                }
                                catch (Exception e)
                                {
                                    Debug.WriteLine(e);
                                }
                            }
                        }
                    }
                    _configuration.security = SecurityAlgorithm;
                }
            }
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
                        DecryptConfiguration(_configuration);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Load JSON configuration error: {e.Message}");
                    }
                }

                _configuration ??= new JsonConfiguration();
            }

            _configuration.Assign(configuration);
            EncryptConfiguration(_configuration);
            data = JsonUtils.DumpJson(_configuration);
            _loader.StoreJson(data);
            _configuration = null;
        }

        /// <summary>
        /// Gets / sets configuration protection factory.
        /// </summary>
        public IConfigurationProtectionFactory ConfigurationProtection { get; set; }
        
        /// <exclude/>
        public bool SkipSecurity { get; set; }

        /// <summary>
        /// Gets / sets configuration protection algorithm.
        /// </summary>
        /// <seealso cref="IConfigurationProtectionFactory"/>
        public string SecurityAlgorithm { get; set; }
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

        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string _server;

        [DataMember(Name = "last_device", EmitDefaultValue = false)]
        public JsonUserDeviceConfiguration _last_device;

        [DataMember(Name = "secured", EmitDefaultValue = false)]
        public bool? secured;

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

            _server = userConf.Server;
        }

        string IUserConfiguration.Username => user;
        string IUserConfiguration.Password => user_password;
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

        [DataMember(Name = "secured", EmitDefaultValue = false)]
        public bool? secured;

        string IDeviceConfiguration.DeviceToken => deviceToken;
        byte[] IDeviceConfiguration.DeviceKey => string.IsNullOrEmpty(privateKey) ? null : privateKey.Base64UrlDecode();
        string IConfigurationId.Id => deviceToken;

        private IConfigCollection<IDeviceServerConfiguration> _serverInfo;

        public IConfigCollection<IDeviceServerConfiguration> ServerInfo
        {
            get
            {
                return _serverInfo ??= new ListConfigCollection<JsonDeviceServerConfiguration, IDeviceServerConfiguration>(
                    () => serverInfo ??= new List<JsonDeviceServerConfiguration>());
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

        [DataMember(Name = "security", EmitDefaultValue = false)]
        public string security;

        public IConfigCollection<IUserConfiguration> Users
        {
            get
            {
                return _users ??= new ListConfigCollection<JsonUserConfiguration, IUserConfiguration>(
                    () => users ??= new List<JsonUserConfiguration>());
            }
        }

        public IConfigCollection<IServerConfiguration> Servers
        {
            get
            {
                return _servers ??= new ListConfigCollection<JsonServerConfiguration, IServerConfiguration>(
                    () => servers ??= new List<JsonServerConfiguration>());
            }
        }

        public IConfigCollection<IDeviceConfiguration> Devices
        {
            get
            {
                return _devices ??= new ListConfigCollection<JsonDeviceConfiguration, IDeviceConfiguration>(
                    () => devices ??= new List<JsonDeviceConfiguration>());
            }
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }
}