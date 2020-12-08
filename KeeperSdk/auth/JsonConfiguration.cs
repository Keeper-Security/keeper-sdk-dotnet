//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Diagnostics;
using System.Threading.Tasks;
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

    internal interface IEntityClone<in T>
    {
        void CloneFrom(T entity);
    }

    internal class ListConfigCollection<T, IT> : IConfigCollection<IT> where T : IT, IEntityClone<IT>, new() where IT : class, IConfigurationId
    {
        private readonly Func<List<T>> _listFunc;
        private readonly Action _modified;

        public ListConfigCollection(Func<List<T>> listFunc, Action modified)
        {
            _listFunc = listFunc;
            _modified = modified;
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

            conf.CloneFrom(configuration);
            _modified?.Invoke();
        }

        public void Delete(string id)
        {
            var list = _listFunc();
            var item = list.FirstOrDefault(x => string.CompareOrdinal(x.Id, id) == 0);
            if (item != null)
            {
                list.Remove(item);
                _modified?.Invoke();
            }
        }

        public IEnumerable<IT> List => _listFunc().Cast<IT>();
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
    /// Caches requests to load/store JSON configuration.
    /// </summary>
    public class JsonConfigurationCache
    {
        private readonly IJsonConfigurationLoader _loader;

        /// <summary>
        /// Creates JSON configuration cache instance.
        /// </summary>
        /// <param name="loader">JSON loader</param>
        public JsonConfigurationCache(IJsonConfigurationLoader loader)
        {
            _loader = loader;
            ReadTimeout = 2000;
            WriteTimeout = 2000;
        }

        /// <summary>
        /// Gets / sets read timeout in milliseconds.
        /// </summary>
        /// <remarks>Default value is 2 seconds.</remarks>
        public int ReadTimeout { get; set; }
        private long _readEpochMillis;

        /// <exclude/>
        public bool SkipSecurity { get; set; }

        /// <summary>
        /// Gets / sets configuration protection algorithm.
        /// </summary>
        /// <seealso cref="IConfigurationProtectionFactory"/>
        public string SecurityAlgorithm { get; set; }

        /// <summary>
        /// Gets / sets write timeout in milliseconds.
        /// </summary>
        /// <remarks>
        /// Default timeout is 2 seconds.
        /// </remarks>
        public int WriteTimeout { get; set; }

        private JsonConfiguration _configuration;

        internal JsonConfiguration Configuration
        {
            get
            {
                lock (this)
                {
                    if (_configuration != null && _storeConfigurationTask != null && !_storeConfigurationTask.IsCompleted) return _configuration;

                    var nowMillis = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                    if (nowMillis - _readEpochMillis > ReadTimeout)
                    {
                        _configuration = null;
                    }

                    if (_configuration == null)
                    {
                        var jsonBytes = _loader.LoadJson();
                        _readEpochMillis = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                        if (jsonBytes != null && jsonBytes.Length >= 2)
                        {
                            try
                            {
                                _configuration = JsonUtils.ParseJson<JsonConfiguration>(jsonBytes);
                                if (ConfigurationProtection != null && !string.IsNullOrEmpty(_configuration.security))
                                {
                                    var protector = ConfigurationProtection.Resolve(_configuration.security);
                                    if (protector != null)
                                    {
                                        if (_configuration.users != null)
                                        {
                                            foreach (var u in _configuration.users)
                                            {
                                                if (u.secured != true) continue;
                                                u.secured = null;
                                                try
                                                {
                                                    u.user_password = protector.Clarify(u.user_password);
                                                }
                                                catch (Exception e)
                                                {
                                                    Debug.WriteLine(e);
                                                    u.user_password = null;
                                                }

#pragma warning disable CS0612 // Type or member is obsolete
                                                if (u._last_device.resume_code != null)
                                                {
                                                    try
                                                    {
                                                        u._last_device.resume_code = protector.Clarify(u._last_device.resume_code);
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        Debug.WriteLine(e);
                                                        u._last_device.resume_code = null;
                                                    }
                                                }
#pragma warning restore CS0612 // Type or member is obsolete
                                            }
                                        }

                                        if (_configuration.devices != null)
                                        {
                                            foreach (var d in _configuration.devices)
                                            {
                                                if (d.secured != true) continue;
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
                                            }
                                        }
                                    }
                                }
#pragma warning disable CS0612 // Type or member is obsolete
                                if (_configuration.devices?.Count > 0) {
                                    foreach (var jd in _configuration.devices) {
                                        if (jd.servers?.Length > 0) {
                                            foreach (var s in jd.servers) {
                                                jd.ServerInfo.Put(new JsonDeviceServerConfiguration
                                                {
                                                    server = s
                                                });
                                            }
                                            jd.servers = null;
                                        }
                                    }
                                }
                                if (_configuration.users?.Count > 0) {
                                    foreach (var u in _configuration.users)
                                    {
                                        if (string.CompareOrdinal(u.user, _configuration.lastLogin) == 0)
                                        {
                                            if (!string.IsNullOrEmpty(u._last_device?.resume_code))
                                            {
                                                var d = _configuration.devices?.FirstOrDefault(x => x.deviceToken == u._last_device.device_token);
                                                if (d != null)
                                                {
                                                    var s = d?.serverInfo?.FirstOrDefault(x => x.server == _configuration.lastServer);
                                                    if (s != null)
                                                    {
                                                        s.cloneCode = u._last_device.resume_code;
                                                    }
                                                }
                                            }
                                        }
                                        if (u._last_device != null)
                                        {
                                            u._last_device.resume_code = null;
                                        }
                                    }
                                }
                                if (!string.IsNullOrEmpty(_configuration.lastLogin) && !string.IsNullOrEmpty(_configuration.lastServer)) {
                                    var u = _configuration.users?.FirstOrDefault(x => x.user == _configuration.lastLogin);
                                }
#pragma warning restore CS0612 // Type or member is obsolete
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                            }
                        }
                        if (_configuration == null)
                        {
                            _configuration = new JsonConfiguration();
                        }
                    }
                }

                return _configuration;
            }
        }

        private Task _storeConfigurationTask;

        /// <summary>
        /// Schedules storing of configuration.
        /// </summary>
        public void Save()
        {
            lock (this)
            {
                if (_storeConfigurationTask != null && !_storeConfigurationTask.IsCompleted) return;

                _storeConfigurationTask = Task.Run(async () =>
                {
                    await Task.Delay(WriteTimeout);
                    if (_storeConfigurationTask != null)
                    {
                        Flush();
                    }
                });
            }
        }

        internal void Flush()
        {
            lock (this)
            {
                _storeConfigurationTask = null;

                if (_configuration == null) return;
                var algorithm = SecurityAlgorithm ?? _configuration.security;
                if (!SkipSecurity && ConfigurationProtection != null && !string.IsNullOrEmpty(algorithm))
                {
                    var protector = ConfigurationProtection.Resolve(algorithm);
                    if (protector != null)
                    {
                        _configuration.security = algorithm;
                        if (_configuration.devices != null)
                        {
                            foreach (var device in _configuration.devices)
                            {
                                if (string.IsNullOrEmpty(device.privateKey)) continue;
                                try
                                {
                                    var encryptedPrivateKey = protector.Obscure(device.privateKey);
                                    device.privateKey = encryptedPrivateKey;
                                    device.secured = true;
                                }
                                catch (Exception e)
                                {
                                    Debug.WriteLine(e);
                                }
                            }
                        }

                        if (_configuration.users != null)
                        {
                            foreach (var user in _configuration.users)
                            {
                                if (string.IsNullOrEmpty(user.user_password)) continue;
                                try
                                {
                                    string encryptedPassword = null;
                                    if (!string.IsNullOrEmpty(user.user_password))
                                    {
                                        encryptedPassword = protector.Obscure(user.user_password);
                                    }
                                    user.user_password = encryptedPassword;
                                    user.secured = true;
                                }
                                catch (Exception e)
                                {
                                    Debug.WriteLine(e);
                                }
                            }
                        }
                    }
                }

                _loader.StoreJson(JsonUtils.DumpJson(_configuration));
                _configuration = null;
            }
        }

        /// <summary>
        /// Gets / sets configuration protection factory.
        /// </summary>
        public IConfigurationProtectionFactory ConfigurationProtection { get; set; }
    }

    /// <summary>
    /// Provides implementation of <see cref="IConfigurationStorage"/> stored in JSON format.
    /// </summary>
    public sealed class JsonConfigurationStorage : IConfigurationStorage, IConfigurationFlush
    {
        /// <summary>
        /// Creates instance with default settings.
        /// </summary>
        /// <remarks>
        /// Configuration is stored to JSON file named <c>config.json</c>
        /// It uses file located in the current directory if it exists.
        /// Otherwise file is created in User Document's <c>.keeper</c> older.
        /// </remarks>
        public JsonConfigurationStorage() : this(new JsonConfigurationCache(new JsonConfigurationFileLoader()))
        {
        }

        /// <summary>
        /// Creates using provided configuration cache object.
        /// </summary>
        /// <param name="cache">Configuration cache.</param>
        public JsonConfigurationStorage(JsonConfigurationCache cache)
        {
            Cache = cache;
            Users = new ListConfigCollection<JsonUserConfiguration, IUserConfiguration>(
                () => Cache.Configuration.users ?? (Cache.Configuration.users = new List<JsonUserConfiguration>()),
                Cache.Save);
            Servers = new ListConfigCollection<JsonServerConfiguration, IServerConfiguration>(
                () => Cache.Configuration.servers ?? (Cache.Configuration.servers = new List<JsonServerConfiguration>()),
                Cache.Save);
            Devices = new ListConfigCollection<JsonDeviceConfiguration, IDeviceConfiguration>(
                () => Cache.Configuration.devices ?? (Cache.Configuration.devices = new List<JsonDeviceConfiguration>()),
                Cache.Save);
        }

        /// <summary>
        /// Gets configuration cache
        /// </summary>
        public JsonConfigurationCache Cache { get; }

        public IConfigCollection<IUserConfiguration> Users { get; }
        public IConfigCollection<IServerConfiguration> Servers { get; }
        public IConfigCollection<IDeviceConfiguration> Devices { get; }

        public string LastLogin
        {
            get => Cache.Configuration.lastLogin;
            set
            {
                Cache.Configuration.lastLogin = value;
                Cache.Save();
            }
        }

        public string LastServer
        {
            get => Cache.Configuration.lastServer;
            set
            {
                Cache.Configuration.lastServer = value;
                Cache.Save();
            }
        }

        public void Flush()
        {
            Cache.Flush();
        }
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

        /// <summary>
        /// Loads configuration from the file.
        /// </summary>
        /// <returns>JSON data</returns>
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

        /// <summary>
        /// Stores configuration to the file.
        /// </summary>
        /// <param name="json">JSON data</param>
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

    [DataContract]
    internal class JsonUserDeviceConfiguration : IUserDeviceConfiguration, IEntityClone<IUserDeviceConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string device_token;

        [DataMember(Name = "resume_code", EmitDefaultValue = false)]
        [Obsolete]
        public string resume_code;

        public ExtensionDataObject ExtensionData { get; set; }

        void IEntityClone<IUserDeviceConfiguration>.CloneFrom(IUserDeviceConfiguration userDevConf)
        {
            if (string.IsNullOrEmpty(device_token))
            {
                device_token = userDevConf.DeviceToken;
            }
        }

        string IUserDeviceConfiguration.DeviceToken => device_token;
    }


    [DataContract]
    internal class JsonUserConfiguration : IUserConfiguration, IEntityClone<IUserConfiguration>, IExtensibleDataObject
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

        [DataMember(Name = "secured", EmitDefaultValue = false)]
        public bool? secured;

        public ExtensionDataObject ExtensionData { get; set; }

        void IEntityClone<IUserConfiguration>.CloneFrom(IUserConfiguration userConf)
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
    internal class JsonServerConfiguration : IServerConfiguration, IEntityClone<IServerConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "server_key_id", EmitDefaultValue = false)]
        public int serverKeyId;

        string IServerConfiguration.Server => server;
        int IServerConfiguration.ServerKeyId => serverKeyId;
        string IConfigurationId.Id => server;

        void IEntityClone<IServerConfiguration>.CloneFrom(IServerConfiguration serverConf)
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
    internal class JsonDeviceServerConfiguration : IDeviceServerConfiguration, IEntityClone<IDeviceServerConfiguration>
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "clone_code", EmitDefaultValue = false)]
        public string cloneCode;

        string IDeviceServerConfiguration.Server => server;

        string IDeviceServerConfiguration.CloneCode => cloneCode;

        string IConfigurationId.Id => server;

        public void CloneFrom(IDeviceServerConfiguration entity)
        {
            if (string.IsNullOrEmpty(server)) {
                server = entity.Server;
            }
            cloneCode = entity.CloneCode;
        }
    }

    [DataContract]
    internal class JsonDeviceConfiguration : IDeviceConfiguration, IEntityClone<IDeviceConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string deviceToken;

        [DataMember(Name = "private_key", EmitDefaultValue = false)]
        public string privateKey;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        [Obsolete]
        public string[] servers;

        [DataMember(Name = "server_info", EmitDefaultValue = false)]
        public List<JsonDeviceServerConfiguration> serverInfo;

        [DataMember(Name = "secured", EmitDefaultValue = false)]
        public bool? secured;

        string IDeviceConfiguration.DeviceToken => deviceToken;
        byte[] IDeviceConfiguration.DeviceKey => string.IsNullOrEmpty(privateKey) ? null : privateKey.Base64UrlDecode();
        string IConfigurationId.Id => deviceToken;

        private IConfigCollection<IDeviceServerConfiguration> _serverInfo = null;

        public IConfigCollection<IDeviceServerConfiguration> ServerInfo
        {
            get
            {
                if (_serverInfo == null)
                {
                    _serverInfo = new ListConfigCollection<JsonDeviceServerConfiguration, IDeviceServerConfiguration>(
                                    () => serverInfo ?? (serverInfo = new List<JsonDeviceServerConfiguration>()), null);
                }
                return _serverInfo;
            }
        }

        void IEntityClone<IDeviceConfiguration>.CloneFrom(IDeviceConfiguration deviceConf)
        {
            if (string.IsNullOrEmpty(deviceToken))
            {
                deviceToken = deviceConf.DeviceToken;
                if (deviceConf.DeviceKey != null)
                {
                    privateKey = deviceConf.DeviceKey.Base64UrlEncode();
                }
            }
            if (deviceConf.ServerInfo != null) {
                foreach (var si in deviceConf.ServerInfo.List) {
                    ServerInfo.Put(si);
                }
            }
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class JsonConfiguration : IExtensibleDataObject
    {
        [DataMember(Name = "last_server", EmitDefaultValue = false)]
        public string lastServer;

        [DataMember(Name = "last_login", EmitDefaultValue = false)]
        public string lastLogin;

        [DataMember(Name = "users", EmitDefaultValue = false)]
        public List<JsonUserConfiguration> users;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        public List<JsonServerConfiguration> servers;

        [DataMember(Name = "devices", EmitDefaultValue = false)]
        public List<JsonDeviceConfiguration> devices;

        [DataMember(Name = "security", EmitDefaultValue = false)]
        public string security;
        public ExtensionDataObject ExtensionData { get; set; }
    }
}