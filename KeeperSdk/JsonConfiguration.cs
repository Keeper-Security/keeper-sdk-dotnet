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

namespace KeeperSecurity.Sdk
{
    public interface IStorageProtection
    {
        string Obscure(string data);
        string Clarify(string data);
    }

    public interface IStorageProtectionFactory
    {
        IStorageProtection Resolve(string protection);
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

    public interface IJsonConfigurationLoader
    {
        byte[] LoadJson();
        void StoreJson(byte[] json);
    }

    public class JsonConfigurationCache
    {
        private readonly IJsonConfigurationLoader _loader;

        public JsonConfigurationCache(IJsonConfigurationLoader loader)
        {
            _loader = loader;
            ReadTimeout = 2000;
            WriteTimeout = 2000;
        }

        public int ReadTimeout { get; set; }
        private long _readEpochMillis;

        public bool SkipSecurity { get; set; }
        public string SecurityAlgorithm { get; set; }
        public int WriteTimeout { get; set; }

        private JsonConfiguration _configuration;
        public JsonConfiguration Configuration
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
                                if (StorageProtection != null && !string.IsNullOrEmpty(_configuration.security))
                                {
                                    var protector = StorageProtection.Resolve(_configuration.security);
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
                    else
                    {
                        Debug.WriteLine("Why?");
                    }
                });
            }
        }

        public void Flush()
        {
            lock (this)
            {
                _storeConfigurationTask = null;

                if (_configuration == null) return;
                var algorithm = SecurityAlgorithm ?? _configuration.security;
                if (!SkipSecurity && StorageProtection != null && !string.IsNullOrEmpty(algorithm))
                {
                    var protector = StorageProtection.Resolve(algorithm);
                    if (protector != null)
                    {
                        _configuration.security = algorithm;
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

                        foreach (var user in _configuration.users)
                        {
                            if (string.IsNullOrEmpty(user.user_password) && string.IsNullOrEmpty(user._last_device?.resume_code)) continue;
                            try
                            {
                                string encryptedPassword = null;
                                string encryptedResumeCode = null;
                                if (!string.IsNullOrEmpty(user.user_password))
                                {
                                    encryptedPassword = protector.Obscure(user.user_password);
                                }

                                if (!string.IsNullOrEmpty(user._last_device?.resume_code))
                                {
                                    encryptedResumeCode = protector.Obscure(user._last_device.resume_code);
                                }
                                
                                user.user_password = encryptedPassword;
                                if (user._last_device != null)
                                {
                                    user._last_device.resume_code = encryptedResumeCode;
                                }

                                user.secured = true;
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                            }
                        }
                    }
                }

                _loader.StoreJson(JsonUtils.DumpJson(_configuration));
                _configuration = null;
            }
        }

        public IStorageProtectionFactory StorageProtection { get; set; }
    }

    public sealed class JsonConfigurationStorage : IConfigurationStorage
    {
        public JsonConfigurationStorage() : this(new JsonConfigurationCache(new JsonConfigurationFileLoader()))
        {
        }

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
    }

    public class JsonConfigurationFileLoader : IJsonConfigurationLoader
    {
        public JsonConfigurationFileLoader() : this("config.json")
        {
        }

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

        public string FilePath { get; }

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
    public class JsonUserDeviceConfiguration : IUserDeviceConfiguration, IEntityClone<IUserDeviceConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string device_token;

        [DataMember(Name = "resume_code", EmitDefaultValue = false)]
        public string resume_code;

        [DataMember(Name = "logout_timer", EmitDefaultValue = false)]
        public int? logout_timer;

        public ExtensionDataObject ExtensionData { get; set; }

        void IEntityClone<IUserDeviceConfiguration>.CloneFrom(IUserDeviceConfiguration userDevConf)
        {
            if (string.IsNullOrEmpty(device_token))
            {
                device_token = userDevConf.DeviceToken;
            }
            resume_code = userDevConf.ResumeCode;
            logout_timer = userDevConf.LogoutTimer;
        }

        string IUserDeviceConfiguration.DeviceToken => device_token;
        string IUserDeviceConfiguration.ResumeCode => resume_code;
        int? IUserDeviceConfiguration.LogoutTimer => logout_timer;
    }


    [DataContract]
    public class JsonUserConfiguration : IUserConfiguration, IEntityClone<IUserConfiguration>, IExtensibleDataObject
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
                    resume_code = userConf.LastDevice.ResumeCode,
                    logout_timer = userConf.LastDevice.LogoutTimer
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
    public class JsonServerConfiguration : IServerConfiguration, IEntityClone<IServerConfiguration>, IExtensibleDataObject
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "server_key_id", EmitDefaultValue = false)]
        public int serverKeyId;

        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        public string deviceId;

        string IServerConfiguration.Server => server;
        int IServerConfiguration.ServerKeyId => serverKeyId;
        byte[] IServerConfiguration.DeviceId => string.IsNullOrEmpty(deviceId) ? null : deviceId.Base64UrlDecode();
        string IConfigurationId.Id => server;

        void IEntityClone<IServerConfiguration>.CloneFrom(IServerConfiguration serverConf)
        {
            if (string.IsNullOrEmpty(server))
            {
                server = serverConf.Server;
            }
            serverKeyId = serverConf.ServerKeyId;
            deviceId = serverConf.DeviceId?.Base64UrlEncode();
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    public class JsonDeviceConfiguration : IDeviceConfiguration, IEntityClone<IDeviceConfiguration>, IExtensibleDataObject
    {

        [DataMember(Name = "device_token", EmitDefaultValue = false)]
        public string deviceToken;

        [DataMember(Name = "private_key", EmitDefaultValue = false)]
        public string privateKey;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        public string[] servers;

        [DataMember(Name = "secured", EmitDefaultValue = false)]
        public bool? secured;

        string IDeviceConfiguration.DeviceToken => deviceToken;
        byte[] IDeviceConfiguration.DeviceKey => string.IsNullOrEmpty(privateKey) ? null : privateKey.Base64UrlDecode();
        IEnumerable<string> IDeviceConfiguration.Servers => servers;
        string IConfigurationId.Id => deviceToken;

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

            if (deviceConf.Servers != null)
            {
                servers = deviceConf.Servers.ToArray();
            }
        }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    public class JsonConfiguration : IExtensibleDataObject
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