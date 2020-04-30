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

namespace KeeperSecurity.Sdk
{
    public abstract class JsonConfigurationBase : IConfigurationStorage
    {
        protected abstract byte[] LoadJson();
        protected abstract void StoreJson(byte[] json);

        private JsonConfiguration _configuration;
        private long _loadEpochMillis;

        private JsonConfiguration GetJsonConfiguration()
        {
            var nowMillis = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            if (nowMillis - _loadEpochMillis > 1000)
            {
                _configuration = null;
            }

            if (_configuration == null)
            {
                var jsonBytes = LoadJson();
                _loadEpochMillis = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                if (jsonBytes != null && jsonBytes.Length >= 2)
                {
                    _configuration = JsonUtils.ParseJson<JsonConfiguration>(jsonBytes);
                }
                else
                {
                    _configuration = new JsonConfiguration();
                }
            }

            return _configuration;
        }

        public string LastLogin => GetJsonConfiguration().lastLogin;

        public IEnumerable<IUserConfiguration> Users
        {
            get
            {
                var conf = GetJsonConfiguration();
                return (conf.users ?? Enumerable.Empty<JsonUserConfiguration>())
                    .Select(x => new UserConfiguration(x.user)
                    {
                        Password = x.password,
                        TwoFactorToken = x.twoFactorToken,
                    });
            }
        }

        public IUserConfiguration GetUser(string username)
        {
            var conf = GetJsonConfiguration();
            if (conf.users == null) return null;

            var name = username.AdjustUserName();
            var uc = conf.users.FirstOrDefault(x => x.user == name);
            if (uc == null) return null;

            return new UserConfiguration(name)
            {
                Password = uc.password,
                TwoFactorToken = uc.twoFactorToken,
            };
        }

        public void PutUser(IUserConfiguration userConfiguration)
        {
            var name = userConfiguration.Username.AdjustUserName();
            var conf = GetJsonConfiguration();
            var uc = (conf.users ?? Enumerable.Empty<JsonUserConfiguration>()).FirstOrDefault(x => x.user == name);
            if (uc == null)
            {
                uc = new JsonUserConfiguration
                {
                    user = name
                };
                conf.users = (conf.users ?? Enumerable.Empty<JsonUserConfiguration>()).Concat(new[] {uc}).ToArray();
            }

            uc.twoFactorToken = userConfiguration.TwoFactorToken;
            conf.lastLogin = name;
            StoreJson(JsonUtils.DumpJson(conf));
        }


        public string LastServer => GetJsonConfiguration().lastServer;

        public IEnumerable<IServerConfiguration> Servers
        {
            get
            {
                var conf = GetJsonConfiguration();
                return (conf.servers ?? Enumerable.Empty<JsonServerConfiguration>())
                    .Select(x => new ServerConfiguration(x.server)
                    {
                        ServerKeyId = x.serverKeyId,
                        DeviceId = string.IsNullOrEmpty(x.deviceId) ? null : x.deviceId.Base64UrlDecode()
                    });
                ;
            }
        }

        public IServerConfiguration GetServer(string server)
        {
            var conf = GetJsonConfiguration();
            if (conf.servers != null)
            {
                var serverName = server.AdjustServerName();
                return conf.servers.Where(x => x.server == serverName)
                    .Select(x => new ServerConfiguration(x.server)
                    {
                        ServerKeyId = x.serverKeyId,
                        DeviceId = string.IsNullOrEmpty(x.deviceId) ? null : x.deviceId.Base64UrlDecode()
                    })
                    .FirstOrDefault();
            }

            return null;
        }

        public void PutServer(IServerConfiguration serverConfiguration)
        {
            var name = serverConfiguration.Server.AdjustUserName();
            var conf = GetJsonConfiguration();
            var sc = (conf.servers ?? Enumerable.Empty<JsonServerConfiguration>())
                .FirstOrDefault(x => x.server == name);
            if (sc == null)
            {
                sc = new JsonServerConfiguration
                {
                    server = name
                };
                conf.servers = (conf.servers ?? Enumerable.Empty<JsonServerConfiguration>()).Concat(new[] {sc})
                    .ToArray();
            }

            sc.serverKeyId = serverConfiguration.ServerKeyId;
            if (serverConfiguration.DeviceId != null)
            {
                sc.deviceId = serverConfiguration.DeviceId.Base64UrlEncode();
            }

            conf.lastServer = name;

            StoreJson(JsonUtils.DumpJson(conf));
        }
    }

    public class JsonConfigurationStorage : JsonConfigurationBase
    {
        public JsonConfigurationStorage() : this("config.json")
        {
        }

        public JsonConfigurationStorage(string fileName)
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

        protected override byte[] LoadJson()
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

        protected override void StoreJson(byte[] json)
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
    public class JsonUserConfiguration : IExtensibleDataObject
    {
        [DataMember(Name = "user", EmitDefaultValue = false)]
        public string user;

        [DataMember(Name = "password", EmitDefaultValue = false)]
        //#pragma warning disable 0649
        public string password;

        //#pragma warning restore 0649
        [DataMember(Name = "mfa_token", EmitDefaultValue = false)]
        public string twoFactorToken;

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    public class JsonServerConfiguration : IExtensibleDataObject
    {
        [DataMember(Name = "server", EmitDefaultValue = false)]
        public string server;

        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        public string deviceId;

        [DataMember(Name = "server_key_id", EmitDefaultValue = false)]
        public int serverKeyId;

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
        public JsonUserConfiguration[] users;

        [DataMember(Name = "servers", EmitDefaultValue = false)]
        public JsonServerConfiguration[] servers;

        public ExtensionDataObject ExtensionData { get; set; }
    }
}