//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
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

        public static Configuration JsonConfigurationToConfiguration(JsonConfiguration json)
        {
            var configuration = new Configuration
            {
                LastLogin = json.lastLogin,
                LastServer = json.lastServer
            };
            if (json.users != null)
            {
                foreach (var u in json.users)
                {
                    if (!string.IsNullOrEmpty(u.user))
                    {
                        var uc = new UserConfiguration(u.user)
                        {
                            Password = u.password,
                            TwoFactorToken = u.twoFactorToken
                        };
                        configuration._users.Add(uc.Username, uc);
                    }
                }
            }
            if (json.servers != null)
            {
                foreach (var s in json.servers)
                {
                    if (!string.IsNullOrEmpty(s.server))
                    {
                        var sc = new ServerConfiguration(s.server)
                        {
                            DeviceId = s.deviceId.Base64UrlDecode(),
                            ServerKeyId = s.serverKeyId
                        };
                        configuration._servers.Add(sc.Server, sc);
                    }
                }
            }
            return configuration;
        }

        public Configuration Get()
        {
            var jsonBytes = LoadJson();
            if (jsonBytes != null && jsonBytes.Length >= 2)
            {
                var json = JsonUtils.ParseJson<JsonConfiguration>(jsonBytes);
                return JsonConfigurationToConfiguration(json);
            }

            return new Configuration();
        }

        public void Put(Configuration configuration)
        {
            JsonConfiguration json;
            var jsonBytes = LoadJson();
            if (jsonBytes != null && jsonBytes.Length >= 2)
            {
                json = JsonUtils.ParseJson<JsonConfiguration>(jsonBytes);
            }
            else
            {
                json = new JsonConfiguration();
            }
            json.lastLogin = configuration.LastLogin;
            json.lastServer = configuration.LastServer;
            var users = new Dictionary<string, JsonUserConfiguration>();
            if (json.users != null)
            {
                foreach (var u in json.users)
                {
                    if (!string.IsNullOrEmpty(u.user))
                    {
                        var username = u.user.AdjustUserName();
                        users.Add(username, u);
                    }
                }
            }
            foreach (var u in configuration.Users)
            {
                if (!users.TryGetValue(u.Username, out JsonUserConfiguration juser))
                {
                    juser = new JsonUserConfiguration
                    {
                        user = u.Username,
                    };
                    users.Add(u.Username, juser);
                }
                juser.twoFactorToken = u.TwoFactorToken;
            }

            var servers = new Dictionary<string, JsonServerConfiguration>();
            if (json.servers != null)
            {
                foreach (var s in json.servers)
                {
                    if (!string.IsNullOrEmpty(s.server))
                    {
                        var servername = s.server.AdjustServerName();
                        servers.Add(servername, s);
                    }
                }
            }
            foreach (var s in configuration.Servers)
            {
                if (!servers.TryGetValue(s.Server, out JsonServerConfiguration jserver))
                {
                    jserver = new JsonServerConfiguration
                    {
                        server = s.Server
                    };
                    servers.Add(s.Server, jserver);
                }
                jserver.deviceId = s.DeviceId.Base64UrlEncode();
                jserver.serverKeyId = s.ServerKeyId;
            }

            json.users = users.Values.OrderBy(x => x.user).ToArray();
            json.servers = servers.Values.OrderBy(x => x.server).ToArray();

            var jsonData = JsonUtils.DumpJson(json);

            StoreJson(jsonData);
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
                var personalFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), ".keeper");
                if (!Directory.Exists(personalFolder))
                {
                    Directory.CreateDirectory(personalFolder);
                }
                FilePath = Path.Combine(personalFolder, fileName);
            }

            Debug.WriteLine(string.Format("JSON config path: \"{0}\"", FilePath));
        }

        public string FilePath { get; private set; }

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
