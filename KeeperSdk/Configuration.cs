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
using System.Linq;

namespace KeeperSecurity.Sdk
{
    public interface IConfigurationId
    {
        string Id { get; }
    }

    public interface IConfigCollection<T> where T : class, IConfigurationId
    {
        T Get(string id);
        void Put(T configuration);
        void Delete(string id);
        IEnumerable<T> List { get; }
    }

    public interface IUserDeviceConfiguration
    {
        string DeviceToken { get; }
    }

    public interface IUserConfiguration: IConfigurationId
    {
        string Username { get; }
        string Password { get; }
        string TwoFactorToken { get; }
        string Server { get; }
        IUserDeviceConfiguration LastDevice { get; }
    }

    public interface IServerConfiguration: IConfigurationId
    {
        string Server { get; }
        int ServerKeyId { get; }
        byte[] DeviceId { get; }
    }

    public interface IDeviceServerConfiguration: IConfigurationId
    {
        string Server { get; }
        string CloneCode { get; }
    }

    public interface IDeviceConfiguration: IConfigurationId
    {
        string DeviceToken { get; }
        byte[] DeviceKey { get; }
        IConfigCollection<IDeviceServerConfiguration> ServerInfo { get; }
    }

    public interface IConfigurationStorage
    {
        IConfigCollection<IUserConfiguration> Users { get; }
        IConfigCollection<IServerConfiguration> Servers { get; }
        IConfigCollection<IDeviceConfiguration> Devices { get; }
        string LastLogin { get; set; }
        string LastServer { get; set; }
    }

    public class InMemoryConfigCollection<T> : IConfigCollection<T> where T : class, IConfigurationId
    {
        private readonly Dictionary<string, T> _collection = new Dictionary<string, T>();
        IEnumerable<T> IConfigCollection<T>.List => _collection.Values;
        void IConfigCollection<T>.Delete(string id)
        {
            if (string.IsNullOrEmpty(id)) return;
            _collection.Remove(id);
        }

        T IConfigCollection<T>.Get(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            return _collection.TryGetValue(id, out var result) ? result : default;
        }

        void IConfigCollection<T>.Put(T configuration)
        {
            _collection[configuration.Id] = configuration;
        }
    }

    public class UserDeviceConfiguration : IUserDeviceConfiguration
    {
        public UserDeviceConfiguration(string deviceToken)
        {
            DeviceToken = deviceToken;
        }

        public UserDeviceConfiguration(IUserDeviceConfiguration other) : this(other.DeviceToken)
        {
        }

        public string DeviceToken { get; set; }
        [Obsolete] public string ResumeCode { get; set; }
    }

    public class UserConfiguration : IUserConfiguration
    {
        public UserConfiguration(string username)
        {
            Username = username.AdjustUserName();
        }

        public UserConfiguration(IUserConfiguration other) : this(other.Username)
        {
            Password = other.Password;
            TwoFactorToken = other.TwoFactorToken;
            Server = other.Server;
            if (other.LastDevice != null)
            {
                LastDevice = new UserDeviceConfiguration(other.LastDevice);
            }
        }

        public string Username { get; }
        public string Password { get; set; }
        public string TwoFactorToken { get; set; }
        public string Server { get; set; }
        public IUserDeviceConfiguration LastDevice { get; set; } 

        string IConfigurationId.Id => Username;
    }

    public class ServerConfiguration : IServerConfiguration
    {
        public ServerConfiguration(string server)
        {
            Server = server.AdjustServerName();
        }

        public ServerConfiguration(IServerConfiguration other) : this(other.Server)
        {
            ServerKeyId = other.ServerKeyId;
            DeviceId = other.DeviceId;
        }

        public string Server { get; }
        public int ServerKeyId { get; set; } = 1;
        public byte[] DeviceId { get; set; }

        string IConfigurationId.Id => Server;

    }

    public class DeviceServerConfiguration : IDeviceServerConfiguration
    {
        public DeviceServerConfiguration(string server)
        {
            Server = server;
        }

        public DeviceServerConfiguration(IDeviceServerConfiguration other): this(other.Server)
        {
            CloneCode = other.CloneCode;
        }

        public string Server { get; }
        public string CloneCode { get; set; }
        string IConfigurationId.Id => Server;
    }

    public class DeviceConfiguration : IDeviceConfiguration
    {
        private readonly IConfigCollection<IDeviceServerConfiguration> _serverInfo;
        public DeviceConfiguration(string deviceToken)
        {
            DeviceToken = deviceToken;
            _serverInfo = new InMemoryConfigCollection<IDeviceServerConfiguration>();
        }

        public DeviceConfiguration(IDeviceConfiguration other) : this(other.DeviceToken)
        {
            DeviceKey = other.DeviceKey;
            if (other.ServerInfo != null && other.ServerInfo.List.Any())
            {
                foreach (var serverInfo in other.ServerInfo.List)
                {
                    _serverInfo.Put(new DeviceServerConfiguration(serverInfo));
                }
            }
        }

        public string DeviceToken { get; }
        public byte[] DeviceKey { get; set; }
        public IConfigCollection<IDeviceServerConfiguration> ServerInfo => _serverInfo;
        string IConfigurationId.Id => DeviceToken;

    }

    public class InMemoryConfigurationStorage : IConfigurationStorage
    {
        public InMemoryConfigurationStorage()
        {
            _users = new InMemoryConfigCollection<IUserConfiguration>();
            _servers = new InMemoryConfigCollection<IServerConfiguration>();
            _devices = new InMemoryConfigCollection<IDeviceConfiguration>();
        }

        private readonly InMemoryConfigCollection<IUserConfiguration> _users;
        private readonly InMemoryConfigCollection<IServerConfiguration> _servers;
        private readonly InMemoryConfigCollection<IDeviceConfiguration> _devices;

        IConfigCollection<IUserConfiguration> IConfigurationStorage.Users => _users;
        IConfigCollection<IServerConfiguration> IConfigurationStorage.Servers => _servers;
        IConfigCollection<IDeviceConfiguration> IConfigurationStorage.Devices => _devices;
        public string LastLogin { get; set; }
        public string LastServer { get; set; }

    }

    public static class ConfigurationExtension
    {
        public static string AdjustServerName(this string server)
        {
            if (string.IsNullOrEmpty(server))
            {
                return "keepersecurity.com";
            }

            var builder = new UriBuilder(server);
            return builder.Uri.Host.ToLowerInvariant();
        }

        public static string AdjustUserName(this string username)
        {
            return username.ToLowerInvariant();
        }
    }
}