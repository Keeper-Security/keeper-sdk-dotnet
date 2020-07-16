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

    public interface IUserConfiguration: IConfigurationId
    {
        string Username { get; }
        string Password { get; }
        string TwoFactorToken { get; }
        string Server { get; }
        string DeviceToken { get; }
        string CloneCode { get; }
    }

    public interface IServerConfiguration: IConfigurationId
    {
        string Server { get; }
        int ServerKeyId { get; }
        byte[] DeviceId { get; }
    }


    public interface IDeviceConfiguration: IConfigurationId
    {
        string DeviceToken { get; }
        byte[] DeviceKey { get; }
        IEnumerable<string> Servers { get; }
    }

    public interface IConfigCollection<T> where T: class, IConfigurationId
    {
        T Get(string id);
        void Put(T configuration);
        void Delete(string id);
        IEnumerable<T> List { get; }
    }


    public interface IConfigurationStorage
    {
        IConfigCollection<IUserConfiguration> Users { get; }
        IConfigCollection<IServerConfiguration> Servers { get; }
        IConfigCollection<IDeviceConfiguration> Devices { get; }
        string LastLogin { get; set; }
        string LastServer { get; set; }
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
            DeviceToken = other.DeviceToken;
            CloneCode = other.CloneCode;
        }

        public string Username { get; }
        public string Password { get; set; }
        public string TwoFactorToken { get; set; }
        public string Server { get; set; }
        public string DeviceToken { get; set; }
        public string CloneCode { get; set; }

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

    public class DeviceConfiguration : IDeviceConfiguration
    {
        public DeviceConfiguration(string deviceToken)
        {
            DeviceToken = deviceToken;
            KeeperServers = new HashSet<string>();
        }

        public DeviceConfiguration(IDeviceConfiguration other) : this(other.DeviceToken)
        {
            DeviceKey = other.DeviceKey;
            if (other.Servers == null) return;
            foreach (var server in other.Servers)
            {
                KeeperServers.Add(server);
            }
        }

        public string DeviceToken { get; }
        public byte[] DeviceKey { get; set; }
        public ISet<string> KeeperServers { get; }
        public IEnumerable<string> Servers => KeeperServers;
        string IConfigurationId.Id => DeviceToken;

    }

    public class InMemoryConfigCollection<T> : IConfigCollection<T> where T: class, IConfigurationId
    {
        private readonly Dictionary<string, T> _collection = new Dictionary<string, T>();
        IEnumerable<T>  IConfigCollection<T>.List => _collection.Values;
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