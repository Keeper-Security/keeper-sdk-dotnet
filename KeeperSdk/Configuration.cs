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
using System.Linq;

namespace KeeperSecurity.Sdk
{
    public interface IUserConfiguration
    {
        string Username { get; }
        string Password { get; }
        string TwoFactorToken { get; set; }
    }

    public interface IServerConfiguration
    {
        string Server { get; }
        byte[] DeviceId { get; set; }
        int ServerKeyId { get; set; }
    }

    public interface IUserStorage
    {
        string LastLogin { get; }
        IUserConfiguration Get(string username);
        void Put(IUserConfiguration userConfiguration);
        IEnumerable<IUserConfiguration> Users { get; }
    }

    public interface IServerStorage
    {
        string LastServer { get; }
        IServerConfiguration Get(string server);
        void Put(IServerConfiguration serverConfiguration);
        IEnumerable<IServerConfiguration> Servers { get; }
    }

    public interface IConfigurationStorage : IUserStorage, IServerStorage { }

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
        }

        public string Username { get; }
        public string Password { get; set; }
        public string TwoFactorToken { get; set; }
    }

    public class ServerConfiguration : IServerConfiguration
    {
        public ServerConfiguration(string server)
        {
            Server = server.AdjustServerName();
        }

        public ServerConfiguration(IServerConfiguration other) : this(other.Server)
        {
            DeviceId = other.DeviceId;
            ServerKeyId = other.ServerKeyId;
        }

        public string Server { get; }
        public byte[] DeviceId { get; set; }
        public int ServerKeyId { get; set; } = 1;
    }

    public class InMemoryConfigurationStorage : IConfigurationStorage
    {
        public InMemoryConfigurationStorage()
        {
            _users = new Dictionary<string, UserConfiguration>();
            _servers = new Dictionary<string, ServerConfiguration>();
        }

        internal readonly Dictionary<string, UserConfiguration> _users;
        internal readonly Dictionary<string, ServerConfiguration> _servers;

        public string LastServer { get; set; }
        public string LastLogin { get; set; }

        public IEnumerable<IUserConfiguration> Users => _users.Values;
        public IEnumerable<IServerConfiguration> Servers => _servers.Values;


        IUserConfiguration IUserStorage.Get(string username)
        {
            var name = username.AdjustUserName();
            return _users.Values.Where(x => string.Compare(name, x.Username) == 0).FirstOrDefault();
        }

        void IUserStorage.Put(IUserConfiguration userConfiguration)
        {
            var u = new UserConfiguration(userConfiguration.Username)
            {
                Password = userConfiguration.Password,
                TwoFactorToken = userConfiguration.TwoFactorToken
            };
            _users[u.Username] = u;
            LastLogin = u.Username;
        }

        IServerConfiguration IServerStorage.Get(string server)
        {
            var url = server.AdjustServerName();
            return _servers.Values.Where(x => string.Compare(url, x.Server) == 0).FirstOrDefault();
        }

        void IServerStorage.Put(IServerConfiguration serverConfiguration)
        {
            var s = new ServerConfiguration(serverConfiguration.Server)
            {
                DeviceId = serverConfiguration.DeviceId.ToArray(),
                ServerKeyId = serverConfiguration.ServerKeyId
            };
            _servers[s.Server] = s;
            LastServer = s.Server;
        }
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
