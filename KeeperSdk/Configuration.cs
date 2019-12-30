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
    public class UserConfiguration
    {
        public UserConfiguration(string username)
        {
            Username = username.AdjustUserName();
        }

        public string Username { get; }
        public string Password { get; set; }
        public string TwoFactorToken { get; set; }
    }

    public class ServerConfiguration
    {
        public ServerConfiguration(string server)
        {
            Server = server.AdjustServerName();
        }

        public string Server { get; }
        public byte[] DeviceId { get; set; }
        public int ServerKeyId { get; set; } = 1;
    }

    public class Configuration
    {
        public Configuration()
        {
            _users = new Dictionary<string, UserConfiguration>();
            _servers = new Dictionary<string, ServerConfiguration>();
        }

        public Configuration(Configuration other) : this()
        {
            MergeConfiguration(other);
        }

        public UserConfiguration GetUserConfiguration(string username)
        {
            var name = username.AdjustUserName();
            return _users.Values.Where(x => string.Compare(name, x.Username) == 0).FirstOrDefault();
        }
        public ServerConfiguration GetServerConfiguration(string server)
        {
            var url = server.AdjustServerName();
            return _servers.Values.Where(x => string.Compare(url, x.Server) == 0).FirstOrDefault();
        }

        public void MergeUserConfiguration(UserConfiguration user)
        {
            var u = new UserConfiguration(user.Username)
            {
                Password = user.Password,
                TwoFactorToken = user.TwoFactorToken
            };
            _users[u.Username] = u;
        }

        public void MergeServerConfiguration(ServerConfiguration server)
        {
            var s = new ServerConfiguration(server.Server)
            {
                DeviceId = server.DeviceId.ToArray(),
                ServerKeyId = server.ServerKeyId
            };
            _servers[s.Server] = s;
        }

        public void MergeConfiguration(Configuration other)
        {
            if (!string.IsNullOrEmpty(other.LastLogin))
            {
                LastLogin = other.LastLogin;
            }
            if (!string.IsNullOrEmpty(other.LastServer))
            {
                LastServer = other.LastServer;
            }

            var users = other.Users;
            if (users != null)
            {
                foreach (var user in users)
                {
                    MergeUserConfiguration(user);
                }
            }

            var servers = other.Servers;
            if (servers != null)
            {
                foreach (var server in servers)
                {
                    MergeServerConfiguration(server);
                }
            }
        }

        internal readonly Dictionary<string, UserConfiguration> _users;
        internal readonly Dictionary<string, ServerConfiguration> _servers;

        public string LastServer { get; set; }
        public string LastLogin { get; set; }

        public IEnumerable<UserConfiguration> Users => _users.Values;
        public IEnumerable<ServerConfiguration> Servers => _servers.Values;
    }


    public interface IConfigurationStorage
    {
        Configuration Get();
        void Put(Configuration configuration);
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

    public class InMemoryConfigurationStorage : IConfigurationStorage
    {
        private readonly Configuration _configuration;

        public InMemoryConfigurationStorage()
        {
            _configuration = new Configuration();
        }

        public InMemoryConfigurationStorage(Configuration configuration) : this()
        {
            _configuration.MergeConfiguration(configuration);
        }

        public Configuration Get()
        {
            return new Configuration(_configuration);
        }

        public void Put(Configuration configuration)
        {
            _configuration.LastLogin = configuration.LastLogin;
            _configuration.LastServer = configuration.LastServer;
            foreach (var user in configuration.Users)
            {
                if (!_configuration._users.TryGetValue(user.Username, out UserConfiguration uc))
                {
                    uc = new UserConfiguration(user.Username);
                    _configuration._users.Add(uc.Username, uc);
                }
                uc.TwoFactorToken = user.TwoFactorToken;
            }

            foreach (var server in configuration.Servers)
            {
                if (!_configuration._servers.TryGetValue(server.Server, out ServerConfiguration sc))
                {
                    sc = new ServerConfiguration(server.Server);
                    _configuration._servers.Add(server.Server, sc);
                }
                sc.DeviceId = server.DeviceId;
                sc.ServerKeyId = server.ServerKeyId;
            }
        }
    }
}
