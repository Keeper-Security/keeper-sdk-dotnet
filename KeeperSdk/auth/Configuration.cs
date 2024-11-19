using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Configuration
{
    /// <summary>
    /// Configuration entity identity interface.
    /// </summary>
    public interface IConfigurationId
    {
        /// <summary>
        /// Gets identity.
        /// </summary>
        string Id { get; }
    }

    /// <summary>
    /// Provides a base entity access interface. 
    /// </summary>
    /// <typeparam name="T">Entity type</typeparam>
    public interface IConfigCollection<T> where T : IConfigurationId
    {
        /// <summary>
        /// Return entity by ID.
        /// </summary>
        /// <param name="id">Entity ID</param>
        /// <returns></returns>
        T Get(string id);

        /// <summary>
        /// Store entity to collection.
        /// </summary>
        /// <param name="entity"></param>
        void Put(T entity);

        /// <summary>
        /// Delete entity from collection by ID.
        /// </summary>
        /// <param name="id"></param>
        void Delete(string id);

        /// <summary>
        /// Return all entities the collection.
        /// </summary>
        IEnumerable<T> List { get; }
    }

    /// <summary>
    /// Define User's Device entity
    /// </summary>
    public interface IUserDeviceConfiguration
    {
        /// <summary>
        /// Last used device token by user.
        /// </summary>
        string DeviceToken { get; }
    }

    /// <summary>
    /// Defines User entity.
    /// </summary>
    public interface IUserConfiguration : IConfigurationId
    {
        /// <summary>
        /// User's email address.
        /// </summary>
        string Username { get; }

        /// <summary>
        /// User's password. Optional.
        /// </summary>
        /// <remarks>
        /// This property is never stored by this library.
        /// <see cref="IAuth.Login"/> uses this property if it is set by customer.
        /// </remarks>
        string Password { get; }

        /// <summary>
        /// Keeper region where user is hosted.
        /// </summary>
        string Server { get; }

        /// <summary>
        /// Last used device.
        /// </summary>
        IUserDeviceConfiguration LastDevice { get; }
    }

    /// <summary>
    /// Defines Keeper server entity.
    /// </summary>
    public interface IServerConfiguration : IConfigurationId
    {
        /// <summary>
        /// Keeper server host.
        /// </summary>
        string Server { get; }

        /// <summary>
        /// Server Key ID.
        /// </summary>
        int ServerKeyId { get; }
    }

    /// <summary>
    /// Defines device's server entity.
    /// </summary>
    public interface IDeviceServerConfiguration : IConfigurationId
    {
        /// <summary>
        /// Keeper server host.
        /// </summary>
        string Server { get; }

        /// <summary>
        /// Resumption code.
        /// </summary>
        string CloneCode { get; }
    }

    /// <summary>
    /// Defines device entity.
    /// </summary>
    public interface IDeviceConfiguration : IConfigurationId
    {
        /// <summary>
        /// Device token.
        /// </summary>
        string DeviceToken { get; }

        /// <summary>
        /// Device EC private key.
        /// </summary>
        byte[] DeviceKey { get; }

        /// <summary>
        /// Device's server collection.
        /// </summary>
        IConfigCollection<IDeviceServerConfiguration> ServerInfo { get; }
    }

    /// <summary>
    /// Defines Keeper configuration properties.
    /// </summary>
    public interface IKeeperConfiguration
    {
        /// <summary>
        /// Gets user collection.
        /// </summary>
        IConfigCollection<IUserConfiguration> Users { get; }

        /// <summary>
        /// Gets server collection.
        /// </summary>
        IConfigCollection<IServerConfiguration> Servers { get; }

        /// <summary>
        /// Gets device collection.
        /// </summary>
        IConfigCollection<IDeviceConfiguration> Devices { get; }

        /// <summary>
        /// Gets last logged in user.
        /// </summary>
        string LastLogin { get; set; }

        /// <summary>
        /// Gets last used Keeper server.
        /// </summary>
        string LastServer { get; set; }

    }

    /// <summary>
    /// Defines Keeper configuration storage
    /// </summary>
    public interface IConfigurationStorage
    {
        /// <summary>
        /// Gets configuration from storage
        /// </summary>
        /// <returns></returns>
        IKeeperConfiguration Get();

        /// <summary>
        /// Stores configuration to storage
        /// </summary>
        /// <param name="configuration"></param>
        void Put(IKeeperConfiguration configuration);
    }

    /// <exclude/>
    public class InMemoryConfigCollection<T> : IConfigCollection<T> where T : class, IConfigurationId
    {
        private readonly Dictionary<string, T> _collection = new();
        IEnumerable<T> IConfigCollection<T>.List => _collection.Values;

        public void Delete(string id)
        {
            if (string.IsNullOrEmpty(id)) return;
            _collection.Remove(id);
        }

        public T Get(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            return _collection.TryGetValue(id, out var result) ? result : default;
        }

        public void Put(T configuration)
        {
            _collection[configuration.Id] = configuration;
        }
    }

    /// <summary>
    /// User's Device entity
    /// </summary>
    public class UserDeviceConfiguration : IUserDeviceConfiguration
    {
        /// <summary>
        /// Creates instance for device token.
        /// </summary>
        /// <param name="deviceToken"></param>
        public UserDeviceConfiguration(string deviceToken)
        {
            DeviceToken = deviceToken;
        }

        /// <summary>
        /// Creates instance from another entity.
        /// </summary>
        /// <param name="other">User's device entity</param>
        public UserDeviceConfiguration(IUserDeviceConfiguration other) : this(other.DeviceToken)
        {
        }

        /// <inheritdoc/>>
        public string DeviceToken { get; set; }

        /// <exclude/>
        [Obsolete]
        public string ResumeCode { get; set; }
    }

    /// <summary>
    /// User entity.
    /// </summary>
    public class UserConfiguration : IUserConfiguration
    {
        /// <summary>
        /// Creates instance for user email.
        /// </summary>
        /// <param name="username">User email.</param>
        public UserConfiguration(string username)
        {
            Username = username.AdjustUserName();
        }

        /// <summary>
        /// Creates instance from another user entity.
        /// </summary>
        /// <param name="other">User entity.</param>
        public UserConfiguration(IUserConfiguration other) : this(other.Username)
        {
            Password = other.Password;
            Server = other.Server;
            if (other.LastDevice != null)
            {
                LastDevice = new UserDeviceConfiguration(other.LastDevice);
            }
        }

        /// <inheritdoc/>>
        public string Username { get; }

        /// <inheritdoc/>>
        public string Password { get; set; }

        /// <inheritdoc/>>
        public string Server { get; set; }

        /// <inheritdoc/>>
        public IUserDeviceConfiguration LastDevice { get; set; }

        /// <exclude/>
        string IConfigurationId.Id => Username;
    }

    /// <summary>
    /// Server entity.
    /// </summary>
    public class ServerConfiguration : IServerConfiguration
    {
        /// <summary>
        /// Creates instance for Keeper server.
        /// </summary>
        /// <param name="server">Keeper server.</param>
        public ServerConfiguration(string server)
        {
            Server = server.AdjustServerName();
        }

        /// <summary>
        /// Creates instance from another user entity.
        /// </summary>
        /// <param name="other">Keeper server entity.</param>
        public ServerConfiguration(IServerConfiguration other) : this(other.Server)
        {
            ServerKeyId = other.ServerKeyId;
        }

        /// <inheritdoc/>>
        public string Server { get; }

        /// <inheritdoc/>>
        public int ServerKeyId { get; set; } = 1;

        /// <exclude/>
        string IConfigurationId.Id => Server;
    }

    /// <summary>
    /// Device server entity.
    /// </summary>
    public class DeviceServerConfiguration : IDeviceServerConfiguration
    {
        /// <summary>
        /// Creates instance for server.
        /// </summary>
        /// <param name="server">Keeper server host.</param>
        public DeviceServerConfiguration(string server)
        {
            Server = server;
        }

        /// <summary>
        /// Creates instance from another user entity.
        /// </summary>
        /// <param name="other">Device server entity.</param>
        public DeviceServerConfiguration(IDeviceServerConfiguration other) : this(other.Server)
        {
            CloneCode = other.CloneCode;
        }

        /// <inheritdoc/>>
        public string Server { get; }

        /// <inheritdoc/>>
        public string CloneCode { get; set; }

        /// <exclude/>
        string IConfigurationId.Id => Server;
    }

    /// <summary>
    /// Device entity.
    /// </summary>
    public class DeviceConfiguration : IDeviceConfiguration
    {
        private readonly IConfigCollection<IDeviceServerConfiguration> _serverInfo;

        /// <summary>
        /// Create instance from device token.
        /// </summary>
        /// <param name="deviceToken">Device token.</param>
        public DeviceConfiguration(string deviceToken)
        {
            DeviceToken = deviceToken;
            _serverInfo = new InMemoryConfigCollection<IDeviceServerConfiguration>();
        }

        /// <summary>
        /// Creates instance from another device entity.
        /// </summary>
        /// <param name="other">Device entity.</param>
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

        /// <inheritdoc/>>
        public string DeviceToken { get; }

        /// <inheritdoc/>>
        public byte[] DeviceKey { get; set; }

        /// <inheritdoc/>>
        public IConfigCollection<IDeviceServerConfiguration> ServerInfo => _serverInfo;

        /// <exclude/>
        string IConfigurationId.Id => DeviceToken;

    }

    /// <exclude/>
    public class KeeperConfiguration : IKeeperConfiguration
    {
        private readonly InMemoryConfigCollection<IUserConfiguration> _users = new();
        private readonly InMemoryConfigCollection<IServerConfiguration> _servers = new();
        private readonly InMemoryConfigCollection<IDeviceConfiguration> _devices = new();

        public KeeperConfiguration() : this(null)
        {
        }

        public KeeperConfiguration(IKeeperConfiguration other)
        {
            if (other == null) return;
            LastLogin = other.LastLogin;
            LastServer = other.LastServer;
            foreach (var uc in other.Users.List)
            {
                _users.Put(new UserConfiguration(uc));
            }

            foreach (var dc in other.Devices.List)
            {
                _devices.Put(new DeviceConfiguration(dc));
            }

            foreach (var sc in other.Servers.List)
            {
                _servers.Put(new ServerConfiguration(sc));
            }
        }

        IConfigCollection<IUserConfiguration> IKeeperConfiguration.Users => _users;
        IConfigCollection<IServerConfiguration> IKeeperConfiguration.Servers => _servers;
        IConfigCollection<IDeviceConfiguration> IKeeperConfiguration.Devices => _devices;
        public string LastLogin { get; set; }
        public string LastServer { get; set; }

    }

    /// <exclude/>
    public class InMemoryConfigurationStorage : IConfigurationStorage
    {
        private IKeeperConfiguration _configuration;

        public InMemoryConfigurationStorage() : this(null)
        {
        }

        public InMemoryConfigurationStorage(IKeeperConfiguration configuration)
        {
            _configuration = configuration ?? new KeeperConfiguration();
        }

        public IKeeperConfiguration Get()
        {
            return _configuration;
        }

        public void Put(IKeeperConfiguration configuration)
        {
            _configuration = new KeeperConfiguration(configuration);
        }
    }

    internal static class ConfigurationExtension
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

        public static void Assign(this IKeeperConfiguration configuration, IKeeperConfiguration other)
        {
            configuration.LastServer = other.LastServer;
            configuration.LastLogin = other.LastLogin;
            var ids = new HashSet<string>();

            ids.Clear();
            ids.UnionWith(configuration.Users.List.Select(x => x.Id));
            foreach (var user in other.Users.List)
            {
                configuration.Users.Put(user);
                ids.Remove(user.Id);
            }
            if (ids.Count > 0) {
                foreach (var id in ids)
                {
                    configuration.Users.Delete(id);
                }
            }

            ids.Clear();
            ids.UnionWith(configuration.Servers.List.Select(x => x.Id));
            foreach (var server in other.Servers.List)
            {
                configuration.Servers.Put(server);
                if (ids.Contains(server.Id))
                {
                    ids.Remove(server.Id);
                }
            }
            if (ids.Count > 0)
            {
                foreach (var id in ids)
                {
                    configuration.Servers.Delete(id);
                }
            }

            ids.Clear();
            ids.UnionWith(configuration.Devices.List.Select(x => x.Id));
            foreach (var device in other.Devices.List)
            {
                configuration.Devices.Put(device);
                if (ids.Contains(device.Id))
                {
                    ids.Remove(device.Id);
                }
            }
            if (ids.Count > 0)
            {
                foreach (var id in ids)
                {
                    configuration.Devices.Delete(id);
                }
            }
        }
    }
}