using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Reflection;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    internal class StorageUtils
    {
        private static Assembly LoadAssembly(string assemblyName)
        {
            try
            {
                // load from file
                return Assembly.LoadFrom(assemblyName);
            }
            catch (FileNotFoundException)
            {
                // load from GAC
                return Assembly.Load(assemblyName);
            }
        }

        public static IExternalLoader SetupCommanderStorage()
        {
            var configValue = ConfigurationManager.AppSettings["useOfflineStorage"];
            if (!bool.TryParse(configValue, out var useOfflineStorage) || !useOfflineStorage)
            {
                return new InMemoryCommanderStorage();
            }

            configValue = ConfigurationManager.AppSettings["storageAssembly"];
            if (string.IsNullOrEmpty(configValue))
            {
                throw new Exception("Offline storage: \"storageAssembly\" is not set.");
            }

            var storageAssembly = LoadAssembly(configValue);
            var connectionString = ConfigurationManager.AppSettings["connectionString"];
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = null;
            }

            Type driverClass = null;
            configValue = ConfigurationManager.AppSettings["driverAssembly"];
            if (!string.IsNullOrEmpty(configValue))
            {
                var driverAssembly = LoadAssembly(configValue);
                configValue = ConfigurationManager.AppSettings["driverClass"];
                if (!string.IsNullOrEmpty(configValue))
                {
                    driverClass = driverAssembly.GetType(configValue);
                    if (driverClass == null)
                    {
                        throw new Exception($"\"{driverAssembly.FullName}\" does not contain class with full name \"{configValue}\"");
                    }
                }
            }

            var loaderType = storageAssembly
                .GetExportedTypes()
                .Where(x => x.IsClass)
                .FirstOrDefault(x => x.Name == "DatabaseLoader");
            if (loaderType == null)
            {
                throw new Exception($"\"{storageAssembly.FullName}\" does not contain class with name \"DatabaseLoader\"");
            }

            if (driverClass == null)
            {
                return (IExternalLoader) Activator.CreateInstance(loaderType, connectionString);
            }

            return (IExternalLoader) Activator.CreateInstance(loaderType, driverClass, connectionString);
        }
    }

    internal class InMemoryCommanderStorage : IExternalLoader
    {
        /// <summary>
        /// JSON configuration storage. "config.json"
        /// </summary>
        /// <returns></returns>
        public IConfigurationStorage GetConfigurationStorage(string name, IConfigurationProtectionFactory protection)
        {
            var loader = string.IsNullOrEmpty(name)
                ? new JsonConfigurationFileLoader()
                : new JsonConfigurationFileLoader(name);
            var cache = new JsonConfigurationCache(loader)
            {
                ReadTimeout = 2000,
                WriteTimeout = 2000,
                ConfigurationProtection = protection,
            };
            return new JsonConfigurationStorage(cache);
        }

        /// <summary>
        /// In memory vault storage
        /// </summary>
        /// <returns></returns>
        public IKeeperStorage GetKeeperStorage(string username)
        {
            return new InMemoryKeeperStorage();
        }

        public bool VerifyDatabase()
        {
            return true;
        }
    }
}
