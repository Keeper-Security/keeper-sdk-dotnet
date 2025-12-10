using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PEDM;
using KeeperSecurity.Utils;

namespace Commander.PEDM
{
    internal class PedmCollectionCommand : PedmCommandBase
    {
        public PedmCollectionCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmCollectionOptions options)
        {
            if (!await EnsurePluginAsync())
                return;

            if (string.IsNullOrEmpty(options.Command))
            {
                options.Command = "list";
            }

            options.Command = options.Command.ToLowerInvariant();

            switch (options.Command)
            {
                case "list":
                    ListCollections();
                    break;

                case "view":
                    ViewCollection(options.CollectionUid);
                    break;

                case "add":
                    await AddCollectionAsync(options);
                    break;

                case "update":
                    await UpdateCollectionAsync(options);
                    break;

                case "remove":
                case "delete":
                    await RemoveCollectionAsync(options.CollectionUid);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, add, update, remove");
                    break;
            }
        }

        private void ListCollections()
        {
            var collections = Plugin.Collections.GetAll().ToList();
            if (collections.Count == 0)
            {
                Console.WriteLine("No collections found.");
            }
            else
            {
                var tab = new Tabulate(3);
                tab.AddHeader("ID", "Collection Type", "Value Count");
                
                var grouped = collections.GroupBy(c => c.CollectionType).OrderBy(g => g.Key);
                int rowNum = 1;
                foreach (var group in grouped)
                {
                    var typeName = GetCollectionTypeName(group.Key);
                    var count = group.Count();
                    tab.AddRow(rowNum.ToString(), typeName, count.ToString());
                    rowNum++;
                }
                tab.Dump();
            }
        }

        private void ViewCollection(string collectionUid)
        {
            if (string.IsNullOrEmpty(collectionUid))
            {
                Console.WriteLine("Collection UID is required for 'view' command.");
                return;
            }

            var collection = Plugin.Collections.GetEntity(collectionUid);
            if (collection == null)
            {
                Console.WriteLine($"Collection '{collectionUid}' not found.");
                return;
            }

            Console.WriteLine($"Collection: {collectionUid}");
            Console.WriteLine($"  Type: {GetCollectionTypeName(collection.CollectionType)}");
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(collection.Created):yyyy-MM-dd HH:mm:ss}");
            
            if (collection.CollectionData != null && collection.CollectionData.Length > 0)
            {
                try
                {
                    var dataJson = Encoding.UTF8.GetString(collection.CollectionData);
                    Console.WriteLine($"  Data: {dataJson}");
                }
                catch
                {
                    Console.WriteLine($"  Data: (binary data, {collection.CollectionData.Length} bytes)");
                }
            }
        }

        private async Task AddCollectionAsync(PedmCollectionOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid))
            {
                Console.WriteLine("Collection UID is required for 'add' command.");
                return;
            }

            var collectionData = new CollectionData
            {
                CollectionUid = options.CollectionUid,
                CollectionType = options.CollectionType ?? 0,
                CollectionDataJson = options.CollectionData ?? "{}"
            };

            var addStatus = await Plugin.ModifyCollections(
                addCollections: new[] { collectionData },
                updateCollections: null,
                removeCollections: null);

            Console.WriteLine($"Collection '{options.CollectionUid}' added.");
            if (addStatus.Add?.Count > 0 || addStatus.Update?.Count > 0 || addStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(addStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task UpdateCollectionAsync(PedmCollectionOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid))
            {
                Console.WriteLine("Collection UID is required for 'update' command.");
                return;
            }

            var collectionData = new CollectionData
            {
                CollectionUid = options.CollectionUid,
                CollectionType = options.CollectionType ?? 0,
                CollectionDataJson = options.CollectionData ?? "{}"
            };

            var updateStatus = await Plugin.ModifyCollections(
                addCollections: null,
                updateCollections: new[] { collectionData },
                removeCollections: null);

            Console.WriteLine($"Collection '{options.CollectionUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveCollectionAsync(string collectionUid)
        {
            if (string.IsNullOrEmpty(collectionUid))
            {
                Console.WriteLine("Collection UID is required for 'remove' command.");
                return;
            }

            var removeStatus = await Plugin.ModifyCollections(
                addCollections: null,
                updateCollections: null,
                removeCollections: new[] { collectionUid });

            Console.WriteLine($"Collection '{collectionUid}' removed.");
            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }

        private static string GetCollectionTypeName(int collectionType)
        {
            return collectionType switch
            {
                1 => "OS Build",
                2 => "Application",
                3 => "User Account",
                4 => "Group Account",
                202 => "OS Version",
                _ => $"Type {collectionType}"
            };
        }
    }

    internal class PedmCollectionOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, add, update, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Collection UID")]
        public string CollectionUid { get; set; }

        [Option("type", Required = false, Default = 0, HelpText = "Collection type (for add, update)")]
        public int? CollectionType { get; set; }

        [Option("data", Required = false, HelpText = "Collection data (JSON string, for add, update)")]
        public string CollectionData { get; set; }
    }
}

