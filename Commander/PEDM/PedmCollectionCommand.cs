using System;
using System.Collections.Generic;
using System.IO;
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
                    ListCollections(options.CollectionType);
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

        private void ListCollections(int? filterType = null)
        {
            var collections = Plugin.Collections.GetAll().ToList();
            
            if (filterType.HasValue)
            {
                collections = collections.Where(c => c.CollectionType == filterType.Value).ToList();
            }
            
            if (collections.Count == 0)
            {
                if (filterType.HasValue)
                {
                    var typeName = GetCollectionTypeName(filterType.Value);
                    Console.WriteLine($"No collections found for type: {typeName} (Type {filterType.Value})");
                }
                else
                {
                    Console.WriteLine("No collections found.");
                }
            }
            else
            {
                var tab = new Tabulate(3);
                tab.AddHeader("Collection UID", "Collection Type", "Name");
                
                foreach (var coll in collections.OrderBy(c => c.CollectionType).ThenBy(c => c.CollectionUid))
                {
                    var typeName = GetCollectionTypeName(coll.CollectionType);
                    string name = "";
                    if (coll.CollectionData != null && coll.CollectionData.Length > 0)
                    {
                        try
                        {
                            var data = JsonUtils.ParseJson<Dictionary<string, object>>(coll.CollectionData);
                            if (data.TryGetValue("Name", out var nameObj))
                            {
                                name = nameObj?.ToString() ?? "";
                            }
                        }
                        catch
                        {
                            Console.WriteLine($"Error parsing collection data: {coll.CollectionData}");
                        }
                    }
                    tab.AddRow(coll.CollectionUid, typeName, name);
                }
                tab.Dump();
            }
        }

        private void ViewCollection(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                Console.WriteLine("Collection UID or name is required for 'view' command.");
                return;
            }

            var collection = ResolveCollection(identifier);
            if (collection == null)
            {
                Console.WriteLine($"Collection '{identifier}' not found.");
                return;
            }

            Console.WriteLine($"Collection: {collection.CollectionUid}");
            Console.WriteLine($"  Type: {GetCollectionTypeName(collection.CollectionType)}");
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(collection.Created):yyyy-MM-dd HH:mm:ss}");
            
            if (collection.CollectionData != null && collection.CollectionData.Length > 0)
            {
                try
                {
                    var data = JsonUtils.ParseJson<Dictionary<string, object>>(collection.CollectionData);
                    
                    if (data.TryGetValue("Name", out var nameObj))
                    {
                        Console.WriteLine($"  Name: {nameObj}");
                    }
                    
                    foreach (var kvp in data)
                    {
                        if (kvp.Key == "Name") continue; // Already displayed
                        if (kvp.Value is Dictionary<string, object> dict)
                        {
                            Console.WriteLine($"  {kvp.Key}:");
                            foreach (var inner in dict)
                            {
                                Console.WriteLine($"    {inner.Key}: {inner.Value}");
                            }
                        }
                        else if (kvp.Value is List<object> list)
                        {
                            Console.WriteLine($"  {kvp.Key}: [{string.Join(", ", list)}]");
                        }
                        else
                        {
                            Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
                        }
                    }
                }
                catch
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
        }
        
        private PedmCollection ResolveCollection(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return null;
            }

            var collection = Plugin.Collections.GetEntity(identifier);
            if (collection != null)
            {
                return collection;
            }

            var matches = Plugin.Collections.GetAll()
                .Where(c =>
                {
                    if (c.CollectionData == null || c.CollectionData.Length == 0)
                        return false;
                    try
                    {
                        var data = JsonUtils.ParseJson<Dictionary<string, object>>(c.CollectionData);
                        if (data.TryGetValue("Name", out var nameObj))
                        {
                            return string.Equals(nameObj?.ToString(), identifier, StringComparison.OrdinalIgnoreCase);
                        }
                    }
                    catch
                    {
                        // Ignore parsing errors
                    }
                    return false;
                })
                .ToList();

            if (matches.Count == 1)
            {
                return matches[0];
            }

            if (matches.Count > 1)
            {
                Console.WriteLine($"Multiple collections match name \"{identifier}\". Please specify Collection UID.");
            }

            return null;
        }

        private static string ReadJsonText(string json, string filePath)
        {
            if (!string.IsNullOrEmpty(json))
            {
                return json;
            }

            if (!string.IsNullOrEmpty(filePath))
            {
                return File.ReadAllText(filePath);
            }

            return null;
        }

        private async Task AddCollectionAsync(PedmCollectionOptions options)
        {
            var collectionUid = options.CollectionUid;
            if (string.IsNullOrEmpty(collectionUid))
            {
                collectionUid = CryptoUtils.GenerateUid();
                Console.WriteLine($"Generated Collection UID: {collectionUid}");
            }

            if (!options.CollectionType.HasValue || options.CollectionType.Value == 0)
            {
                Console.WriteLine("Collection type is required for 'add' command. Use --type option (e.g., --type 2 for Application).");
                return;
            }

            var dataJson = ReadJsonText(options.CollectionData, options.CollectionDataFile);
            if (string.IsNullOrEmpty(dataJson))
            {
                dataJson = "{}";
            }

            var collectionData = new CollectionData
            {
                CollectionUid = collectionUid,
                CollectionType = options.CollectionType.Value,
                CollectionDataJson = dataJson
            };

            var addStatus = await Plugin.ModifyCollections(
                addCollections: new[] { collectionData },
                updateCollections: null,
                removeCollections: null);

            if (addStatus.AddErrors?.Count > 0)
            {
                foreach (var error in addStatus.AddErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to add collection \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            if (addStatus.Add == null || !addStatus.Add.Contains(collectionUid))
            {
                Console.WriteLine($"Warning: Collection '{collectionUid}' may not have been added successfully.");
                Console.WriteLine($"Add status: {(addStatus.Add?.Count > 0 ? string.Join(", ", addStatus.Add) : "none")}");
                if (addStatus.Add?.Count > 0 || addStatus.Update?.Count > 0 || addStatus.Remove?.Count > 0)
                {
                    PrintModifyStatus(addStatus);
                }
                return;
            }

            Console.WriteLine($"Collection '{collectionUid}' added.");
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
                Console.WriteLine("Collection UID or name is required for 'update' command.");
                return;
            }

            await Plugin.SyncDown();

            var collection = ResolveCollection(options.CollectionUid);
            if (collection == null)
            {
                Console.WriteLine($"Collection \"{options.CollectionUid}\" does not exist locally. Please ensure it exists and try again.");
                return;
            }

            var dataJson = ReadJsonText(options.CollectionData, options.CollectionDataFile);
            if (string.IsNullOrEmpty(dataJson))
            {
                if (collection.CollectionData != null && collection.CollectionData.Length > 0)
                {
                    dataJson = Encoding.UTF8.GetString(collection.CollectionData);
                }
                else
                {
                    dataJson = "{}";
                }
            }

            var collectionType = options.CollectionType.HasValue && options.CollectionType.Value != 0
                ? options.CollectionType.Value
                : collection.CollectionType;

            var collectionData = new CollectionData
            {
                CollectionUid = collection.CollectionUid,
                CollectionType = collectionType,
                CollectionDataJson = dataJson
            };

            var updateStatus = await Plugin.ModifyCollections(
                addCollections: null,
                updateCollections: new[] { collectionData },
                removeCollections: null);

            if (updateStatus.UpdateErrors?.Count > 0)
            {
                foreach (var error in updateStatus.UpdateErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to update collection \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            if (updateStatus.Update == null || !updateStatus.Update.Contains(collection.CollectionUid))
            {
                Console.WriteLine($"Warning: Collection '{collection.CollectionUid}' may not have been updated successfully.");
                Console.WriteLine($"Update status: {(updateStatus.Update?.Count > 0 ? string.Join(", ", updateStatus.Update) : "none")}");
                if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
                {
                    PrintModifyStatus(updateStatus);
                }
                return;
            }

            Console.WriteLine($"Collection '{collection.CollectionUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveCollectionAsync(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                Console.WriteLine("Collection UID or name is required for 'remove' command.");
                return;
            }

            var collection = ResolveCollection(identifier);
            if (collection == null)
            {
                Console.WriteLine($"Collection \"{identifier}\" does not exist");
                return;
            }

            var removeStatus = await Plugin.ModifyCollections(
                addCollections: null,
                updateCollections: null,
                removeCollections: new[] { collection.CollectionUid });

            if (removeStatus.RemoveErrors?.Count > 0)
            {
                foreach (var error in removeStatus.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to remove collection \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            Console.WriteLine($"Collection '{collection.CollectionUid}' removed.");
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

        [Value(1, Required = false, HelpText = "Collection UID (optional for add - will be auto-generated if omitted, required for view/update/remove)")]
        public string CollectionUid { get; set; }

        [Option("type", Required = false, HelpText = "Collection type (for add, update, or filter list). Types: 1=OS Build, 2=Application, 3=User Account, 4=Group Account, 202=OS Version")]
        public int? CollectionType { get; set; }

        [Option("data", Required = false, HelpText = "Collection data (JSON string, for add, update)")]
        public string CollectionData { get; set; }

        [Option("data-file", Required = false, HelpText = "Path to file containing collection data JSON")]
        public string CollectionDataFile { get; set; }
    }
}

