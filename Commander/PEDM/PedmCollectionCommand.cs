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
using PEDMProto = PEDM;

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

                case "connect":
                    await ConnectCollectionAsync(options);
                    break;

                case "disconnect":
                    await DisconnectCollectionAsync(options);
                    break;

                case "wipe-out":
                    await WipeOutCollectionsAsync(options);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, add, update, remove, connect, disconnect, wipe-out");
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


        private async Task ConnectCollectionAsync(PedmCollectionOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid))
            {
                Console.WriteLine("Collection UID or name is required for 'connect' command.");
                return;
            }

            if (string.IsNullOrEmpty(options.LinkType))
            {
                Console.WriteLine("--link-type is required for 'connect' command. Options: agent, policy, collection");
                return;
            }

            if (options.LinkUids == null || options.LinkUids.Count == 0)
            {
                Console.WriteLine("Link UID(s) or name(s) are required for 'connect' command.");
                return;
            }

            var collection = ResolveCollection(options.CollectionUid);
            if (collection == null)
            {
                Console.WriteLine($"Collection '{options.CollectionUid}' not found.");
                return;
            }

            var linkType = ParseLinkType(options.LinkType);
            if (linkType == null)
            {
                Console.WriteLine($"Invalid link type: {options.LinkType}. Options: agent, policy, collection");
                return;
            }

            var links = new List<string>();
            
            if (linkType == PEDMProto.CollectionLinkType.CltCollection)
            {
                var collLinks = ResolveCollections(options.LinkUids);
                links.AddRange(collLinks.Select(c => c.CollectionUid));
            }
            else if (linkType == PEDMProto.CollectionLinkType.CltAgent)
            {
                foreach (var agentUid in options.LinkUids)
                {
                    var agent = Plugin.Agents.GetEntity(agentUid);
                    if (agent == null)
                    {
                        Console.WriteLine($"Agent '{agentUid}' not found.");
                        continue;
                    }
                    links.Add(agent.AgentUid);
                }
            }
            else if (linkType == PEDMProto.CollectionLinkType.CltPolicy)
            {
                foreach (var policyUid in options.LinkUids)
                {
                    var policy = ResolvePolicy(policyUid);
                    if (policy == null)
                    {
                        Console.WriteLine($"Policy '{policyUid}' not found.");
                        continue;
                    }
                    links.Add(policy.PolicyUid);
                }
            }

            if (links.Count == 0)
            {
                Console.WriteLine("No valid links found.");
                return;
            }

            var setLinks = links.Select(linkUid => new CollectionLink
            {
                CollectionUid = collection.CollectionUid,
                LinkUid = linkUid,
                LinkType = linkType.Value
            }).ToList();

            var status = await Plugin.SetCollectionLinks(setLinks: setLinks, unsetLinks: null);
            
            if (status.AddErrors?.Count > 0)
            {
                foreach (var error in status.AddErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to set collection link \"{error.EntityUid}\": {error.Message}");
                    }
                }
            }

            if (status.Add?.Count > 0 || status.Update?.Count > 0 || status.Remove?.Count > 0)
            {
                PrintModifyStatus(status);
            }

            await Plugin.SyncDown();
        }

        private async Task DisconnectCollectionAsync(PedmCollectionOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid))
            {
                Console.WriteLine("Collection UID or name is required for 'disconnect' command.");
                return;
            }

            if (options.LinkUids == null || options.LinkUids.Count == 0)
            {
                Console.WriteLine("Link UID(s) are required for 'disconnect' command.");
                return;
            }

            var collection = ResolveCollection(options.CollectionUid);
            if (collection == null)
            {
                Console.WriteLine($"Collection '{options.CollectionUid}' not found.");
                return;
            }

            var existingLinks = Plugin.CollectionLinks.GetLinksForSubject(collection.CollectionUid).ToList();
            var toUnlink = new HashSet<string>(options.LinkUids, StringComparer.OrdinalIgnoreCase);

            var unsetLinks = new List<CollectionLink>();
            foreach (var link in existingLinks)
            {
                if (toUnlink.Contains(link.LinkUid))
                {
                    unsetLinks.Add(new CollectionLink
                    {
                        CollectionUid = collection.CollectionUid,
                        LinkUid = link.LinkUid,
                        LinkType = (PEDMProto.CollectionLinkType)link.LinkType
                    });
                    toUnlink.Remove(link.LinkUid);
                }
            }

            if (toUnlink.Count > 0)
            {
                Console.WriteLine($"{toUnlink.Count} link(s) cannot be removed from collection: {options.CollectionUid}");
            }

            if (unsetLinks.Count == 0)
            {
                return;
            }

            if (!options.Force)
            {
                Console.Write($"Do you want to remove {unsetLinks.Count} link(s)? [y/n]: ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.IsNullOrEmpty(answer) || 
                    !answer.Trim().StartsWith("y", StringComparison.InvariantCultureIgnoreCase))
                {
                    return;
                }
            }

            var status = await Plugin.SetCollectionLinks(setLinks: null, unsetLinks: unsetLinks);
            
            if (status.RemoveErrors?.Count > 0)
            {
                foreach (var error in status.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to unset collection link \"{error.EntityUid}\": {error.Message}");
                    }
                }
            }

            if (status.Add?.Count > 0 || status.Update?.Count > 0 || status.Remove?.Count > 0)
            {
                PrintModifyStatus(status);
            }

            await Plugin.SyncDown();
        }

        private async Task WipeOutCollectionsAsync(PedmCollectionOptions options)
        {
            var collectionType = options.CollectionType;
            if (!collectionType.HasValue)
            {
                Console.WriteLine("Collection type is required for 'wipe-out' command. Use --type option.");
                return;
            }

            var collections = Plugin.Collections.GetAll()
                .Where(c => c.CollectionType == collectionType.Value)
                .Select(c => c.CollectionUid)
                .ToList();

            if (collections.Count == 0)
            {
                Console.WriteLine($"No collections found for type: {GetCollectionTypeName(collectionType.Value)} ({collectionType.Value})");
                return;
            }

            var removeStatus = await Plugin.ModifyCollections(
                addCollections: null,
                updateCollections: null,
                removeCollections: collections);

            if (removeStatus.RemoveErrors?.Count > 0)
            {
                foreach (var error in removeStatus.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to remove collection \"{error.EntityUid}\": {error.Message}");
                    }
                }
            }

            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }

        private List<PedmCollection> ResolveCollections(IList<string> identifiers)
        {
            var collections = new List<PedmCollection>();
            foreach (var identifier in identifiers)
            {
                var collection = ResolveCollection(identifier);
                if (collection != null)
                {
                    collections.Add(collection);
                }
            }
            return collections;
        }


        private PEDMProto.CollectionLinkType? ParseLinkType(string linkType)
        {
            if (string.IsNullOrEmpty(linkType))
                return null;

            var lower = linkType.ToLowerInvariant();
            return lower switch
            {
                "agent" => PEDMProto.CollectionLinkType.CltAgent,
                "policy" => PEDMProto.CollectionLinkType.CltPolicy,
                "collection" => PEDMProto.CollectionLinkType.CltCollection,
                _ => null
            };
        }
    }

    internal class PedmCollectionOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, add, update, remove, connect, disconnect, wipe-out")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Collection UID (optional for add - will be auto-generated if omitted, required for view/update/remove/connect/disconnect)")]
        public string CollectionUid { get; set; }

        [Option("type", Required = false, HelpText = "Collection type (for add, update, filter list, or wipe-out). Types: 1=OS Build, 2=Application, 3=User Account, 4=Group Account, 202=OS Version")]
        public int? CollectionType { get; set; }

        [Option("data", Required = false, HelpText = "Collection data (JSON string, for add, update)")]
        public string CollectionData { get; set; }

        [Option("data-file", Required = false, HelpText = "Path to file containing collection data JSON")]
        public string CollectionDataFile { get; set; }

        [Option("link-type", Required = false, HelpText = "Link type for connect command: agent, policy, collection")]
        public string LinkType { get; set; }

        [Option("link", Required = false, HelpText = "Link UID(s) or name(s) for connect/disconnect commands")]
        public IList<string> LinkUids { get; set; }
    }
}

