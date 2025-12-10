using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PEDM;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;

namespace Commander.PEDM
{
    internal class PedmCollectionLinkCommand : PedmCommandBase
    {
        public PedmCollectionLinkCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmCollectionLinkOptions options)
        {
            if (!await EnsurePluginAsync())
                return;

            if (string.IsNullOrEmpty(options.Command))
            {
                options.Command = "get";
            }

            options.Command = options.Command.ToLowerInvariant();

            switch (options.Command)
            {
                case "get":
                    await GetCollectionLinksAsync(options);
                    break;

                case "set":
                    await SetCollectionLinksAsync(options);
                    break;

                case "unset":
                    await UnsetCollectionLinksAsync(options);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: get, set, unset");
                    break;
            }
        }

        private async Task GetCollectionLinksAsync(PedmCollectionLinkOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid) && string.IsNullOrEmpty(options.LinkUid))
            {
                Console.WriteLine("Either 'collection' or 'link' UID is required for 'get' command.");
                return;
            }

            var links = new List<CollectionLink>();
            
            if (!string.IsNullOrEmpty(options.CollectionUid) && !string.IsNullOrEmpty(options.LinkUid))
            {
                links.Add(new CollectionLink
                {
                    CollectionUid = options.CollectionUid,
                    LinkUid = options.LinkUid,
                    LinkType = (PEDMProto.CollectionLinkType)(options.LinkType ?? 0)
                });
            }
            else if (!string.IsNullOrEmpty(options.CollectionUid))
            {
                var collectionLinks = Plugin.GetCollectionLinks(new[] { new CollectionLink { CollectionUid = options.CollectionUid } });
                var results = await collectionLinks;
                foreach (var result in results)
                {
                    Console.WriteLine($"Collection: {result.CollectionLink.CollectionUid}");
                    Console.WriteLine($"  Link UID: {result.CollectionLink.LinkUid}");
                    Console.WriteLine($"  Link Type: {result.CollectionLink.LinkType}");
                    if (result.LinkData != null && result.LinkData.Length > 0)
                    {
                        Console.WriteLine($"  Link Data: {System.Text.Encoding.UTF8.GetString(result.LinkData)}");
                    }
                }
                return;
            }

            var collectionLinkResults = await Plugin.GetCollectionLinks(links);
            foreach (var result in collectionLinkResults)
            {
                Console.WriteLine($"Collection: {result.CollectionLink.CollectionUid}");
                Console.WriteLine($"  Link UID: {result.CollectionLink.LinkUid}");
                Console.WriteLine($"  Link Type: {result.CollectionLink.LinkType}");
                if (result.LinkData != null && result.LinkData.Length > 0)
                {
                    Console.WriteLine($"  Link Data: {System.Text.Encoding.UTF8.GetString(result.LinkData)}");
                }
            }
        }

        private async Task SetCollectionLinksAsync(PedmCollectionLinkOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid) || string.IsNullOrEmpty(options.LinkUid))
            {
                Console.WriteLine("Both 'collection' and 'link' UIDs are required for 'set' command.");
                return;
            }

            var setLink = new CollectionLink
            {
                CollectionUid = options.CollectionUid,
                LinkUid = options.LinkUid,
                LinkType = (PEDMProto.CollectionLinkType)(options.LinkType ?? 0)
            };

            var setStatus = await Plugin.SetCollectionLinks(
                setLinks: new[] { setLink },
                unsetLinks: null);

            Console.WriteLine($"Collection link set.");
            if (setStatus.Add?.Count > 0 || setStatus.Update?.Count > 0 || setStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(setStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task UnsetCollectionLinksAsync(PedmCollectionLinkOptions options)
        {
            if (string.IsNullOrEmpty(options.CollectionUid) || string.IsNullOrEmpty(options.LinkUid))
            {
                Console.WriteLine("Both 'collection' and 'link' UIDs are required for 'unset' command.");
                return;
            }

            var unsetLink = new CollectionLink
            {
                CollectionUid = options.CollectionUid,
                LinkUid = options.LinkUid,
                LinkType = (PEDMProto.CollectionLinkType)(options.LinkType ?? 0)
            };

            var unsetStatus = await Plugin.SetCollectionLinks(
                setLinks: null,
                unsetLinks: new[] { unsetLink });

            Console.WriteLine($"Collection link unset.");
            if (unsetStatus.Add?.Count > 0 || unsetStatus.Update?.Count > 0 || unsetStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(unsetStatus);
            }

            await Plugin.SyncDown();
        }
    }

    internal class PedmCollectionLinkOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: get, set, unset")]
        public string Command { get; set; }

        [Option("collection", Required = false, HelpText = "Collection UID")]
        public string CollectionUid { get; set; }

        [Option("link", Required = false, HelpText = "Link UID")]
        public string LinkUid { get; set; }

        [Option("type", Required = false, Default = 0, HelpText = "Link type")]
        public int? LinkType { get; set; }
    }
}

