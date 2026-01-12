using System;
using System.Collections.Generic;
using System.Linq;
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
                options.Command = "list";
            }

            options.Command = options.Command.ToLowerInvariant();

            switch (options.Command)
            {
                case "list":
                    ListCollectionLinks();
                    break;

                case "set":
                    await SetCollectionLinksAsync(options);
                    break;

                case "unset":
                    await UnsetCollectionLinksAsync(options);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, set, unset");
                    break;
            }
        }

        private void ListCollectionLinks()
        {
            var allLinks = Plugin.CollectionLinks.GetAllLinks().ToList();
            if (allLinks.Count == 0)
            {
                Console.WriteLine("No collection links found.");
            }
            else
            {
                var tab = new Tabulate(3);
                tab.AddHeader("Collection UID", "Link UID", "Link Type");
                
                foreach (var link in allLinks.OrderBy(l => l.CollectionUid).ThenBy(l => l.LinkUid))
                {
                    var linkTypeName = GetLinkTypeName((PEDMProto.CollectionLinkType)link.LinkType);
                    tab.AddRow(link.CollectionUid, link.LinkUid, linkTypeName);
                }
                
                Console.WriteLine();
                tab.Dump();
            }
        }

        private static string GetLinkTypeName(PEDMProto.CollectionLinkType linkType)
        {
            return linkType switch
            {
                PEDMProto.CollectionLinkType.CltOther => "Other",
                PEDMProto.CollectionLinkType.CltAgent => "Agent",
                PEDMProto.CollectionLinkType.CltPolicy => "Policy",
                PEDMProto.CollectionLinkType.CltCollection => "Collection",
                PEDMProto.CollectionLinkType.CltDeployment => "Deployment",
                _ => $"Type {(int)linkType}"
            };
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
        [Value(0, Required = false, HelpText = "Command: list, set, unset")]
        public string Command { get; set; }

        [Option("collection", Required = false, HelpText = "Collection UID")]
        public string CollectionUid { get; set; }

        [Option("link", Required = false, HelpText = "Link UID")]
        public string LinkUid { get; set; }

        [Option("type", Required = false, Default = 0, HelpText = "Link type")]
        public int? LinkType { get; set; }
    }
}

