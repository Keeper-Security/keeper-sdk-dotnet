using CommandLine;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Text;
using Cli;

namespace Commander
{
    internal partial class VaultContext
    {
        private TeamInfo[] _teamCache;

        public async Task<TeamInfo[]> GetAvailableTeams()
        {
            if (_teamCache == null)
            {
                _teamCache = (await Vault.GetTeamsForShare()).ToArray();
            }

            return _teamCache;
        }
    }

    internal static class FolderCommandExtensions
    {
        public static async Task MakeFolderCommand(this VaultContext context, MakeFolderOptions options)
        {
            var sfOptions = options.Shared
                ? new SharedFolderOptions
                {
                    ManageRecords = options.ManageRecords,
                    ManageUsers = options.ManageUsers,
                    CanEdit = options.CanEdit,
                    CanShare = options.CanShare,
                }
                : null;
            _ = await context.Vault.CreateFolder(options.FolderName, context.CurrentFolder, sfOptions);
        }

        public static async Task RemoveFolderCommand(this VaultContext context, FolderOptions options)
        {
            if (context.TryResolvePath(options.FolderName, out var folder))
            {
                await context.Vault.DeleteFolder(folder.FolderUid);
            }
            else
            {
                Console.WriteLine($"Invalid folder path: {options.FolderName}");
            }
        }

        public static async Task UpdateFolderCommand(this VaultContext context, UpdateFolderOptions options)
        {
            if (context.TryResolvePath(options.FolderName, out var folder))
            {
                SharedFolderOptions sharedFolderOptions = null;
                if (folder.FolderType == FolderType.SharedFolder)
                {
                    sharedFolderOptions = new SharedFolderOptions
                    {
                        ManageRecords = options.ManageRecords,
                        ManageUsers = options.ManageUsers,
                        CanEdit = options.CanEdit,
                        CanShare = options.CanShare,
                    };
                }

                await context.Vault.UpdateFolder(folder.FolderUid, options.NewName, sharedFolderOptions);
            }
            else
            {
                Console.WriteLine($"Invalid folder path: {options.FolderName}");
            }
        }

        public static async Task MoveCommand(this VaultContext context, MoveOptions options)
        {
            if (!context.Vault.TryGetFolder(options.DestinationName, out var dstFolder))
            {
                if (!context.TryResolvePath(options.DestinationName, out dstFolder))
                {
                    Console.WriteLine($"Invalid destination folder path: {options.DestinationName}");
                    return;
                }
            }

            if (context.Vault.TryGetFolder(options.SourceName, out var srcFolder))
            {
                await context.Vault.MoveFolder(srcFolder.FolderUid, dstFolder.FolderUid, options.Link);
            }
            else if (context.Vault.TryGetKeeperRecord(options.SourceName, out var record))
            {
                var folders = Enumerable.Repeat(context.Vault.RootFolder, 1).Concat(context.Vault.Folders)
                    .Where(x => x.Records.Contains(record.Uid)).ToArray();
                if (folders.Length == 0)
                {
                    Console.WriteLine("not expected");
                    return;
                }

                var folder = folders.Length == 1
                    ? folders[0]
                    : folders.FirstOrDefault(x => x.FolderUid == context.CurrentFolder)
                      ?? folders.FirstOrDefault(x => string.IsNullOrEmpty(x.FolderUid))
                      ?? folders.FirstOrDefault(x => x.FolderType == FolderType.UserFolder)
                      ?? folders[0];

                await context.Vault.MoveRecords(new[] { new RecordPath { FolderUid = folder.FolderUid, RecordUid = record.Uid } },
                    dstFolder.FolderUid, options.Link);
            }
            else
            {
                if (!context.TryResolvePath(options.SourceName, out srcFolder, out string recordTitle))
                {
                    Console.WriteLine($"Invalid source path: {options.SourceName}");
                    return;
                }

                if (string.IsNullOrEmpty(recordTitle))
                {
                    await context.Vault.MoveFolder(srcFolder.FolderUid, dstFolder.FolderUid, options.Link);
                }
                else
                {
                    var sb = new StringBuilder();
                    sb.Append(recordTitle);
                    sb = sb.Replace("*", ".*");
                    sb = sb.Replace("?", @".");
                    sb = sb.Replace("#", @"[0-9]");
                    sb.Insert(0, "^");
                    sb.Append("$");
                    var pattern = sb.ToString();

                    var records = new List<RecordPath>();
                    foreach (var recordUid in srcFolder.Records)
                    {
                        if (!context.Vault.TryGetKeeperRecord(recordUid, out record)) continue;

                        var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                            records.Add(new RecordPath { FolderUid = srcFolder.FolderUid, RecordUid = recordUid });
                        }
                    }

                    if (records.Count == 0)
                    {
                        throw new Exception(
                            $"Folder {srcFolder.Name} does not contain any record matching {recordTitle}");
                    }

                    await context.Vault.MoveRecords(records.ToArray(), dstFolder.FolderUid, options.Link);
                }
            }
        }
        public static Task ListSharedFoldersCommand(this VaultContext context, string arguments)
        {
            var tab = new Tabulate(4)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new[] { "Shared Folder UID", "Name", "# Records", "# Users" });
            foreach (var sf in context.Vault.SharedFolders)
            {
                tab.AddRow(new object[] { sf.Uid, sf.Name, sf.RecordPermissions.Count, sf.UsersPermissions.Count });
            }

            tab.Sort(1);
            tab.Dump();

            return Task.FromResult(true);
        }

        private const string EmailPattern = @"(?i)^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$";

        public static async Task ShareFolderUserPermissionCommand(this VaultContext context, ShareFolderUserPermissionOptions options)
        {
            if (!context.Vault.TryGetSharedFolder(options.FolderName, out var sf))
            {
                var sfs = context.Vault.SharedFolders
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) ==
                                0)
                    .ToArray();
                if (sfs.Length == 1)
                {
                    sf = sfs[0];
                }
            }

            if (sf == null)
            {
                if (!context.Vault.TryGetFolder(options.FolderName, out var folder))
                {
                    if (!context.TryResolvePath(options.FolderName, out folder))
                    {
                        Console.WriteLine($"Folder \'{options.FolderName}\' not found");
                        return;
                    }
                }

                if (folder.FolderType == FolderType.UserFolder)
                {
                    Console.WriteLine($"Folder \'{folder.Name}\' is not Shared Folder");
                    return;
                }

                sf = context.Vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder
                    ? folder.FolderUid
                    : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.User))
            {
                var teams = await context.GetAvailableTeams();
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.SetColumnRightAlign(2, true);
                tab.SetColumnRightAlign(3, true);
                tab.AddHeader(new[] { "User ID", "User Type", "Manage Records", "Manage Users" });
                foreach (var p in sf.UsersPermissions.OrderBy(x => $"{(int) x.UserType} {x.UserId.ToLowerInvariant()}"))
                {
                    if (p.UserType == UserType.User)
                    {
                        tab.AddRow(new[]
                            {p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-", p.ManageUsers ? "X" : "="});
                    }
                    else
                    {
                        var team = teams.FirstOrDefault(x => x.TeamUid == p.UserId);
                        tab.AddRow(new[]
                        {
                            team?.Name ?? p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-",
                            p.ManageUsers ? "X" : "-"
                        });
                    }
                }

                tab.Dump();
            }
            else
            {
                var userType = UserType.User;
                string userId = null;
                var rx = new Regex(EmailPattern);
                if (rx.IsMatch(options.User))
                {
                    userId = options.User.ToLowerInvariant();
                }
                else
                {
                    userType = UserType.Team;
                    if (context.Vault.TryGetTeam(options.User, out var team))
                    {
                        userId = team.TeamUid;
                    }
                    else
                    {
                        team = context.Vault.Teams.FirstOrDefault(x =>
                            string.Compare(x.Name, options.User, StringComparison.CurrentCultureIgnoreCase) == 0);
                        if (team != null)
                        {
                            userId = team.TeamUid;
                        }
                        else
                        {
                            var teams = await context.GetAvailableTeams();
                            var teamInfo = teams.FirstOrDefault(x =>
                                string.Compare(x.Name, options.User, StringComparison.CurrentCultureIgnoreCase) == 0 ||
                                string.CompareOrdinal(x.TeamUid, options.User) == 0
                            );
                            if (teamInfo != null)
                            {
                                userId = teamInfo.TeamUid;
                            }
                        }
                    }

                    if (userId == null)
                    {
                        Console.WriteLine($"User {options.User} cannot be resolved as email or team");
                        return;
                    }
                }

                var userPermission =
                    sf.UsersPermissions.FirstOrDefault(x => x.UserType == userType && x.UserId == userId);

                if (options.Delete)
                {
                    if (userPermission != null)
                    {
                        await context.Vault.RemoveUserFromSharedFolder(sf.Uid, userId, userType);
                    }
                    else
                    {
                        Console.WriteLine(
                            $"{(userType == UserType.User ? "User" : "Team")} \'{userId}\' is not a part of Shared Folder \'{sf.Name}\'");
                    }
                }
                else
                {
                    try
                    {
                        await context.Vault.PutUserToSharedFolder(sf.Uid, userId, userType, new SharedFolderUserOptions
                        {
                            ManageUsers = options.ManageUsers ?? sf.DefaultManageUsers,
                            ManageRecords = options.ManageRecords ?? sf.DefaultManageRecords,
                        });
                    }
                    catch (NoActiveShareWithUserException e)
                    {
                        Console.WriteLine(e.Message);
                        Console.Write(
                            $"Do you want to send share invitation request to \"{e.Username}\"? (Yes/No) : ");
                        var answer = await Program.GetInputManager().ReadLine();
                        if (string.Equals("y", answer, StringComparison.InvariantCultureIgnoreCase))
                        {
                            answer = "yes";
                        }
                        if (string.Equals(answer, "yes", StringComparison.InvariantCultureIgnoreCase))
                        {
                            await context.Vault.SendShareInvitationRequest(e.Username);
                            Console.WriteLine($"Invitation has been sent to {e.Username}\nPlease repeat this command when your invitation is accepted.");
                        }
                    }
                }
            }
        }

        public static async Task ShareFolderRecordPermissionCommand(this VaultContext context, ShareFolderRecordPermissionOptions options)
        {
            if (!context.Vault.TryGetSharedFolder(options.FolderName, out var sf))
            {
                var sfs = context.Vault.SharedFolders
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) ==
                                0)
                    .ToArray();
                if (sfs.Length == 1)
                {
                    sf = sfs[0];
                }
            }

            if (sf == null)
            {
                if (!context.Vault.TryGetFolder(options.FolderName, out var folder))
                {
                    if (!context.TryResolvePath(options.FolderName, out folder))
                    {
                        Console.WriteLine($"Folder \'{options.FolderName}\'");
                        return;
                    }
                }

                if (folder.FolderType == FolderType.UserFolder)
                {
                    Console.WriteLine($"Folder \'{folder.Name}\' is not Shared Folder");
                    return;
                }

                sf = context.Vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder
                    ? folder.FolderUid
                    : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.Record))
            {
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] { "Record Title", "Record UID", "Can Edit", "Can Share" });
                foreach (var p in sf.RecordPermissions)
                {
                    if (context.Vault.TryGetKeeperRecord(p.RecordUid, out var record))
                    {
                        tab.AddRow(record.Title, p.RecordUid, p.CanEdit ? "X" : "-", p.CanShare ? "X" : "-");
                    }
                }

                tab.Sort(0);
                tab.Dump();
            }
            else
            {
                string recordUid = null;
                if (context.Vault.TryGetKeeperRecord(options.Record, out var record))
                {
                    recordUid = record.Uid;
                }
                else
                {
                    if (context.TryResolvePath(options.Record, out var folder, out var title))
                    {
                        recordUid = folder.Records.Select(x => context.Vault.GetRecord(x)).FirstOrDefault(x =>
                            string.Compare(x.Title, title, StringComparison.CurrentCultureIgnoreCase) == 0)?.Uid;

                    }
                }

                if (string.IsNullOrEmpty(recordUid))
                {
                    Console.WriteLine($"\'{options.Record}\' cannot be resolved as record");
                    return;
                }

                var recordPermission = sf.RecordPermissions.FirstOrDefault(x => x.RecordUid == recordUid);
                if (recordPermission == null)
                {
                    Console.WriteLine($"Record \'{options.Record}\' is not a part of Shared Folder {sf.Name}");
                    return;
                }

                if (options.CanShare.HasValue || options.CanEdit.HasValue)
                {
                    await context.Vault.ChangeRecordInSharedFolder(sf.Uid, recordUid, new SharedFolderRecordOptions
                    {
                        CanEdit = options.CanEdit ?? recordPermission.CanEdit,
                        CanShare = options.CanShare ?? recordPermission.CanShare,
                    });
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Record UID", record.Uid);
                    Console.WriteLine("{0, 20}: {1}", "Record Title", record.Title);
                    Console.WriteLine("{0, 20}: {1}", "Can Edit", recordPermission.CanEdit ? "Yes" : "No");
                    Console.WriteLine("{0, 20}: {1}", "Can Share", recordPermission.CanShare ? "Yes" : "No");
                    Console.WriteLine();
                }
            }
        }

    }

    class FolderOptions
    {
        [Value(0, Required = true, MetaName = "folder name", HelpText = "folder name")]
        public string FolderName { get; set; }
    }

    class UpdateFolderOptions : FolderOptions
    {
        [Option("manage-users", Required = false, Default = null, HelpText = "default manage users")]
        public bool? ManageUsers { get; set; }

        [Option("manage-records", Required = false, Default = null, HelpText = "default manage records")]
        public bool? ManageRecords { get; set; }

        [Option("can-share", Required = false, Default = null, HelpText = "default can share")]
        public bool? CanShare { get; set; }

        [Option("can-edit", Required = false, Default = null, HelpText = "default can edit")]
        public bool? CanEdit { get; set; }

        [Option("name", Required = false, Default = null, HelpText = "new folder folder")]
        public string NewName { get; set; }
    }

    class MakeFolderOptions : FolderOptions
    {
        [Option('s', "shared", Required = false, Default = false, HelpText = "shared folder")]
        public bool Shared { get; set; }

        [Option("manage-users", Required = false, Default = null, HelpText = "default manage users")]
        public bool? ManageUsers { get; set; }

        [Option("manage-records", Required = false, Default = null, HelpText = "default manage records")]
        public bool? ManageRecords { get; set; }

        [Option("can-share", Required = false, Default = null, HelpText = "default can share")]
        public bool? CanShare { get; set; }

        [Option("can-edit", Required = false, Default = null, HelpText = "default can edit")]
        public bool? CanEdit { get; set; }
    }
    class MoveOptions
    {
        [Option("link", Required = false, HelpText = "do not delete source")]
        public bool Link { get; set; }

        [Value(0, Required = true, MetaName = "source record or folder", HelpText = "source record or folder")]
        public string SourceName { get; set; }

        [Value(1, Required = true, MetaName = "destination folder", HelpText = "destination folder")]
        public string DestinationName { get; set; }
    }

    class ShareFolderRecordPermissionOptions : FolderOptions
    {
        [Option('r', "record", Required = false, Default = null, HelpText = "record name or record uid")]
        public string Record { get; set; }

        [Option('s', "can-share", Required = false, Default = null, HelpText = "record permission: can be shared.")]
        public bool? CanShare { get; set; }

        [Option('e', "can-edit", Required = false, Default = null, HelpText = "record permission: can be edited.")]
        public bool? CanEdit { get; set; }
    }

    class ShareFolderUserPermissionOptions : FolderOptions
    {

        [Option("user", Required = false, Default = null, HelpText = "account email, team name, or team uid")]
        public string User { get; set; }

        [Option("delete", Required = false, Default = false, SetName = "delete", HelpText = "delete user from shared folder")]
        public bool Delete { get; set; }

        [Option('r', "manage-records", Required = false, Default = null, SetName = "set", HelpText = "account permission: can manage records.")]
        public bool? ManageRecords { get; set; }

        [Option('u', "manage-users", Required = false, Default = null, SetName = "set", HelpText = "account permission: can manage users.")]
        public bool? ManageUsers { get; set; }
    }

}
