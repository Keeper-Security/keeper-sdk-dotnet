using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Authentication;
using KeeperSecurity.Configuration;
using KeeperSecurity.OfflineStorage.Sqlite;
using KeeperSecurity.Utils;

namespace EnterpriseBackup
{
    internal partial class MainMenuCliContext : StateCommands
    {
        public MainMenuCliContext()
        {
            var keeperLocation = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), ".keeper");
            if (!Directory.Exists(keeperLocation))
            {
                Directory.CreateDirectory(keeperLocation);
            }
            var configFile = Path.Combine(keeperLocation, "backup.json");
            var cache = new JsonConfigurationCache(new JsonConfigurationFileLoader(configFile));
            Storage = new JsonConfigurationStorage(cache);
            if (string.IsNullOrEmpty(Storage.LastServer))
            {
                KeeperServer = KeeperEndpoint.DefaultKeeperServer;
                Console.WriteLine($"Connecting to the default Keeper sever: {KeeperServer}");
            }
            else
            {
                KeeperServer = Storage.LastServer;
            }
            BackupLocation = Path.Combine(keeperLocation, "Backups");
            if (!Directory.Exists(BackupLocation))
            {
                Directory.CreateDirectory(BackupLocation);
            }

            Commands.Add("server",
                new SimpleCommand
                {
                    Order = 10,
                    Description = "Gets or sets Keeper server.",
                    Action = (arguments) =>
                    {
                        if (!string.IsNullOrEmpty(arguments))
                        {
                            KeeperServer = arguments;
                        }
                        Console.WriteLine($"Keeper server: {KeeperServer}");
                        return Task.CompletedTask;
                    },
                });

            Commands.Add("backup-dir",
                new SimpleCommand
                {
                    Order = 11,
                    Description = "Gets or sets backup file(s) directory.",
                    Action = (arguments) =>
                    {
                        if (!string.IsNullOrEmpty(arguments))
                        {
                            if (!Directory.Exists(arguments))
                            {
                                Directory.CreateDirectory(arguments);
                            }

                            BackupLocation = arguments;
                        }
                        Console.WriteLine($"Backup file location: {BackupLocation}");
                        return Task.CompletedTask;
                    },
                });
            CommandAliases.Add("bd", "backup-dir");

            Commands.Add("backup-list",
                new SimpleCommand
                {
                    Order = 12,
                    Description = "Lists backup files.",
                    Action = ListBackupFiles,
                });
            CommandAliases.Add("bl", "backup-list");

            Commands.Add("backup-new",
                new ParsableCommand<CreateBackupOptions>
                {
                    Order = 20,
                    Description = "Creates a backup file.",
                    Action = CreateBackup,
                });
            CommandAliases.Add("bn", "backup-new");

            Commands.Add("backup-unlock",
                new ParsableCommand<BackupOptions>
                {
                    Order = 21,
                    Description = "Selects and unlocks a backup file.",
                    Action = UnlockBackup,
                });
            CommandAliases.Add("bu", "backup-unlock");
        }

        private async Task ListBackupFiles(string arguments)
        {
            var tab = new Tabulate(4);
            tab.AddHeader("Backup Name", "Created", "Author", "Admins");
            foreach (var file in Directory.EnumerateFiles(BackupLocation))
            {
                try
                {
                    var info = new Dictionary<string, string>();
                    {
                        await using var connection = new SQLiteConnection($"Data Source={file};");
                        connection.Open();
                        var isValid = DatabaseUtils.VerifyDatabase(false,
                            connection,
                            new[] {typeof(BackupRecord), typeof(BackupUser), typeof(BackupAdminKey), typeof(BackupInfo)},
                            null);
                        if (!isValid) continue;
                        var adminStorage = new BackupDataReader<BackupInfo>(() => connection);
                        foreach (var pair in adminStorage.GetAll())
                        {
                            if (!string.IsNullOrEmpty(pair.Name) && !string.IsNullOrEmpty(pair.Value))
                            {
                                info[pair.Name] = pair.Value;
                            }
                        }
                    }
                    var admins = info.ContainsKey("BackupAdmins") ? info["BackupAdmins"].Split('\n') : new string[0];
                    for (var i = 0; i < Math.Max(1, admins.Length); i++)
                    {
                        if (i == 0)
                        {
                            var name = Path.GetFileName(file);
                            if (name.EndsWith(".backup"))
                            {
                                name = name.Substring(0, name.Length - ".backup".Length);
                            }

                            if (!info.TryGetValue("BackupDate", out var unixDate)) unixDate = "";
                            if (!string.IsNullOrEmpty(unixDate))
                            {
                                if (int.TryParse(unixDate, out var unix))
                                {
                                    var date = DateTimeOffset.FromUnixTimeSeconds(unix);
                                    unixDate = date.ToString("s");
                                }
                            }

                            tab.AddRow(name, unixDate, 
                                info.TryGetValue("BackupAuthor", out var author) ? author : "",
                                admins.Length > 0 ? admins[0] : "");
                        }
                        else
                        {
                            tab.AddRow("", "", "", admins[i]);
                        }
                    }

                    tab.DumpRowNo = false;
                    tab.Dump();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

            }
        }

        public JsonConfigurationStorage Storage { get; set; }

        public string KeeperServer { get; set; }
        public string BackupLocation { get; set; }

        public override string GetPrompt()
        {
            return "Main Menu";
        }
    }

    internal class BackupOptions
    {
        [Value(0, Required = true, MetaName = "name", HelpText = "Backup file name.")]
        public string Name { get; set; }
    }

    internal class CreateBackupOptions : BackupOptions
    {
        [Option("admin", Required = false, HelpText = "Backup Administrator account.")]
        public string AdminAccount { get; set; }
    }

}