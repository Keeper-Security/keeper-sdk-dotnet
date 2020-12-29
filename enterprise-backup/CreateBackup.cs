using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.OfflineStorage.Sqlite;
using KeeperSecurity.Utils;

namespace EnterpriseBackup
{
    internal partial class MainMenuCliContext
    {
        public async Task CreateBackup(CreateBackupOptions options)
        {
            if (string.IsNullOrEmpty(options.Name))
            {
                options.Name = "keeper.backup";
            }

            var backupFileName = options.Name;
            if (!backupFileName.Contains('.'))
            {
                backupFileName += ".backup";
            }

            backupFileName = Path.Combine(BackupLocation, backupFileName);
            if (File.Exists(backupFileName))
            {
                Console.Write($"\nBackup file \"{options.Name}\" exists. Delete? (Yes/No): ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0)
                {
                    Console.WriteLine("Cancelled");
                    return;
                }
            }

            using var auth = new Auth(new ConsoleAuthUi(Program.GetInputManager()), Storage)
            {
                Endpoint = {DeviceName = "Enterprise Backup", ClientVersion = "c15.0.0"}
            };
            if (!string.IsNullOrEmpty(KeeperServer))
            {
                auth.Endpoint.Server = KeeperServer;
            }

            if (string.IsNullOrEmpty(options.AdminAccount))
            {
                Console.Write($"\nBackup Administrator Username: ");
                options.AdminAccount = await Program.GetInputManager().ReadLine();
            }

            if (string.IsNullOrEmpty(options.AdminAccount)) return;

            Console.WriteLine("Connecting to Keeper...");
            await auth.Login(options.AdminAccount);
            if (!auth.IsAuthenticated()) return;
            if (!auth.AuthContext.IsEnterpriseAdmin)
            {
                Console.WriteLine($"Account \"${auth.Username}\" is not enterprise administrator.");
                return;
            }

            Console.WriteLine("Backing up...");

            if (File.Exists(backupFileName))
            {
                File.Delete(backupFileName);
            }

            await using var connection = new SQLiteConnection($"Data Source={backupFileName};");
            connection.Open();
            var isValid = DatabaseUtils.VerifyDatabase(true,
                connection,
                new[] {typeof(BackupRecord), typeof(BackupUser), typeof(BackupAdminKey), typeof(BackupInfo)},
                null);
            if (!isValid)
            {
                Console.WriteLine("Cannot create backup database.");
                return;
            }

            var recordStorage = new BackupDataWriter<BackupRecord>(() => connection);
            var userStorage = new BackupDataWriter<BackupUser>(() => connection);
            var backupKeyStorage = new BackupDataWriter<BackupAdminKey>(() => connection);
            var infoStorage = new BackupDataWriter<BackupInfo>(() => connection);
            var admins = new List<BackupAdminKey>();
            byte[] enterprisePrivateKey = null;
            var rq = new BackupRequest();
            var usernameLookup = new Dictionary<int, string>();
            var totalRecords = 0;
            var totalUsers = 0;
            var cursorTop = Console.CursorTop;
            while (true)
            {
                var rs = await auth.ExecuteAuthRest<BackupRequest, BackupResponse>("enterprise/get_backup", rq);

                if (rs.EnterpriseEccPrivateKey.Length > 0)
                {
                    enterprisePrivateKey = rs.EnterpriseEccPrivateKey.ToByteArray();
                    if (admins.Count > 0)
                    {
                        foreach (var admin in admins)
                        {
                            admin.EnterpriseEccPrivateKey = enterprisePrivateKey.Base64UrlEncode();
                        }

                        backupKeyStorage.Put(admins);
                    }
                }

                var users = rs.Users.ToArray();
                totalUsers += users.Length;
                if (users.Any())
                {
                    userStorage.Put(users.Select(x => new BackupUser
                    {
                        UserId = x.UserId,
                        Username = x.UserName,
                        DataKey = x.DataKey.Length > 0 ? x.DataKey.ToByteArray().Base64UrlEncode() : null,
                        DataKeyType = (int) x.DataKeyType,
                        PrivateKey = x.PrivateKey.Length > 0 ? x.PrivateKey.ToByteArray().Base64UrlEncode() : null,
                    }));
                    foreach (var user in users)
                    {
                        usernameLookup[user.UserId] = user.UserName;
                    }

                    var backupKeys = users
                        .Where(x => x.BackupKey.Length > 0)
                        .Select(x => new BackupAdminKey
                        {
                            UserId = x.UserId,
                            TreeKey = x.TreeKey.Length > 0 ? x.TreeKey.ToByteArray().Base64UrlEncode() : null,
                            TreeKeyType = (int) x.TreeKeyType,
                            BackupKey = x.BackupKey.ToByteArray().Base64UrlEncode(),
                            EnterpriseEccPrivateKey = enterprisePrivateKey?.Base64UrlEncode(),
                        })
                        .ToArray();
                    if (backupKeys.Length > 0)
                    {
                        admins.AddRange(backupKeys);
                        backupKeyStorage.Put(backupKeys);
                    }
                }

                var records = rs.Records.Select(x => new BackupRecord
                {
                    RecordUid = x.RecordUid.ToByteArray().Base64UrlEncode(),
                    UserId = x.UserId,
                    KeyType = (int) x.KeyType,
                    RecordKey = x.Key.ToByteArray().Base64UrlEncode(),
                    Version = x.Version,
                    Data = x.Data.Length > 0 ? x.Data.ToByteArray().Base64UrlEncode() : null,
                    Extra = x.Extra.Length > 0 ? x.Extra.ToByteArray().Base64UrlEncode() : null,
                }).ToArray();
                totalRecords += records.Length;

                recordStorage.Put(records);

                if (rs.ContinuationToken.Length == 0) break;
                rq.ContinuationToken = rs.ContinuationToken;
                Console.CursorLeft = 0;
                Console.CursorTop = cursorTop;
                Console.Write($"{totalUsers} User(s) {totalRecords} Record(s)");
            }

            Console.CursorLeft = 0;
            Console.CursorTop = cursorTop;
            Console.WriteLine($"Imported {totalUsers} User(s) {totalRecords} Record(s)");

            infoStorage.Put(new[]
            {
                new BackupInfo
                {
                    Name = "BackupDate",
                    Value = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                },
                new BackupInfo
                {
                    Name = "BackupAuthor",
                    Value = auth.Username,
                },
                new BackupInfo
                {
                    Name = "BackupAdmins",
                    Value = string.Join('\n',
                        admins.Select(x =>
                                usernameLookup.TryGetValue(x.UserId, out var username) ? username : null)
                            .Where(x => !string.IsNullOrEmpty(x)))
                },
            });
            Debug.WriteLine($"Created Enterprise Backup: {backupFileName}");
        }
    }
}
