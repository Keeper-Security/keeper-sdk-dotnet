using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommandLine;
using Enterprise;
using KeeperSecurity.Commands;
using KeeperSecurity.OfflineStorage.Sqlite;
using KeeperSecurity.Utils;

namespace EnterpriseBackup
{
    internal partial class MainMenuCliContext
    {
        public async Task UnlockBackup(BackupOptions options)
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
            if (!File.Exists(backupFileName))
            {
                Console.Write($"\nBackup file \"{options.Name}\" is not found.");
            }

            await using var connection = new SQLiteConnection($"Data Source={backupFileName};");
            connection.Open();
            var isValid = DatabaseUtils.VerifyDatabase(false,
                connection,
                new[] {typeof(BackupRecord), typeof(BackupUser), typeof(BackupAdminKey), typeof(BackupInfo)},
                null);
            if (!isValid)
            {
                Console.WriteLine("Invalid or corrupted backup file.");
                return;
            }

            var adminStorage = new BackupDataReader<BackupAdminKey>(() => connection);
            var admins = adminStorage.GetAll().ToArray();
            var userStorage = new BackupDataReader<BackupUser>(() => connection);
            var users = new Dictionary<int, BackupUser>();
            foreach (var user in userStorage.GetAll())
            {
                users[user.UserId] = user;
            }

            var recordStorage = new BackupDataReader<BackupRecord>(() => connection);
            foreach (var tup in recordStorage.GetCountsByIndex1())
            {
                if (!(tup.Item2 is IConvertible conv)) continue;
                var userId = conv.ToInt32(NumberFormatInfo.CurrentInfo);
                if (users.TryGetValue(userId, out var u))
                {
                    u.RecordCount = tup.Item1;
                }
            }

            byte[] treeKey = null;
            byte[] enterprisePrivateKey = null;
            Console.WriteLine($"Unlocking the backup: {options.Name}");
            foreach (var admin in admins)
            {
                var user = users[admin.UserId];
                while (true)
                {
                    try
                    {
                        Console.WriteLine("\n{0, 20}: {1}", "Username", user.Username);
                        Console.Write("{0, 20}: ", "Password");
                        var password = await Program.GetInputManager().ReadLine(new ReadLineParameters
                        {
                            IsSecured = true,
                        });
                        if (string.IsNullOrEmpty(password)) return;

                        if (user.DataKeyType != (int) BackupUserDataKeyType.Own)
                        {
                            Console.WriteLine($"Admin data key should be protected by password.");
                            return;
                        }

                        user.DecryptedDataKey = CryptoUtils.DecryptEncryptionParams(password, user.DataKey.Base64UrlDecode());
                        user.DecryptedPrivateKey = CryptoUtils.DecryptAesV1(user.PrivateKey.Base64UrlDecode(), user.DecryptedDataKey);
                        var privateKey = CryptoUtils.LoadPrivateKey(user.DecryptedPrivateKey);
                        admin.DecryptedBackupKey = CryptoUtils.DecryptRsa(admin.BackupKey.Base64UrlDecode(), privateKey);
                        if (treeKey == null)
                        {
                            var encryptedTreeKey = admin.TreeKey.Base64UrlDecode();
                            switch (admin.TreeKeyType)
                            {
                                case (int) BackupKeyType.EncryptedByDataKey:
                                    treeKey = CryptoUtils.DecryptAesV1(encryptedTreeKey, user.DecryptedDataKey);
                                    break;
                                case (int) BackupKeyType.EncryptedByPublicKey:
                                    treeKey = CryptoUtils.DecryptRsa(encryptedTreeKey, privateKey);
                                    break;
                            }
                        }

                        if (treeKey != null && enterprisePrivateKey == null)
                        {
                            var encryptedPrivateKey = admin.EnterpriseEccPrivateKey.Base64UrlDecode();
                            enterprisePrivateKey = CryptoUtils.DecryptAesV2(encryptedPrivateKey, treeKey);
                        }

                        break;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
            }

            var backupKey = admins[0].DecryptedBackupKey
                .Zip(admins[1].DecryptedBackupKey, (x, y) => (byte)(x ^ y))
                .ToArray();

            var keys = new KeysToUnlock
            {
                BackupKey = backupKey,
                TreeKey = treeKey,
                EnterprisePrivateKey = enterprisePrivateKey,
            };
            var unlockCommands = new UnlockedBackupCommands(backupFileName, keys, users)
            {
                ParentCommands = this
            };
            NextStateCommands = unlockCommands;
        }
    }

    internal class KeysToUnlock
    {
        public byte[] BackupKey { get; set; }
        public byte[] TreeKey { get; set; }
        public byte[] EnterprisePrivateKey { get; set; }
    }

    internal class UnlockedBackupCommands : StateCommands
    {
        public StateCommands ParentCommands;
        private string BackupFileName { get; }
        private KeysToUnlock Keys { get; }
        private Dictionary<int, BackupUser> Users { get; }

        private string ExportFilePath { get; }

        public UnlockedBackupCommands(string backupFileName, KeysToUnlock keys, Dictionary<int, BackupUser> users)
        {
            BackupFileName = backupFileName;
            Keys = keys;
            Users = users;
            _fileName = Path.GetFileNameWithoutExtension(BackupFileName);
            ExportFilePath = Path.GetDirectoryName(backupFileName) ?? "";
            if (!string.IsNullOrEmpty(ExportFilePath))
            {
                var path = Directory.GetParent(ExportFilePath);
                if (path != null)
                {
                    ExportFilePath = Path.Combine(path.FullName, "Exports");
                    if (!Directory.Exists(ExportFilePath))
                    {
                        Directory.CreateDirectory(ExportFilePath);
                    }
                }
            }

            ExportFilePath = Path.Combine(ExportFilePath, _fileName);
            if (!Directory.Exists(ExportFilePath))
            {
                Directory.CreateDirectory(ExportFilePath);
            }


            Commands.Add("user-list",
                new ParsableCommand<UserListOptions>
                {
                    Order = 32,
                    Description = "Displays a list of users in the backup.",
                    Action = DisplayUserList,
                });
            CommandAliases.Add("ul", "user-list");

            Commands.Add("user-export",
                new ParsableCommand<UserExportOptions>
                {
                    Order = 33,
                    Description = "Exports user records into external file.",
                    Action = ExportUserRecords,
                });
            CommandAliases.Add("ue", "user-export");

            Commands.Add("exit",
                new SimpleCommand
                {
                    Order = 41,
                    Description = "Locks the backup file and returns back to the main menu.",
                    Action = _ =>
                    {
                        NextStateCommands = ParentCommands;
                        return Task.CompletedTask;
                    },
                });
            CommandAliases.Add("e", "exit");
        }

        private Task DisplayUserList(UserListOptions options)
        {
            var pattern = string.IsNullOrEmpty(options.Match) ? null : new Regex(options.Match);
            var toShow = Users.Values
                .Where(x => pattern == null || pattern.IsMatch(x.Username))
                .ToArray();


            if (toShow.Length > 0)
            {
                var tab = new Tabulate(3);
                tab.SetColumnRightAlign(2, true);
                tab.AddHeader("Username", "Need password", "Records");
                foreach (var user in toShow)
                {
                    tab.AddRow(
                        user.Username, 
                        (user.DecryptedDataKey == null && user.DataKeyType == (int) BackupUserDataKeyType.Own) ? "Yes" : "No",
                        user.RecordCount);
                }
                tab.Sort(0);
                tab.DumpRowNo = true;
                tab.Dump();
            }
            else
            {
                Console.WriteLine($"No user found according to criteria \"{options.Match}\"");
            }

            return Task.CompletedTask;
        }

        private async Task ExportUserRecords(UserExportOptions options)
        {
            var zipFileName = options.ZipFile;
            if (!string.IsNullOrEmpty(zipFileName))
            {
                if (!zipFileName.Contains('.'))
                {
                    zipFileName += ".zip";
                }
            }

            var pattern = options.Username
                .Replace(@"\", @"\\")
                .Replace(".", @"\.")
                .Replace("+", @"\+")
                .Replace("*", ".*?");
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            var users = Users.Values
                .Where(x => regex.IsMatch(x.Username)).ToArray();
            if (users.Length == 0)
            {
                Console.WriteLine($"User(s) \"{options.Username}\" not found in the backup.");
                return;
            }

            await using var connection = new SQLiteConnection($"Data Source={BackupFileName};");
            connection.Open();

            foreach (var user in users)
            {
                if (user.DecryptedDataKey == null)
                {
                    var encryptedDataKey = user.DataKey.Base64UrlDecode();
                    switch (user.DataKeyType)
                    {
                        case (int) BackupUserDataKeyType.Own:
                        {
                            Console.WriteLine("\n{0, 20}: {1}", "Username", user.Username);
                            while (true)
                            {
                                Console.Write("{0, 20}: ", "Password");
                                var password = await Program.GetInputManager().ReadLine(new ReadLineParameters
                                {
                                    IsSecured = true
                                });
                                if (string.IsNullOrEmpty(password)) break;
                                try
                                {
                                    user.DecryptedDataKey = CryptoUtils.DecryptEncryptionParams(password, encryptedDataKey);
                                    break;
                                }
                                catch
                                {
                                    Console.WriteLine("Invalid password");
                                }
                            }
                        }
                            break;
                        case (int) BackupUserDataKeyType.SharedToEnterprise:
                        {
                            var eccPrivateKey = CryptoUtils.LoadPrivateEcKey(Keys.EnterprisePrivateKey);
                            user.DecryptedDataKey = CryptoUtils.DecryptEc(encryptedDataKey, eccPrivateKey);
                        }
                            break;
                    }

                    if (user.DecryptedDataKey != null)
                    {
                        user.DecryptedPrivateKey = CryptoUtils.DecryptAesV1(user.PrivateKey.Base64UrlDecode(), user.DecryptedDataKey);
                    }
                    else
                    {
                        Console.WriteLine($"Skipping user \"{user.Username}\" from record export.");
                        continue;
                    }

                }

                var fileName = $"{user.Username}.csv";
                await using var exporter = new CsvExporter(ExportFilePath, fileName, zipFileName);
                var recordStorage = new BackupDataReader<BackupRecord>(() => connection);
                var privateKey = CryptoUtils.LoadPrivateKey(user.DecryptedPrivateKey);
                var recordNo = 0;
                foreach (var record in recordStorage.GetByUserId(user.UserId))
                {
                    byte[] recordKey = null;
                    var encryptedRecordKey = CryptoUtils.DecryptAesV2(record.RecordKey.Base64UrlDecode(), Keys.BackupKey);
                    switch (record.KeyType)
                    {
                        case (int) BackupKeyType.EncryptedByDataKey:
                            recordKey = CryptoUtils.DecryptAesV1(encryptedRecordKey, user.DecryptedDataKey);
                            break;
                        case (int) BackupKeyType.EncryptedByPublicKey:
                            recordKey = CryptoUtils.DecryptRsa(encryptedRecordKey, privateKey);
                            break;
                    }

                    if (recordKey != null)
                    {
                        var data = CryptoUtils.DecryptAesV1(record.Data.Base64UrlDecode(), recordKey);
                        var recordData = JsonUtils.ParseJson<RecordData>(data);
                        RecordExtra recordExtra = null;
                        if (!string.IsNullOrEmpty(record.Extra))
                        {
                            var extra = CryptoUtils.DecryptAesV1(record.Extra.Base64UrlDecode(), recordKey);
                            recordExtra = JsonUtils.ParseJson<RecordExtra>(extra);
                        }

                        await exporter.ExportRecord(recordData, recordExtra);
                        recordNo++;
                    }
                }

                if (recordNo > 0)
                {
                    var info = $"Exported {recordNo} record(s) to file {fileName}";
                    if (!string.IsNullOrEmpty(zipFileName))
                    {
                        info = $"{info} inside archive {zipFileName}";
                    }
                    Console.WriteLine($"{info} located in \"{ExportFilePath}\" folder.");
                }
            }

            connection.Close();
        }

        private readonly string _fileName;
        public override string GetPrompt()
        {
            return _fileName;
        }
    }

    internal class UserListOptions
    {
        [Value(0, Required = false, MetaName = "Match", HelpText = "username filter.")]
        public string Match { get; set; }
    }

    internal class UserExportOptions : UserOptions
    {
        [Option("zip", Required = false, HelpText = "compress output file.")]
        public string ZipFile { get; set; }
    }

    internal class UserOptions
    {
        [Value(0, Required = true, MetaName = "Username", HelpText = "user email or pattern.")]
        public string Username { get; set; }
    }

    internal class CsvExporter : IExportRecord, IAsyncDisposable, IDisposable
    {
        private IDisposable _toDispose;
        private StreamWriter _writer;

        private bool _createHeader;

        public CsvExporter(string path, string fileName, string zipName = null)
        {
            if (!string.IsNullOrEmpty(zipName))
            {
                var fullPath = Path.Combine(path, zipName);
                var fileStream = File.Open(fullPath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
                var zipArchive = new ZipArchive(fileStream, ZipArchiveMode.Update, false);
                var entry = zipArchive.GetEntry(fileName) ?? zipArchive.CreateEntry(fileName, CompressionLevel.Fastest);
                _writer = new StreamWriter(entry.Open(), Encoding.UTF8, -1, false);
                _toDispose = zipArchive;
            }
            else
            {
                var fullPath = Path.Combine(path, fileName);
                var fileStream = File.OpenWrite(fullPath);
                _writer = new StreamWriter(fileStream, Encoding.UTF8, -1, false);
            }

            _createHeader = true;
        }

        private IEnumerable<string> GetCsvColumns(params object[] columns)
        {
            return columns
                .Select(x => x == null ? "" : x.ToString())
                .Select(x =>
                {
                    if (string.IsNullOrEmpty(x)) return "";
                    var shouldQuote = x.Contains(',');
                    if (x.Contains('\r'))
                    {
                        x = x.Replace("\r\n", "\n");
                        x = x.Replace("\r", "\n");
                    }
                    shouldQuote = shouldQuote || x.Contains('\n');
                    if (x.Contains('"'))
                    {
                        shouldQuote = true;
                        x = x.Replace("\"", "\"\"");
                    }

                    return shouldQuote ? $"\"{x}\"" : x;
                });
        }

        private IEnumerable<object> ExtractFields(RecordData data, RecordExtra extra)
        {
            yield return data?.title;
            yield return data?.secret1;
            yield return data?.secret2;
            yield return data?.link;
            yield return data?.notes;
            if (data?.custom != null)
            {
                foreach (var custom in data.custom)
                {
                    yield return custom.name;
                    yield return custom.value;
                }
            }

            if (extra?.fields == null) yield break;

            foreach (var obj in extra.fields)
            {
                if (!obj.ContainsKey("field_type") || !obj.ContainsKey("data")) continue;
                var type = obj["field_type"];
                if (!(type is string types)) continue;
                if (types != "totp") continue;
                    
                yield return "totp";
                yield return obj["data"];
            }
        }

        public async Task ExportRecord(RecordData data, RecordExtra extra)
        {
            if (_createHeader)
            {
                _createHeader = false;
                await _writer.WriteLineAsync(string.Join(',', GetCsvColumns(
                    "Title", "Login", "Password", "URL", "Notes", "Name1", "Value1", "Name2", "Value2")));
            }

            await _writer.WriteLineAsync(string.Join(',', ExtractFields(data, extra)));
        }

        protected virtual async ValueTask DisposeAsyncCore()
        {
            if (_writer is not null)
            {
                await _writer.FlushAsync();
                await _writer.DisposeAsync();
                _writer = null;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_writer is not null)
                {
                    _writer.Flush();
                    _writer.Dispose();
                    _writer = null;
                }
            }

            if (_toDispose != null)
            {
                _toDispose.Dispose();
                _toDispose = null;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await DisposeAsyncCore();
            Dispose(false);
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    internal interface IExportRecord
    {
        Task ExportRecord(RecordData data, RecordExtra extra);
    }
}
