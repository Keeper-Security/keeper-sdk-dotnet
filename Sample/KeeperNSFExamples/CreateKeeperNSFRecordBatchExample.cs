using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch creation of Keeper NSF records via <see cref="IVault.CreateKeeperNSFRecordsFromImport"/>.
    /// Uses the same JSON record shape as Import-KeeperVault / Export-KeeperVault.
    /// </summary>
    public static class CreateKeeperNSFRecordsBatchExample
    {
        /// <summary>
        /// Creates sample records covering common record types from an in-memory import payload.
        /// </summary>
        public static async Task CreateBatch(VaultOnline vault, string defaultFolderUid = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var import = BuildSampleImportFile(defaultFolderUid);
            await CreateBatch(vault, import, defaultFolderUid);
        }

        /// <summary>
        /// Creates records from the embedded sample JSON (same shape as PowerCommander -DownloadSampleRecords).
        /// </summary>
        public static async Task CreateBatchFromSampleFile(VaultOnline vault, string defaultFolderUid = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var import = LoadSampleImportFile();
            await CreateBatch(vault, import, defaultFolderUid);
        }

        /// <summary>
        /// Runs the batch record-create API and prints per-record results.
        /// </summary>
        public static async Task CreateBatch(
            VaultOnline vault,
            ImportFile import,
            string defaultFolderUid = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (import?.Records == null || import.Records.Length == 0)
            {
                Console.WriteLine("No records to create.");
                return;
            }

            try
            {
                Console.WriteLine($"Creating {import.Records.Length} Keeper NSF record(s) in batch...");
                var results = await vault.CreateKeeperNSFRecordsFromImport(import, defaultFolderUid);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine($"  [OK]   {result.Title}  UID: {result.RecordUid}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"  [FAIL] {result.Title}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Loads the embedded sample JSON as an <see cref="ImportFile"/>.
        /// </summary>
        public static ImportFile LoadSampleImportFile()
        {
            var jOptions = new JsonOptions
            {
                DateTimeStyles = DateTimeStyles.None,
            };
            jOptions.SerializationOptions &= ~JsonSerializationOptions.AutoParseDateTime;
            var jsonDict = Json.Deserialize<Dictionary<string, object>>(SampleImportJson, jOptions);
            return KeeperImport.LoadJsonDictionary(jsonDict);
        }

        private const string SampleImportJson = @"{
  ""records"": [
    {
      ""title"": ""Batch Demo - Login"",
      ""$type"": ""login"",
      ""login"": ""batch.demo.login@example.com"",
      ""password"": ""Replace-With-Your-Password"",
      ""login_url"": ""https://portal.example.com"",
      ""notes"": ""Standard login record. Replace credentials before importing.""
    },
    {
      ""title"": ""Batch Demo - Legacy General"",
      ""login"": ""legacy.user@example.com"",
      ""password"": ""Replace-With-Your-Password"",
      ""login_url"": ""https://legacy.example.com"",
      ""notes"": ""Legacy/general record (no $type)""
    },
    {
      ""title"": ""Batch Demo - Bank Card"",
      ""$type"": ""bankCard"",
      ""notes"": ""Payment card record"",
      ""custom_fields"": {
        ""$paymentCard"": {
          ""cardNumber"": ""4111111111111111"",
          ""cardExpirationDate"": ""04/2028"",
          ""cardSecurityCode"": ""123""
        }
      }
    },
    {
      ""title"": ""Batch Demo - Database Credentials"",
      ""$type"": ""databaseCredentials"",
      ""login"": ""db_app_user"",
      ""password"": ""Replace-With-Your-Password"",
      ""notes"": ""SQL Server application login"",
      ""custom_fields"": {
        ""$host"": {
          ""hostName"": ""192.168.1.10"",
          ""port"": ""1433""
        },
        ""$databaseType"": ""sqlServer""
      }
    },
    {
      ""title"": ""Batch Demo - Server Credentials"",
      ""$type"": ""serverCredentials"",
      ""login"": ""admin"",
      ""password"": ""Replace-With-Your-Password"",
      ""notes"": ""Linux admin account"",
      ""custom_fields"": {
        ""$host"": {
          ""hostName"": ""server.example.com"",
          ""port"": ""22""
        }
      }
    },
    {
      ""title"": ""Batch Demo - SSH Keys"",
      ""$type"": ""sshKeys"",
      ""notes"": ""SSH key pair (demo placeholders - replace with real keys for production)"",
      ""custom_fields"": {
        ""$keyPair"": {
          ""publicKey"": ""LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0="",
          ""privateKey"": ""LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==""
        }
      }
    },
    {
      ""title"": ""Batch Demo - Address"",
      ""$type"": ""address"",
      ""notes"": ""Office location"",
      ""custom_fields"": {
        ""$address:Work"": {
          ""street1"": ""123 Main Street"",
          ""street2"": ""Suite 400"",
          ""city"": ""San Jose"",
          ""state"": ""CA"",
          ""zip"": ""95110"",
          ""country"": ""US""
        }
      }
    },
    {
      ""title"": ""Batch Demo - Contact"",
      ""$type"": ""contact"",
      ""notes"": ""Sample contact card"",
      ""custom_fields"": {
        ""$name"": {
          ""first"": ""Jane"",
          ""middle"": """",
          ""last"": ""Doe""
        },
        ""$email"": ""jane.doe@example.com"",
        ""$phone:Mobile"": {
          ""region"": ""US"",
          ""number"": ""5551234567"",
          ""ext"": """",
          ""type"": ""mobile""
        }
      }
    },
    {
      ""title"": ""Batch Demo - Secure Note"",
      ""$type"": ""secureNote"",
      ""notes"": ""Record-level notes"",
      ""custom_fields"": {
        ""$note"": ""Sensitive information stored in the secure note field.""
      }
    },
    {
      ""title"": ""Batch Demo - Bank Account"",
      ""$type"": ""bankAccount"",
      ""notes"": ""Business checking account"",
      ""custom_fields"": {
        ""$bankAccount"": {
          ""accountType"": ""Checking"",
          ""routingNumber"": ""021000021"",
          ""accountNumber"": ""1234567890""
        }
      }
    }
  ]
}";

        /// <summary>
        /// Sample import payload (same structure as kimport records section) covering common record types.
        /// </summary>
        public static ImportFile BuildSampleImportFile(string defaultFolderUid = null)
        {
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
            var folders = BuildFolderEntry(defaultFolderUid);

            return new ImportFile
            {
                Records = new[]
                {
                    BuildLoginRecord(stamp, folders),
                    BuildLegacyGeneralRecord(stamp, folders),
                    BuildBankCardRecord(stamp, folders),
                    BuildDatabaseCredentialsRecord(stamp, folders),
                    BuildServerCredentialsRecord(stamp, folders),
                    BuildSshKeysRecord(stamp, folders),
                    BuildAddressRecord(stamp, folders),
                    BuildContactRecord(stamp, folders),
                    BuildSecureNoteRecord(stamp, folders),
                    BuildBankAccountRecord(stamp, folders),
                },
            };
        }

        // Optional default-folder entry when a folder UID is passed in.
        private static ImportRecordFolder[] BuildFolderEntry(string defaultFolderUid)
        {
            return string.IsNullOrEmpty(defaultFolderUid)
                ? null
                : new[] { new ImportRecordFolder { FolderName = defaultFolderUid } };
        }

        // Sample login record for the in-memory import payload.
        private static ImportRecord BuildLoginRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Login ({stamp})",
                RecordType = "login",
                Login = "batch.demo.login@example.com",
                Password = "BatchDemo-Login-2026!",
                LoginUrl = "https://portal.example.com",
                Notes = "Standard login record",
                Folders = folders,
            };

        // Legacy general record (no explicit $type).
        private static ImportRecord BuildLegacyGeneralRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Legacy General ({stamp})",
                Login = "legacy.user@example.com",
                Password = "BatchDemo-Legacy-2026!",
                LoginUrl = "https://legacy.example.com",
                Notes = "Legacy/general record (no $type)",
                Folders = folders,
            };

        // Sample bankCard record with $paymentCard custom field.
        private static ImportRecord BuildBankCardRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Bank Card ({stamp})",
                RecordType = "bankCard",
                Notes = "Payment card record",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$paymentCard",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "cardNumber", Value = "4111111111111111" },
                            new ImportCustomFieldElement { Name = "cardExpirationDate", Value = "04/2028" },
                            new ImportCustomFieldElement { Name = "cardSecurityCode", Value = "123" },
                        },
                    },
                },
            };

        // Sample databaseCredentials record with host/port custom fields.
        private static ImportRecord BuildDatabaseCredentialsRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Database Credentials ({stamp})",
                RecordType = "databaseCredentials",
                Login = "db_app_user",
                Password = "BatchDemo-DB-2026!",
                Notes = "SQL Server application login",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$host",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "hostName", Value = "192.168.1.10" },
                            new ImportCustomFieldElement { Name = "port", Value = "1433" },
                        },
                    },
                    new ImportCustomField { Name = "$databaseType", TextValue = "sqlServer" },
                },
            };

        // Sample serverCredentials record with SSH host/port.
        private static ImportRecord BuildServerCredentialsRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Server Credentials ({stamp})",
                RecordType = "serverCredentials",
                Login = "admin",
                Password = "BatchDemo-Server-2026!",
                Notes = "Linux admin account",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$host",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "hostName", Value = "server.example.com" },
                            new ImportCustomFieldElement { Name = "port", Value = "22" },
                        },
                    },
                },
            };

        // Sample sshKeys record with placeholder key pair.
        private static ImportRecord BuildSshKeysRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - SSH Keys ({stamp})",
                RecordType = "sshKeys",
                Notes = "SSH key pair (demo placeholders)",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$keyPair",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "publicKey", Value = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0=" },
                            new ImportCustomFieldElement { Name = "privateKey", Value = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==" },
                        },
                    },
                },
            };

        // Sample address record with work address custom field.
        private static ImportRecord BuildAddressRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Address ({stamp})",
                RecordType = "address",
                Notes = "Office location",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$address:Work",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "street1", Value = "123 Main Street" },
                            new ImportCustomFieldElement { Name = "street2", Value = "Suite 400" },
                            new ImportCustomFieldElement { Name = "city", Value = "San Jose" },
                            new ImportCustomFieldElement { Name = "state", Value = "CA" },
                            new ImportCustomFieldElement { Name = "zip", Value = "95110" },
                            new ImportCustomFieldElement { Name = "country", Value = "US" },
                        },
                    },
                },
            };

        // Sample contact record with name, email, and phone fields.
        private static ImportRecord BuildContactRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Contact ({stamp})",
                RecordType = "contact",
                Notes = "Sample contact card",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$name",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "first", Value = "Jane" },
                            new ImportCustomFieldElement { Name = "middle", Value = "" },
                            new ImportCustomFieldElement { Name = "last", Value = "Doe" },
                        },
                    },
                    new ImportCustomField { Name = "$email", TextValue = "jane.doe@example.com" },
                    new ImportCustomField
                    {
                        Name = "$phone:Mobile",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "region", Value = "US" },
                            new ImportCustomFieldElement { Name = "number", Value = "5551234567" },
                            new ImportCustomFieldElement { Name = "ext", Value = "" },
                            new ImportCustomFieldElement { Name = "type", Value = "mobile" },
                        },
                    },
                },
            };

        // Sample secureNote record with $note custom field.
        private static ImportRecord BuildSecureNoteRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Secure Note ({stamp})",
                RecordType = "secureNote",
                Notes = "Record-level notes",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField { Name = "$note", TextValue = "Sensitive information stored in the secure note field." },
                },
            };

        // Sample bankAccount record with routing/account numbers.
        private static ImportRecord BuildBankAccountRecord(string stamp, ImportRecordFolder[] folders) =>
            new ImportRecord
            {
                Title = $"Batch Demo - Bank Account ({stamp})",
                RecordType = "bankAccount",
                Notes = "Business checking account",
                Folders = folders,
                CustomFields = new[]
                {
                    new ImportCustomField
                    {
                        Name = "$bankAccount",
                        Elements = new[]
                        {
                            new ImportCustomFieldElement { Name = "accountType", Value = "Checking" },
                            new ImportCustomFieldElement { Name = "routingNumber", Value = "021000021" },
                            new ImportCustomFieldElement { Name = "accountNumber", Value = "1234567890" },
                        },
                    },
                },
            };
    }
}
