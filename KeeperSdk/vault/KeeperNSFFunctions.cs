using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Records;
using FolderProto = Folder;
using AuthProto = Authentication;
using RecordProto = Record.V3;
using RecordSharingProto = Record.V3.Sharing;
using RecordDetailsProto = Record.V3.Details;

namespace KeeperSecurity.Vault
{
    internal static partial class VaultOnlineFunctions
    {
        internal static byte[] SerializeNsfRecordData(NsfRecordData data)
        {
            if (data == null)
            {
                return JsonUtils.DumpJson(new NsfRecordData(), indent: false);
            }

            var payload = new NsfRecordData
            {
                Type = data.Type,
                Title = data.Title,
                Name = data.Name,
                Notes = data.Notes,
                ExtensionData = data.ExtensionData,
                Fields = data.Fields?
                    .Select(CloneNsfFieldForJson)
                    .Where(f => f != null)
                    .ToList(),
            };

            return JsonUtils.DumpJson(payload, indent: false);
        }

        private static NsfRecordFieldData CloneNsfFieldForJson(NsfRecordFieldData field)
        {
            if (field == null || string.IsNullOrEmpty(field.Type))
            {
                return null;
            }

            return new NsfRecordFieldData
            {
                Type = field.Type,
                Value = field.Value?.Select(v => CoerceNsfFieldValue(field.Type, v)).ToArray(),
            };
        }

        private static NsfRecordData BuildNsfRecordData(
            string recordType,
            string title,
            string notes,
            IDictionary<string, object> fields)
        {
            var data = new NsfRecordData
            {
                Type = string.IsNullOrEmpty(recordType) ? "login" : recordType,
                Title = title,
                Notes = notes,
                Fields = new List<NsfRecordFieldData>(),
            };

            if (fields == null)
            {
                return data;
            }

            foreach (var pair in fields)
            {
                if (pair.Value == null || string.IsNullOrEmpty(pair.Key))
                {
                    continue;
                }

                data.Fields.Add(new NsfRecordFieldData
                {
                    Type = pair.Key,
                    Value = ToNsfFieldValues(pair.Key, pair.Value),
                });
            }

            return data;
        }

        private static object[] ToNsfFieldValues(string fieldType, object value)
        {
            if (value is object[] values)
            {
                return values.Select(v => CoerceNsfFieldValue(fieldType, v)).ToArray();
            }

            return new[] { CoerceNsfFieldValue(fieldType, value) };
        }

        private static object CoerceNsfFieldValue(string fieldType, object value)
        {
            if (value is not IDictionary dict
                || !RecordTypesConstants.TryGetRecordField(fieldType, out var recordField)
                || !typeof(IFieldTypeSerialize).IsAssignableFrom(recordField.Type.Type))
            {
                return value;
            }

            var coerced = Activator.CreateInstance(recordField.Type.Type);
            if (coerced is not IFieldTypeSerialize serializer)
            {
                return value;
            }

            foreach (var key in dict.Keys)
            {
                if (key is not string element)
                {
                    continue;
                }

                serializer.SetElementValue(element, dict[key]?.ToString() ?? string.Empty);
            }

            return coerced;
        }

        public static async Task<string> AddKeeperNSFFolder(this VaultOnline vault, string folderName, string parentFolderUid = null, string color = null, bool inheritPermissions = true)
        {
            if (string.IsNullOrEmpty(folderName))
            {
                throw new ArgumentNullException(nameof(folderName));
            }

            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                if (!vault.TryGetKeeperNSFFolder(parentFolderUid, out _))
                {
                    throw new VaultException($"Parent Keeper NSF folder '{parentFolderUid}' not found");
                }
            }

            var nameLower = folderName.ToLowerInvariant();
            foreach (var existing in vault.KeeperNSFFolderNodes)
            {
                if (existing.Name != null && existing.Name.ToLowerInvariant() == nameLower)
                {
                    var existingParent = existing.ParentUid ?? "";
                    var expectedParent = parentFolderUid ?? "";
                    if (existingParent == expectedParent)
                    {
                        throw new VaultException($"Keeper NSF folder '{folderName}' already exists");
                    }
                }
            }

            var folderUid = CryptoUtils.GenerateUid();
            var folderKey = CryptoUtils.GenerateEncryptionKey();

            var encryptionKey = vault.Auth.AuthContext.DataKey;
            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                if (vault.TryGetKeeperNSFFolder(parentFolderUid, out var parentFolder) && parentFolder.FolderKey != null)
                {
                    encryptionKey = parentFolder.FolderKey;
                }
            }

            var folderData = new FolderDataJson { name = folderName };
            if (!string.IsNullOrEmpty(color) && color != "none")
            {
                folderData.color = color;
            }
            var dataJson = JsonUtils.DumpJson(folderData, false);
            var encryptedData = CryptoUtils.EncryptAesV2(dataJson, folderKey);
            var encryptedFolderKey = CryptoUtils.EncryptAesV2(folderKey, encryptionKey);

            var fd = new Folder.FolderData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                Data = ByteString.CopyFrom(encryptedData),
                FolderKey = ByteString.CopyFrom(encryptedFolderKey),
                Type = Folder.FolderUsageType.UtNormal,
                InheritUserPermissions = inheritPermissions
                    ? Folder.SetBooleanValue.BooleanTrue
                    : Folder.SetBooleanValue.BooleanFalse,
            };

            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                fd.ParentUid = ByteString.CopyFrom(parentFolderUid.Base64UrlDecode());
            }

            var rq = new Folder.FolderAddRequest();
            rq.FolderData.Add(fd);

            var response = await vault.Auth.ExecuteAuthRest<Folder.FolderAddRequest, Folder.FolderAddResponse>("vault/folders/v3/add", rq);

            if (response.FolderAddResults.Count > 0)
            {
                var result = response.FolderAddResults[0];
                if (result.Status == Folder.FolderModifyStatus.Success)
                {
                    return folderUid;
                }
                throw new VaultException($"Failed to create Keeper NSF folder: {result.Message}");
            }
            throw new VaultException("No response from server for folder creation");
        }

        private static FolderProto.AccessRoleType ResolveAccessRole(string role)
        {
            switch (role?.ToLowerInvariant())
            {
                case "viewer": return FolderProto.AccessRoleType.Viewer;
                case "share-manager": return FolderProto.AccessRoleType.SharedManager;
                case "content-manager": return FolderProto.AccessRoleType.ContentManager;
                case "content-share-manager": return FolderProto.AccessRoleType.ContentShareManager;
                case "full-manager": return FolderProto.AccessRoleType.Manager;
                default:
                    throw new ArgumentException($"Unknown access role '{role}'. Valid roles: viewer, share-manager, content-manager, content-share-manager, full-manager");
            }
        }

        public static async Task GrantKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string userEmail, string role, SharedFolderUserOptions options = null)
        {
            if (string.IsNullOrEmpty(folderUid))
                throw new VaultException("Folder UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                throw new KeeperApiException("public_key_error", $"User '{userEmail}' not found or has no public key: {pkRs.Message}");

            var folderKey = folder.FolderKey;
            if (folderKey == null)
                throw new VaultException($"Cannot share folder: folder key is not available for '{folderUid}'");

            var accessRole = ResolveAccessRole(role);
            var folderUidBytes = ByteString.CopyFrom(folderUid.Base64UrlDecode());
            var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(options);

            FolderProto.FolderAccessData existingAccess = null;
            try
            {
                var accessRq = new FolderProto.V3.GetFolderAccessRequest();
                accessRq.FolderUid.Add(folderUidBytes);
                var accessRs = await vault.Auth.ExecuteAuthRest<FolderProto.V3.GetFolderAccessRequest, FolderProto.V3.GetFolderAccessResponse>(
                    "vault/folders/v3/access", accessRq);
                foreach (var fr in accessRs.FolderAccessResults)
                {
                    if (fr.Error != null) continue;
                    foreach (var accessor in fr.Accessors)
                    {
                        if (accessor.AccessType == FolderProto.AccessType.AtUser
                            && accessor.AccessTypeUid.Equals(pkRs.AccountUid))
                        {
                            existingAccess = accessor;
                            break;
                        }
                    }
                    if (existingAccess != null) break;
                }
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"KeeperNSF: Could not look up existing folder access for '{folderUid}'; falling back to create flow: {ex.Message}");
            }

            var rq = new FolderProto.FolderAccessRequest();

            if (existingAccess != null)
            {
                if (existingAccess.AccessRoleType == accessRole && tlaProperties == null)
                {
                    return;
                }

                var updateData = new FolderProto.FolderAccessData
                {
                    FolderUid = folderUidBytes,
                    AccessTypeUid = pkRs.AccountUid,
                    AccessType = FolderProto.AccessType.AtUser,
                    AccessRoleType = accessRole,
                };
                if (tlaProperties != null)
                    updateData.TlaProperties = tlaProperties;
                rq.FolderAccessUpdates.Add(updateData);
            }
            else
            {
                var forbidKeyType2 = vault.Auth.AuthContext.ForbidKeyType2;

                byte[] encryptedFolderKey;
                FolderProto.EncryptedKeyType keyType;
                if (forbidKeyType2 && !pkRs.PublicEccKey.IsEmpty)
                {
                    var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                    encryptedFolderKey = CryptoUtils.EncryptEc(folderKey, ecPk);
                    keyType = FolderProto.EncryptedKeyType.EncryptedByPublicKeyEcc;
                }
                else if (!forbidKeyType2 && !pkRs.PublicKey.IsEmpty)
                {
                    var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                    encryptedFolderKey = CryptoUtils.EncryptRsa(folderKey, rsaPk);
                    keyType = FolderProto.EncryptedKeyType.EncryptedByPublicKey;
                }
                else if (!pkRs.PublicEccKey.IsEmpty)
                {
                    var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                    encryptedFolderKey = CryptoUtils.EncryptEc(folderKey, ecPk);
                    keyType = FolderProto.EncryptedKeyType.EncryptedByPublicKeyEcc;
                }
                else
                {
                    var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                    encryptedFolderKey = CryptoUtils.EncryptRsa(folderKey, rsaPk);
                    keyType = FolderProto.EncryptedKeyType.EncryptedByPublicKey;
                }

                var addData = new FolderProto.FolderAccessData
                {
                    FolderUid = folderUidBytes,
                    AccessTypeUid = pkRs.AccountUid,
                    AccessType = FolderProto.AccessType.AtUser,
                    AccessRoleType = accessRole,
                };
                addData.FolderKey = new FolderProto.EncryptedDataKey
                {
                    EncryptedKey = ByteString.CopyFrom(encryptedFolderKey),
                    EncryptedKeyType = keyType,
                };
                if (tlaProperties != null)
                    addData.TlaProperties = tlaProperties;
                rq.FolderAccessAdds.Add(addData);
            }

            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    var action = existingAccess != null ? "update" : "grant";
                    throw new VaultException($"Failed to {action} access: {result.Message}");
                }
            }
        }

        public static async Task RevokeKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string userEmail)
        {
            if (string.IsNullOrEmpty(folderUid))
                throw new VaultException("Folder UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.AccountUid.IsEmpty)
                throw new KeeperApiException("user_not_found", $"User '{userEmail}' not found");

            var accessData = new FolderProto.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = pkRs.AccountUid,
                AccessType = FolderProto.AccessType.AtUser,
            };

            var rq = new FolderProto.FolderAccessRequest();
            rq.FolderAccessRemoves.Add(accessData);

            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to revoke access: {result.Message}");
                }
            }
        }

        public static async Task<string> CreateKeeperNSFRecordInternal(this VaultOnline vault, string title, string recordType, string folderUid, string notes, IDictionary<string, object> fields)
        {
            if (string.IsNullOrEmpty(title))
                throw new VaultException("Record title cannot be empty");

            var recordUid = CryptoUtils.GenerateUid();
            var recordKey = CryptoUtils.GenerateEncryptionKey();

            byte[] encryptionKey;
            FolderProto.FolderKeyEncryptionType keyEncryptedBy;

            if (!string.IsNullOrEmpty(folderUid))
            {
                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                    throw new VaultException($"Keeper NSF folder '{folderUid}' not found");
                if (folder.FolderKey == null)
                    throw new VaultException($"Folder key not available for folder '{folderUid}'");
                encryptionKey = folder.FolderKey;
                keyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByParentKey;
            }
            else
            {
                encryptionKey = vault.Auth.AuthContext.DataKey;
                keyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByUserKey;
            }

            var dataObj = BuildNsfRecordData(recordType, title, notes, fields);
            var jsonData = SerializeNsfRecordData(dataObj);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, recordKey);
            var encryptedRecordKey = CryptoUtils.EncryptAesV2(recordKey, encryptionKey);

            var ra = new RecordProto.RecordAdd
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                RecordKeyType = FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm,
                RecordKeyEncryptedBy = keyEncryptedBy,
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Data = ByteString.CopyFrom(encryptedData),
            };

            if (!string.IsNullOrEmpty(folderUid))
            {
                ra.FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode());
            }

            var rq = new RecordProto.RecordsAddRequest();
            rq.Records.Add(ra);

            var rs = await vault.Auth.ExecuteAuthRest<RecordProto.RecordsAddRequest, RecordsModifyResponse>(
                "vault/records/v3/add", rq);

            if (rs.Records.Count > 0)
            {
                var result = rs.Records[0];
                if (result.Status != RecordModifyResult.RsSuccess)
                {
                    throw new VaultException($"Failed to create record: {result.Message}");
                }
            }

            return recordUid;
        }

        public static async Task UpdateKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string title, string recordType, string notes, IDictionary<string, object> fields)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");

            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                throw new VaultException($"Keeper NSF record '{recordUid}' not found");

            await vault.UpdateKeeperNSFRecordInternal(record, title, recordType, notes, fields).ConfigureAwait(false);
        }

        public static async Task UpdateKeeperNSFRecordInternal(this VaultOnline vault, KeeperNSFRecord record, string title, string recordType, string notes, IDictionary<string, object> fields)
        {
            if (record == null)
                throw new ArgumentNullException(nameof(record));

            var recordUid = record.RecordUid;
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");

            if (record.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");

            if (record.Data == null)
                throw new VaultException($"Record '{recordUid}' has no decrypted data available. Cannot update.");

            var dataObj = record.Data;
            if (dataObj.Fields == null)
            {
                dataObj.Fields = new List<NsfRecordFieldData>();
            }

            if (title != null) dataObj.Title = title;
            if (recordType != null) dataObj.Type = recordType;
            if (notes != null) dataObj.Notes = notes;

            if (fields != null)
            {
                foreach (var kvp in fields)
                {
                    var existing = dataObj.Fields.FirstOrDefault(f => f.Type == kvp.Key);
                    if (existing != null)
                    {
                        existing.Value = ToNsfFieldValues(kvp.Key, kvp.Value);
                    }
                    else
                    {
                        dataObj.Fields.Add(new NsfRecordFieldData
                        {
                            Type = kvp.Key,
                            Value = ToNsfFieldValues(kvp.Key, kvp.Value),
                        });
                    }
                }
            }

            var jsonData = SerializeNsfRecordData(dataObj);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, record.RecordKey);

            var ru = new RecordUpdate
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Revision = record.Revision,
                Data = ByteString.CopyFrom(encryptedData),
            };

            var rq = new RecordsUpdateRequest();
            rq.Records.Add(ru);

            var rs = await vault.Auth.ExecuteAuthRest<RecordsUpdateRequest, RecordsModifyResponse>(
                "vault/records/v3/update", rq);

            if (rs.Records.Count > 0)
            {
                var result = rs.Records[0];
                if (result.Status != RecordModifyResult.RsSuccess)
                {
                    var status = Enum.GetName(typeof(RecordModifyResult), result.Status) ?? "";
                    if (status.StartsWith("Rs", StringComparison.Ordinal))
                    {
                        status = status.Substring(2);
                    }

                    throw new KeeperApiException(status.ToSnakeCase(), result.Message ?? "Failed to update record");
                }
            }
        }

        private static async Task<RecordSharingProto.Permissions> BuildRecordSharePermissions(
            VaultOnline vault, string recordUid, string userEmail, string role, SharedFolderRecordOptions options = null)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                throw new VaultException($"Keeper NSF record '{recordUid}' not found");
            if (record.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");

            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                throw new KeeperApiException("public_key_error", $"User '{userEmail}' not found or has no public key: {pkRs.Message}");

            byte[] encryptedRecordKey;
            bool useEcc;
            if (!pkRs.PublicKey.IsEmpty)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptRsa(record.RecordKey, rsaPk);
                useEcc = false;
            }
            else
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptEc(record.RecordKey, ecPk);
                useEcc = true;
            }

            var accessRole = ResolveAccessRole(role);
            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                UseEccKey = useEcc,
            };
            var rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = FolderProto.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Owner = false,
                AccessRoleType = accessRole,
            };
            var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(options);
            if (tlaProperties != null)
                rules.TlaProperties = tlaProperties;
            perm.Rules = rules;
            return perm;
        }

        public static async Task ShareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail, string role, SharedFolderRecordOptions options = null)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            var perm = await BuildRecordSharePermissions(vault, recordUid, userEmail, role, options);
            var recipientUid = perm.RecipientUid;
            var requestedRole = (int)ResolveAccessRole(role);
            var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(options);

            bool hasDirectShare = false;
            try
            {
                var detailsRq = new RecordDetailsProto.RecordAccessRequest();
                detailsRq.RecordUids.Add(ByteString.CopyFrom(recordUid.Base64UrlDecode()));
                var detailsRs = await vault.Auth.ExecuteAuthRest<RecordDetailsProto.RecordAccessRequest, RecordDetailsProto.RecordAccessResponse>(
                    "vault/records/v3/details/access", detailsRq);
                foreach (var ra in detailsRs.RecordAccesses)
                {
                    var data = ra?.Data;
                    if (data == null) continue;
                    if (data.AccessType != FolderProto.AccessType.AtUser) continue;
                    if (data.Owner) continue;
                    if (data.Inherited) continue;
                    if (!data.AccessTypeUid.Equals(recipientUid)) continue;

                    if (data.AccessRoleType == (FolderProto.AccessRoleType)requestedRole && tlaProperties == null)
                    {
                        return;
                    }
                    hasDirectShare = true;
                    break;
                }
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"KeeperNSF: Could not look up existing record access for '{recordUid}'; falling back to create flow: {ex.Message}");
            }

            if (!hasDirectShare)
            {
                var createRq = new RecordSharingProto.Request();
                createRq.CreateSharingPermissions.Add(perm);
                var createRs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                    "vault/records/v3/share", createRq);

                var createStatus = createRs.CreatedSharingStatus.FirstOrDefault();
                if (createStatus != null && createStatus.Status_ == RecordSharingProto.SharingStatus.Success)
                {
                    return;
                }

                if (createStatus == null || createStatus.Status_ != RecordSharingProto.SharingStatus.AlreadyShared)
                {
                    var msg = createStatus?.Message;
                    throw new VaultException($"Failed to share record: {(string.IsNullOrEmpty(msg) ? "unknown error" : msg)}");
                }
            }

            var updateRq = new RecordSharingProto.Request();
            updateRq.UpdateSharingPermissions.Add(perm);
            var updateRs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", updateRq);
            foreach (var status in updateRs.UpdatedSharingStatus)
            {
                if (status.Status_ != RecordSharingProto.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to update record share: {status.Message}");
                }
            }
        }

        /// <summary>
        /// Transfers NSF record ownership via v3 share (owner flag). Used when the record is already shared with the recipient.
        /// </summary>
        public static async Task TransferKeeperNSFRecordOwnershipViaShareInternal(
            this VaultOnline vault, string recordUid, string userEmail)
        {
            var perm = await BuildKeeperNSFOwnerTransferPermissions(vault, recordUid, userEmail).ConfigureAwait(false);

            var updateRq = new RecordSharingProto.Request();
            updateRq.UpdateSharingPermissions.Add(perm);
            var updateRs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", updateRq).ConfigureAwait(false);

            if (updateRs.UpdatedSharingStatus.Any(s => s.Status_ == RecordSharingProto.SharingStatus.Success))
            {
                return;
            }

            var createRq = new RecordSharingProto.Request();
            createRq.CreateSharingPermissions.Add(perm);
            var createRs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", createRq).ConfigureAwait(false);

            if (createRs.CreatedSharingStatus.Any(s => s.Status_ == RecordSharingProto.SharingStatus.Success))
            {
                return;
            }

            var failure = updateRs.UpdatedSharingStatus.FirstOrDefault()
                ?? createRs.CreatedSharingStatus.FirstOrDefault();
            var message = failure?.Message;
            if (string.IsNullOrEmpty(message))
            {
                message = "Failed to transfer ownership via record share.";
            }

            throw new VaultException(message);
        }

        private static async Task<RecordSharingProto.Permissions> BuildKeeperNSFOwnerTransferPermissions(
            VaultOnline vault, string recordUid, string userEmail)
        {
            var perm = await BuildRecordSharePermissions(vault, recordUid, userEmail, "full-manager").ConfigureAwait(false);
            if (perm.Rules != null)
            {
                perm.Rules.Owner = true;
                perm.Rules.AccessType = FolderProto.AccessType.AtOwner;
            }

            return perm;
        }

        public static async Task UnshareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.AccountUid.IsEmpty)
                throw new KeeperApiException("user_not_found", $"User '{userEmail}' not found");

            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            perm.Rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = FolderProto.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };

            var rq = new RecordSharingProto.Request();
            rq.RevokeSharingPermissions.Add(perm);

            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq);

            foreach (var status in rs.RevokedSharingStatus)
            {
                if (status.Status_ != RecordSharingProto.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to revoke record access: {status.Message}");
                }
            }
        }

        private static string GetRoleLabel(int roleType)
        {
            var enumValue = (FolderProto.AccessRoleType)roleType;
            switch (enumValue)
            {
                case FolderProto.AccessRoleType.Navigator: return "contributor";
                case FolderProto.AccessRoleType.Requestor: return "contributor";
                case FolderProto.AccessRoleType.Viewer: return "viewer";
                case FolderProto.AccessRoleType.SharedManager: return "share-manager";
                case FolderProto.AccessRoleType.ContentManager: return "content-manager";
                case FolderProto.AccessRoleType.ContentShareManager: return "content-share-manager";
                case FolderProto.AccessRoleType.Manager: return "full-manager";
                default: return "unknown";
            }
        }

        private static void CollectRecordUids(VaultOnline vault, string folderUid, bool recursive, HashSet<string> recordUids, HashSet<string> visited)
        {
            if (folderUid != null)
            {
                if (visited.Contains(folderUid)) return;
                visited.Add(folderUid);

                if (vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    foreach (var recUid in folder.Records)
                    {
                        recordUids.Add(recUid);
                    }

                    if (recursive)
                    {
                        foreach (var subUid in folder.Subfolders)
                        {
                            CollectRecordUids(vault, subUid, true, recordUids, visited);
                        }
                    }
                }
            }
            else
            {
                foreach (var folder in vault.KeeperNSFFolderNodes)
                {
                    if (visited.Contains(folder.FolderUid)) continue;
                    visited.Add(folder.FolderUid);

                    foreach (var recUid in folder.Records)
                    {
                        recordUids.Add(recUid);
                    }
                }
            }
        }

        public static async Task<KeeperNSFPermissionResult> UpdateKeeperNSFRecordPermissionsInternal(
            this VaultOnline vault, string folderUid, string action, string role, bool recursive, bool dryRun = false)
        {
            var recordUids = new HashSet<string>();
            CollectRecordUids(vault, folderUid, recursive, recordUids, new HashSet<string>());

            if (recordUids.Count == 0)
                throw new VaultException("No records found in the specified folder");

            var accessRq = new RecordDetailsProto.RecordAccessRequest();
            foreach (var uid in recordUids)
            {
                accessRq.RecordUids.Add(ByteString.CopyFrom(uid.Base64UrlDecode()));
            }

            var accessRs = await vault.Auth.ExecuteAuthRest<RecordDetailsProto.RecordAccessRequest,
                RecordDetailsProto.RecordAccessResponse>(
                "vault/records/v3/details/access", accessRq);

            var currentUser = vault.Auth.Username;
            var forbidden = new HashSet<string>();
            foreach (var fu in accessRs.ForbiddenRecords)
            {
                forbidden.Add(CryptoUtils.Base64UrlEncode(fu.ToByteArray()));
            }

            var accesses = new List<KeeperNSFAccessEntry>();
            var canUpdateMap = new Dictionary<string, bool>();

            foreach (var ra in accessRs.RecordAccesses)
            {
                var d = ra.Data;
                var ai = ra.AccessorInfo;
                var recUid = CryptoUtils.Base64UrlEncode(d.RecordUid.ToByteArray());
                var accessorName = ai?.Name ?? "";

                if (accessorName == currentUser)
                {
                    canUpdateMap[recUid] = d.CanUpdateAccess;
                }

                accesses.Add(new KeeperNSFAccessEntry
                {
                    RecordUid = recUid,
                    AccessorName = accessorName,
                    AccessTypeUid = CryptoUtils.Base64UrlEncode(d.AccessTypeUid.ToByteArray()),
                    Owner = d.Owner,
                    Inherited = d.Inherited,
                    AccessRoleType = (int)d.AccessRoleType,
                    CanEdit = d.CanEdit,
                    CanView = d.CanView,
                    CanUpdateAccess = d.CanUpdateAccess,
                    CanDelete = d.CanDelete,
                });
            }

            var result = new KeeperNSFPermissionResult();

            foreach (var recUid in recordUids)
            {
                if (forbidden.Contains(recUid))
                {
                    result.Skipped.Add(new KeeperNSFPermissionChange
                    {
                        RecordUid = recUid, Email = "", CurrentRole = "",
                        ChangeType = "skip", Message = "No access - record is forbidden",
                    });
                }
            }

            foreach (var access in accesses)
            {
                if (!recordUids.Contains(access.RecordUid) || access.Owner)
                    continue;
                if (string.IsNullOrEmpty(access.AccessorName) || access.AccessorName == currentUser)
                    continue;

                var curRole = GetRoleLabel(access.AccessRoleType);

                if (!canUpdateMap.TryGetValue(access.RecordUid, out var canUpdate) || !canUpdate)
                {
                    result.Skipped.Add(new KeeperNSFPermissionChange
                    {
                        RecordUid = access.RecordUid, Email = access.AccessorName,
                        CurrentRole = curRole, ChangeType = "skip",
                        Message = "Insufficient permission (can_update_access is false)",
                    });
                    continue;
                }

                if (action == "grant")
                {
                    if (curRole != role)
                    {
                        if (dryRun)
                        {
                            result.Grants.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, NewRole = role,
                                ChangeType = access.Inherited ? "create" : "update",
                                Success = true, Message = "dry-run",
                            });
                        }
                        else
                        {
                            try
                            {
                                if (access.Inherited)
                                {
                                    await vault.ShareKeeperNSFRecordInternal(access.RecordUid, access.AccessorName, role);
                                }
                                else
                                {
                                    await UpdateKeeperNSFRecordShareInternal(vault, access.RecordUid, access.AccessorName, role);
                                }
                                result.Grants.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, NewRole = role,
                                    ChangeType = access.Inherited ? "create" : "update",
                                    Success = true,
                                });
                            }
                            catch (Exception ex)
                            {
                                result.Grants.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, NewRole = role,
                                    ChangeType = access.Inherited ? "create" : "update",
                                    Success = false, Message = ex.Message,
                                });
                            }
                        }
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(role) || curRole == role)
                    {
                        if (access.Inherited)
                        {
                            result.Skipped.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, ChangeType = "skip",
                                Message = "Inherited from a shared folder - revoke at the parent shared folder",
                            });
                        }
                        else if (dryRun)
                        {
                            result.Revokes.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, ChangeType = "revoke",
                                Success = true, Message = "dry-run",
                            });
                        }
                        else
                        {
                            try
                            {
                                await vault.UnshareKeeperNSFRecordInternal(access.RecordUid, access.AccessorName);
                                result.Revokes.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, ChangeType = "revoke", Success = true,
                                });
                            }
                            catch (Exception ex)
                            {
                                result.Revokes.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, ChangeType = "revoke",
                                    Success = false, Message = ex.Message,
                                });
                            }
                        }
                    }
                }
            }

            return result;
        }

        private static async Task UpdateKeeperNSFRecordShareInternal(VaultOnline vault, string recordUid, string userEmail, string role)
        {
            var perm = await BuildRecordSharePermissions(vault, recordUid, userEmail, role);

            var rq = new RecordSharingProto.Request();
            rq.UpdateSharingPermissions.Add(perm);

            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq);

            foreach (var status in rs.UpdatedSharingStatus)
            {
                if (status.Status_ != RecordSharingProto.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to update record share: {status.Message}");
                }
            }
        }

        private static Dictionary<string, HashSet<string>> BuildShortcutMap(VaultOnline vault)
        {
            var knownFolders = new HashSet<string>();
            foreach (var f in vault.KeeperNSFFolderNodes)
            {
                knownFolders.Add(f.FolderUid);
            }

            var recordFolders = new Dictionary<string, HashSet<string>>();
            foreach (var link in vault.Storage.KdFolderRecords.GetAllLinks())
            {
                if (!knownFolders.Contains(link.FolderUid))
                    continue;
                if (!recordFolders.TryGetValue(link.RecordUid, out var folders))
                {
                    folders = new HashSet<string>();
                    recordFolders[link.RecordUid] = folders;
                }
                folders.Add(link.FolderUid);
            }

            var shortcuts = new Dictionary<string, HashSet<string>>();
            foreach (var kvp in recordFolders)
            {
                if (kvp.Value.Count > 1)
                {
                    shortcuts[kvp.Key] = kvp.Value;
                }
            }
            return shortcuts;
        }

        private static string GetRecordTitle(VaultOnline vault, string recordUid)
        {
            if (vault.TryGetKeeperNSFRecord(recordUid, out var rec) && !string.IsNullOrEmpty(rec.Title))
                return rec.Title;
            return recordUid;
        }

        private static string GetFolderName(VaultOnline vault, string folderUid)
        {
            if (vault.TryGetKeeperNSFFolder(folderUid, out var folder) && !string.IsNullOrEmpty(folder.Name))
                return folder.Name;
            return folderUid;
        }

        public static async Task<KeeperNSFRecordDetailsResult> GetKeeperNSFRecordDetailsInternal(
            this VaultOnline vault, IReadOnlyList<string> recordUids)
        {
            var response = await vault.FetchKeeperNSFRecordDetailsDataAsync(recordUids).ConfigureAwait(false);

            var result = new KeeperNSFRecordDetailsResult();
            foreach (var forbiddenUid in response.ForbiddenRecords)
            {
                result.ForbiddenRecords.Add(CryptoUtils.Base64UrlEncode(forbiddenUid.ToByteArray()));
            }

            foreach (var recordData in response.Data)
            {
                var recordUid = CryptoUtils.Base64UrlEncode(recordData.RecordUid.ToByteArray());
                var title = "Unknown";
                var type = "Unknown";

                if (TryDecryptKeeperNSFRecordDetailsData(vault, recordData, recordUid, out var decrypted))
                {
                    title = !string.IsNullOrEmpty(decrypted?.Title)
                        ? decrypted.Title
                        : !string.IsNullOrEmpty(decrypted?.Name) ? decrypted.Name : "Unknown";
                    type = !string.IsNullOrEmpty(decrypted?.Type) ? decrypted.Type : "Unknown";
                }
                else if (vault.TryGetKeeperNSFRecord(recordUid, out var cached))
                {
                    ResolveKeeperNSFRecordTitleAndType(cached, out title, out type);
                }

                result.Data.Add(new KeeperNSFRecordDetailEntry
                {
                    RecordUid = recordUid,
                    Title = title,
                    Type = type,
                    Version = recordData.Version,
                    Revision = recordData.Revision,
                });
            }

            return result;
        }

        private static async Task<RecordDetailsProto.RecordDataResponse> FetchKeeperNSFRecordDetailsDataAsync(
            this VaultOnline vault, IReadOnlyList<string> recordUids)
        {
            if (recordUids == null || recordUids.Count == 0)
            {
                throw new KeeperInvalidParameter("GetKeeperNSFRecordDetails", nameof(recordUids), "", "at least one record UID required");
            }

            var request = new RecordDetailsProto.RecordDataRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };

            foreach (var uid in recordUids.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                var uidBytes = uid.Trim().Base64UrlDecode();
                if (uidBytes == null || uidBytes.Length == 0)
                {
                    Trace.TraceWarning($"KeeperNSF: Skipping record details request with malformed UID '{uid}'");
                    continue;
                }

                request.RecordUids.Add(ByteString.CopyFrom(uidBytes));
            }

            if (request.RecordUids.Count == 0)
            {
                throw new KeeperInvalidParameter("GetKeeperNSFRecordDetails", nameof(recordUids), "", "no valid record UIDs");
            }

            return await vault.Auth.ExecuteAuthRest<RecordDetailsProto.RecordDataRequest, RecordDetailsProto.RecordDataResponse>(
                "vault/records/v3/details/data", request).ConfigureAwait(false);
        }

        internal static async Task<KeeperNSFRecord> GetRefreshedKeeperNSFRecordAsync(this VaultOnline vault, string recordUid)
        {
            if (string.IsNullOrWhiteSpace(recordUid))
                return null;

            var trimmedUid = recordUid.Trim();
            var response = await vault.FetchKeeperNSFRecordDetailsDataAsync(new[] { trimmedUid }).ConfigureAwait(false);

            var recordData = (response.Data ?? Enumerable.Empty<Records.RecordData>())
                .FirstOrDefault(x =>
                {
                    if (x.RecordUid == null || x.RecordUid.IsEmpty)
                        return false;
                    var uid = CryptoUtils.Base64UrlEncode(x.RecordUid.ToByteArray());
                    return string.Equals(uid, trimmedUid, StringComparison.OrdinalIgnoreCase);
                });

            return recordData != null && TryBuildKeeperNSFRecordFromDetailsData(vault, recordData, trimmedUid, out var record)
                ? record
                : null;
        }

        private static bool TryBuildKeeperNSFRecordFromDetailsData(
            VaultOnline vault, Records.RecordData recordData, string recordUid, out KeeperNSFRecord record)
        {
            record = null;
            if (recordData == null || string.IsNullOrWhiteSpace(recordUid))
                return false;

            if (!TryDecryptKeeperNSFRecordDetailsData(vault, recordData, recordUid, out var data))
                return false;

            var recordKey = TryDecryptKeeperNSFRecordKeyFromDetails(vault, recordData, recordUid);
            if (recordKey == null || recordKey.Length == 0)
                return false;

            vault.TryGetKeeperNSFRecord(recordUid, out var cached);

            record = new KeeperNSFRecord
            {
                RecordUid = recordUid,
                Title = !string.IsNullOrEmpty(data?.Title) ? data.Title : data?.Name,
                Type = data?.Type,
                Notes = data?.Notes,
                Revision = recordData.Revision,
                Version = recordData.Version,
                Shared = cached?.Shared ?? false,
                ClientModifiedTime = cached?.ClientModifiedTime ?? 0,
                FileSize = cached?.FileSize ?? 0,
                ThumbnailSize = cached?.ThumbnailSize ?? 0,
                FolderUid = cached?.FolderUid,
                FolderName = cached?.FolderName,
                RecordKey = recordKey,
                Data = data,
            };
            return true;
        }

        private static void ResolveKeeperNSFRecordTitleAndType(KeeperNSFRecord record, out string title, out string type)
        {
            if (!string.IsNullOrEmpty(record?.Type))
            {
                type = record.Type;
            }
            else if (record?.Version == 4)
            {
                type = "file";
            }
            else if (record?.Version == 5)
            {
                type = "application";
            }
            else
            {
                type = "Unknown";
            }

            title = !string.IsNullOrEmpty(record?.Title) ? record.Title : "Unknown";
        }

        private static bool TryDecryptKeeperNSFRecordDetailsData(
            VaultOnline vault, Records.RecordData recordData, string recordUid, out NsfRecordData data)
        {
            data = null;
            var recordKey = TryDecryptKeeperNSFRecordKeyFromDetails(vault, recordData, recordUid);
            if (recordKey == null || recordKey.Length == 0)
            {
                return false;
            }

            if (string.IsNullOrEmpty(recordData.EncryptedRecordData))
            {
                return false;
            }

            if (!CryptoUtils.TryDecryptAesV2(recordData.EncryptedRecordData.Base64UrlDecode(), recordKey, out var decryptedBytes))
            {
                Trace.TraceWarning($"KeeperNSF: Failed to decrypt record details for {recordUid}");
                return false;
            }

            data = JsonUtils.ParseJson<NsfRecordData>(decryptedBytes);
            return data != null;
        }

        private static byte[] TryDecryptKeeperNSFRecordKeyFromDetails(
            VaultOnline vault, Records.RecordData recordData, string recordUid)
        {
            if (vault.TryGetKeeperNSFRecord(recordUid, out var cached) && cached.RecordKey?.Length > 0)
            {
                return cached.RecordKey;
            }

            if (recordData.RecordKey == null || recordData.RecordKey.IsEmpty)
            {
                return null;
            }

            var encryptedKey = recordData.RecordKey.ToByteArray();
            var context = vault.Auth.AuthContext;
            byte[] recordKey = null;

            switch (recordData.RecordKeyType)
            {
                case Records.RecordKeyType.EncryptedByDataKey:
                    if (!CryptoUtils.TryDecryptAesV1(encryptedKey, context.DataKey, out recordKey))
                    {
                        Trace.TraceWarning($"KeeperNSF: AES v1 record key decrypt failed for {recordUid}");
                    }

                    break;
                case Records.RecordKeyType.EncryptedByDataKeyGcm:
                case Records.RecordKeyType.NoKey:
                    if (!CryptoUtils.TryDecryptAesV2(encryptedKey, context.DataKey, out recordKey))
                    {
                        Trace.TraceWarning($"KeeperNSF: AES v2 record key decrypt failed for {recordUid}");
                    }

                    break;
                case Records.RecordKeyType.EncryptedByPublicKey:
                    if (context.PrivateRsaKey != null
                        && !CryptoUtils.TryDecryptRsa(encryptedKey, context.PrivateRsaKey, out recordKey))
                    {
                        Trace.TraceWarning($"KeeperNSF: RSA record key decrypt failed for {recordUid}");
                    }

                    break;
                case Records.RecordKeyType.EncryptedByPublicKeyEcc:
                    if (context.PrivateEcKey != null
                        && !CryptoUtils.TryDecryptEc(encryptedKey, context.PrivateEcKey, out recordKey))
                    {
                        Trace.TraceWarning($"KeeperNSF: ECC record key decrypt failed for {recordUid}");
                    }

                    break;
            }

            if (recordKey != null && recordKey.Length > 0)
            {
                return recordKey;
            }

            foreach (var link in vault.Storage.KdRecordKeys.GetAllLinks()
                .Where(item => string.Equals(item.RecordUid, recordUid, StringComparison.Ordinal)))
            {
                if (string.IsNullOrEmpty(link.FolderUid)
                    || !vault.TryGetKeeperNSFFolder(link.FolderUid, out var folder)
                    || folder.FolderKey == null
                    || folder.FolderKey.Length == 0)
                {
                    continue;
                }

                if (CryptoUtils.TryDecryptSymmetric(encryptedKey, folder.FolderKey, out recordKey)
                    && recordKey.Length > 0)
                {
                    return recordKey;
                }
            }

            return null;
        }

        public static IList<KeeperNSFShortcutEntry> GetKeeperNSFShortcutsInternal(
            this VaultOnline vault, string recordUid = null, string folderUid = null)
        {
            var shortcuts = BuildShortcutMap(vault);
            var result = new List<KeeperNSFShortcutEntry>();

            IEnumerable<string> recordUids;
            if (!string.IsNullOrEmpty(recordUid))
            {
                if (!shortcuts.ContainsKey(recordUid))
                    return result;
                recordUids = new[] { recordUid };
            }
            else if (!string.IsNullOrEmpty(folderUid))
            {
                recordUids = shortcuts.Keys.Where(r => shortcuts[r].Contains(folderUid));
            }
            else
            {
                recordUids = shortcuts.Keys;
            }

            foreach (var rUid in recordUids.OrderBy(x => x))
            {
                var entry = new KeeperNSFShortcutEntry
                {
                    RecordUid = rUid,
                    Title = GetRecordTitle(vault, rUid),
                };
                foreach (var fUid in shortcuts[rUid].OrderBy(x => x))
                {
                    entry.Folders.Add(new KeeperNSFShortcutFolder
                    {
                        FolderUid = fUid,
                        Name = GetFolderName(vault, fUid),
                    });
                }
                result.Add(entry);
            }

            return result;
        }

        public static async Task<KeeperNSFShortcutKeepResult> KeepKeeperNSFRecordInFolderInternal(
            this VaultOnline vault, string recordUid, string keepFolderUid)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");
            if (string.IsNullOrEmpty(keepFolderUid))
                throw new VaultException("Folder UID to keep the record in cannot be empty");

            var shortcuts = BuildShortcutMap(vault);

            if (!shortcuts.TryGetValue(recordUid, out var folderSet))
                throw new VaultException($"Record '{recordUid}' does not appear in multiple folders");
            if (!folderSet.Contains(keepFolderUid))
                throw new VaultException($"Record '{recordUid}' is not in folder '{keepFolderUid}'");

            var foldersToRemove = folderSet.Where(f => f != keepFolderUid).ToList();
            if (foldersToRemove.Count == 0)
                throw new VaultException("Record is already in only one folder");

            var result = new KeeperNSFShortcutKeepResult
            {
                RecordUid = recordUid,
                KeptFolderUid = keepFolderUid,
                KeptFolderName = GetFolderName(vault, keepFolderUid),
            };

            var recordUidBytes = ByteString.CopyFrom(recordUid.Base64UrlDecode());
            var removalMetadata = new FolderProto.RecordMetadata
            {
                RecordUid = recordUidBytes,
                EncryptedRecordKey = ByteString.Empty,
                EncryptedRecordKeyType = FolderProto.EncryptedKeyType.NoKey,
            };

            foreach (var fUid in foldersToRemove)
            {
                var removal = new KeeperNSFShortcutRemoval
                {
                    FolderUid = fUid,
                    FolderName = GetFolderName(vault, fUid),
                };
                try
                {
                    var rq = new FolderProto.FolderRecordUpdateRequest
                    {
                        FolderUid = ByteString.CopyFrom(fUid.Base64UrlDecode()),
                    };
                    rq.RemoveRecords.Add(removalMetadata);

                    var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderRecordUpdateRequest,
                        FolderProto.FolderRecordUpdateResponse>(
                        "vault/folders/v3/record_update", rq);

                    var hasError = false;
                    foreach (var r in rs.FolderRecordUpdateResult)
                    {
                        if (r.Status != FolderProto.FolderModifyStatus.Success)
                        {
                            hasError = true;
                            removal.Message = r.Message;
                        }
                    }
                    removal.Success = !hasError;
                }
                catch (Exception ex)
                {
                    removal.Success = false;
                    removal.Message = ex.Message;
                }
                result.Removals.Add(removal);
            }

            return result;
        }
    }
}
