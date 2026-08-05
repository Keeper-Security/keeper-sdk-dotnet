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
                Label = field.Label,
                Value = field.Value?.Select(v => CoerceNsfFieldValue(field.Type, v)).ToArray(),
                ExtensionData = field.ExtensionData,
            };
        }

        private static NsfRecordData CloneNsfRecordData(NsfRecordData source)
        {
            if (source == null)
            {
                return new NsfRecordData { Fields = new List<NsfRecordFieldData>() };
            }

            return new NsfRecordData
            {
                Type = source.Type,
                Title = source.Title,
                Name = source.Name,
                Notes = source.Notes,
                ExtensionData = source.ExtensionData,
                Fields = source.Fields?
                    .Select(f => f == null
                        ? null
                        : new NsfRecordFieldData
                        {
                            Type = f.Type,
                            Label = f.Label,
                            Value = f.Value?.ToArray(),
                            ExtensionData = f.ExtensionData,
                        })
                    .Where(f => f != null)
                    .ToList()
                    ?? new List<NsfRecordFieldData>(),
            };
        }

        private static void SplitNsfFieldKey(string fieldKey, out string fieldType, out string fieldLabel)
        {
            fieldType = fieldKey ?? string.Empty;
            fieldLabel = null;
            if (string.IsNullOrEmpty(fieldKey))
            {
                return;
            }

            var separator = fieldKey.IndexOf(':');
            if (separator <= 0)
            {
                return;
            }

            fieldType = fieldKey.Substring(0, separator);
            fieldLabel = fieldKey.Substring(separator + 1);
        }

        private static NsfRecordFieldData FindNsfField(
            IList<NsfRecordFieldData> fields,
            string fieldType,
            string fieldLabel)
        {
            if (fields == null || string.IsNullOrEmpty(fieldType))
            {
                return null;
            }

            if (!string.IsNullOrEmpty(fieldLabel))
            {
                return fields.FirstOrDefault(f =>
                    string.Equals(f.Type, fieldType, StringComparison.Ordinal)
                    && string.Equals(f.Label ?? string.Empty, fieldLabel, StringComparison.OrdinalIgnoreCase));
            }

            return fields.FirstOrDefault(f =>
                string.Equals(f.Type, fieldType, StringComparison.Ordinal)
                && string.IsNullOrEmpty(f.Label));
        }

        private static void ApplyNsfFieldUpdates(NsfRecordData dataObj, IDictionary<string, object> fields)
        {
            if (dataObj == null || fields == null)
            {
                return;
            }

            if (dataObj.Fields == null)
            {
                dataObj.Fields = new List<NsfRecordFieldData>();
            }

            foreach (var kvp in fields)
            {
                if (kvp.Value == null || string.IsNullOrEmpty(kvp.Key))
                {
                    continue;
                }

                SplitNsfFieldKey(kvp.Key, out var fieldType, out var fieldLabel);
                if (string.IsNullOrEmpty(fieldType))
                {
                    continue;
                }

                var existing = FindNsfField(dataObj.Fields, fieldType, fieldLabel);
                if (existing != null)
                {
                    existing.Value = ToNsfFieldValues(fieldType, kvp.Value);
                    if (!string.IsNullOrEmpty(fieldLabel))
                    {
                        existing.Label = fieldLabel;
                    }
                }
                else
                {
                    dataObj.Fields.Add(new NsfRecordFieldData
                    {
                        Type = fieldType,
                        Label = string.IsNullOrEmpty(fieldLabel) ? null : fieldLabel,
                        Value = ToNsfFieldValues(fieldType, kvp.Value),
                    });
                }
            }
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

            ApplyNsfFieldUpdates(data, fields);
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

                await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, parentFolderUid)
                    .ConfigureAwait(false);
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

        private const int MaxKeeperNSFFoldersAddBatchSize = 100;

        /// <summary>
        /// Creates many NSF folders in chunks of 100. Used by IVault.CreateKeeperNSFFolders.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFFolderCreateResult>> CreateKeeperNSFFoldersInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderCreateRequest> folders)
        {
            if (folders == null || folders.Count == 0)
            {
                throw new ArgumentException("At least one folder is required.", nameof(folders));
            }

            for (var i = 0; i < folders.Count; i++)
            {
                if (folders[i] == null)
                {
                    throw new ArgumentException($"Folder at index {i} is null.", nameof(folders));
                }

                if (string.IsNullOrWhiteSpace(folders[i].Name))
                {
                    throw new ArgumentException($"Folder name cannot be empty (index {i}).", nameof(folders));
                }
            }

            var parentUids = folders
                .Select(f => f.ParentFolderUid?.Trim())
                .Where(uid => !string.IsNullOrEmpty(uid))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            foreach (var parentUid in parentUids)
            {
                if (!vault.TryGetKeeperNSFFolder(parentUid, out var parentFolder))
                {
                    throw new VaultException($"Parent Keeper NSF folder '{parentUid}' not found");
                }

                if (parentFolder.FolderKey == null || parentFolder.FolderKey.Length == 0)
                {
                    throw new VaultException($"Folder key not available for parent folder '{parentUid}'");
                }

                await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, parentUid)
                    .ConfigureAwait(false);
            }

            var prepared = new List<(KeeperNSFFolderCreateRequest Request, string FolderUid, Folder.FolderData FolderData)>(folders.Count);
            foreach (var request in folders)
            {
                var folderUid = BuildKeeperNSFFolderAdd(vault, request, out var folderData);
                prepared.Add((request, folderUid, folderData));
            }

            var results = new List<KeeperNSFFolderCreateResult>(folders.Count);
            for (var offset = 0; offset < prepared.Count; offset += MaxKeeperNSFFoldersAddBatchSize)
            {
                var chunk = prepared.Skip(offset).Take(MaxKeeperNSFFoldersAddBatchSize).ToList();
                var chunkResults = await ExecuteKeeperNSFFoldersAddBatchAsync(vault, chunk).ConfigureAwait(false);
                results.AddRange(chunkResults);
            }

            return results;
        }

        // builds encrypted folder payload + new UID for one create item
        private static string BuildKeeperNSFFolderAdd(
            VaultOnline vault,
            KeeperNSFFolderCreateRequest request,
            out Folder.FolderData folderData)
        {
            var folderName = request.Name.Trim();
            var parentFolderUid = string.IsNullOrWhiteSpace(request.ParentFolderUid)
                ? null
                : request.ParentFolderUid.Trim();

            var folderUid = CryptoUtils.GenerateUid();
            var folderKey = CryptoUtils.GenerateEncryptionKey();

            var encryptionKey = vault.Auth.AuthContext.DataKey;
            if (!string.IsNullOrEmpty(parentFolderUid)
                && vault.TryGetKeeperNSFFolder(parentFolderUid, out var parentFolder)
                && parentFolder.FolderKey != null)
            {
                encryptionKey = parentFolder.FolderKey;
            }

            var folderDataJson = new FolderDataJson { name = folderName };
            if (!string.IsNullOrEmpty(request.Color) && request.Color != "none")
            {
                folderDataJson.color = request.Color;
            }

            var dataJson = JsonUtils.DumpJson(folderDataJson, false);
            var encryptedData = CryptoUtils.EncryptAesV2(dataJson, folderKey);
            var encryptedFolderKey = CryptoUtils.EncryptAesV2(folderKey, encryptionKey);

            folderData = new Folder.FolderData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                Data = ByteString.CopyFrom(encryptedData),
                FolderKey = ByteString.CopyFrom(encryptedFolderKey),
                Type = Folder.FolderUsageType.UtNormal,
                InheritUserPermissions = request.InheritPermissions
                    ? Folder.SetBooleanValue.BooleanTrue
                    : Folder.SetBooleanValue.BooleanFalse,
            };

            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                folderData.ParentUid = ByteString.CopyFrom(parentFolderUid.Base64UrlDecode());
            }

            return folderUid;
        }

        // posts one folder-add chunk and maps server status to results
        private static async Task<IReadOnlyList<KeeperNSFFolderCreateResult>> ExecuteKeeperNSFFoldersAddBatchAsync(
            VaultOnline vault,
            IReadOnlyList<(KeeperNSFFolderCreateRequest Request, string FolderUid, Folder.FolderData FolderData)> batch)
        {
            var rq = new Folder.FolderAddRequest();
            foreach (var item in batch)
            {
                rq.FolderData.Add(item.FolderData);
            }

            var response = await vault.Auth
                .ExecuteAuthRest<Folder.FolderAddRequest, Folder.FolderAddResponse>("vault/folders/v3/add", rq)
                .ConfigureAwait(false);

            var statusByUid = new Dictionary<string, Folder.FolderModifyResult>(StringComparer.Ordinal);
            if (response?.FolderAddResults != null)
            {
                foreach (var status in response.FolderAddResults)
                {
                    if (status?.FolderUid == null || status.FolderUid.IsEmpty)
                    {
                        continue;
                    }

                    statusByUid[CryptoUtils.Base64UrlEncode(status.FolderUid.ToByteArray())] = status;
                }
            }

            var results = new List<KeeperNSFFolderCreateResult>(batch.Count);
            for (var i = 0; i < batch.Count; i++)
            {
                var item = batch[i];
                var parentUid = string.IsNullOrWhiteSpace(item.Request.ParentFolderUid)
                    ? null
                    : item.Request.ParentFolderUid.Trim();

                if (!statusByUid.TryGetValue(item.FolderUid, out var status)
                    && i < (response?.FolderAddResults?.Count ?? 0))
                {
                    status = response.FolderAddResults[i];
                }

                if (status == null)
                {
                    results.Add(new KeeperNSFFolderCreateResult
                    {
                        FolderUid = item.FolderUid,
                        Name = item.Request.Name?.Trim(),
                        ParentFolderUid = parentUid,
                        Status = "missing",
                        Message = "Server returned no status for this folder.",
                        Success = false,
                    });
                    continue;
                }

                results.Add(new KeeperNSFFolderCreateResult
                {
                    FolderUid = item.FolderUid,
                    Name = item.Request.Name?.Trim(),
                    ParentFolderUid = parentUid,
                    Status = FormatFolderModifyStatus(status.Status),
                    Message = status.Message,
                    Success = status.Status == Folder.FolderModifyStatus.Success,
                });
            }

            return results;
        }

        private static string FormatFolderModifyStatus(Folder.FolderModifyStatus status)
        {
            return Enum.GetName(typeof(Folder.FolderModifyStatus), status) ?? status.ToString();
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

        private static bool FolderInheritsParentPermissions(VaultOnline vault, string folderUid)
        {
            string parentUid = null;
            if (vault.TryGetKeeperNSFFolder(folderUid, out var node))
            {
                parentUid = node.ParentUid;
            }

            var row = vault.Storage.KdFolders.GetEntity(folderUid);
            if (string.IsNullOrEmpty(parentUid) && row != null)
            {
                parentUid = row.ParentUid;
            }

            if (string.IsNullOrEmpty(parentUid)
                || parentUid == KeeperNSFConstants.KeeperDriveRootFolderUid)
            {
                return false;
            }

            if (row == null)
            {
                return true;
            }

            return row.InheritPermissions != (int)FolderProto.SetBooleanValue.BooleanFalse;
        }

        private static async Task EnsureKeeperNSFFolderDirectPermissionsAsync(
            VaultOnline vault, string folderUid)
        {
            if (!FolderInheritsParentPermissions(vault, folderUid))
            {
                return;
            }

            System.Diagnostics.Trace.TraceInformation(
                $"KeeperNSF: Disabled folder inheritance for '{folderUid}' to apply direct permissions.");

            var updateResult = await vault.UpdateKeeperNSFFolderCore(
                folderUid, null, null, inheritPermissions: false, requestSync: false).ConfigureAwait(false);
            VaultOnline.ValidateFolderModifyResult(updateResult);
        }

        private static async Task PrepareKeeperNSFFolderForAccessChangeAsync(
            VaultOnline vault, string folderUid)
        {
            await EnsureKeeperNSFFolderDirectPermissionsAsync(vault, folderUid).ConfigureAwait(false);
        }

        public static async Task GrantKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string accessor, string role, SharedFolderUserOptions options = null, bool? asTeam = null)
        {
            if (string.IsNullOrEmpty(folderUid))
                throw new VaultException("Folder UID cannot be empty");
            if (string.IsNullOrEmpty(accessor))
                throw new VaultException("User or team identifier cannot be empty");

            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            await KeeperNSFAccessHelpers.RequireKeeperNSFFolderSharePermissionAsync(vault, folderUid)
                .ConfigureAwait(false);

            await PrepareKeeperNSFFolderForAccessChangeAsync(vault, folderUid).ConfigureAwait(false);

            NsfShareRecipient recipient;
            if (asTeam.HasValue)
            {
                if (asTeam.Value)
                {
                    var teamUid = await NsfShareRecipientHelper.ResolveTeamUidAsync(vault.Auth, accessor)
                        .ConfigureAwait(false);
                    recipient = new NsfShareRecipient(NsfShareRecipientKind.Team, teamUid);
                }
                else
                {
                    recipient = new NsfShareRecipient(NsfShareRecipientKind.User, accessor.Trim().ToLowerInvariant());
                }
            }
            else
            {
                var classified = await NsfShareRecipientHelper.ClassifyShareRecipientAsync(vault, accessor)
                    .ConfigureAwait(false);
                if (!classified.HasValue)
                {
                    throw new VaultException($"User or team \"{accessor}\" could not be resolved.");
                }

                recipient = classified.Value;
            }

            if (recipient.Kind == NsfShareRecipientKind.Team)
            {
                await GrantKeeperNSFFolderAccessToTeam(vault, folderUid, recipient.Identifier, role, options)
                    .ConfigureAwait(false);
            }
            else
            {
                await GrantKeeperNSFFolderAccessToUser(vault, folderUid, recipient.Identifier, role, options)
                    .ConfigureAwait(false);
            }
        }

        private static async Task GrantKeeperNSFFolderAccessToUser(this VaultOnline vault, string folderUid, string userEmail, string role, SharedFolderUserOptions options = null)
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
                var accessors = await KeeperNSFAccessHelpers.FetchFolderAccessDataAsync(vault, folderUid)
                    .ConfigureAwait(false);
                existingAccess = accessors.FirstOrDefault(accessor =>
                    accessor.AccessType == FolderProto.AccessType.AtUser
                    && accessor.AccessTypeUid.Equals(pkRs.AccountUid));
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

        private static async Task GrantKeeperNSFFolderAccessToTeam(this VaultOnline vault, string folderUid, string teamNameOrUid, string role, SharedFolderUserOptions options = null)
        {
            if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            var teamUid = await NsfShareRecipientHelper.ResolveTeamUidAsync(vault.Auth, teamNameOrUid)
                .ConfigureAwait(false);
            var teamUidBytes = ByteString.CopyFrom(teamUid.Base64UrlDecode());

            var folderKey = folder.FolderKey;
            if (folderKey == null)
                throw new VaultException($"Cannot share folder: folder key is not available for '{folderUid}'");

            var accessRole = ResolveAccessRole(role);
            var folderUidBytes = ByteString.CopyFrom(folderUid.Base64UrlDecode());
            var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(options);

            FolderProto.FolderAccessData existingAccess = null;
            try
            {
                var accessors = await KeeperNSFAccessHelpers.FetchFolderAccessDataAsync(vault, folderUid)
                    .ConfigureAwait(false);
                existingAccess = accessors.FirstOrDefault(accessor =>
                    accessor.AccessType == FolderProto.AccessType.AtTeam
                    && accessor.AccessTypeUid.Equals(teamUidBytes));
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
                    AccessTypeUid = teamUidBytes,
                    AccessType = FolderProto.AccessType.AtTeam,
                    AccessRoleType = accessRole,
                };
                if (tlaProperties != null)
                    updateData.TlaProperties = tlaProperties;
                rq.FolderAccessUpdates.Add(updateData);
            }
            else
            {
                var teamKeys = await vault.Auth.GetTeamKeysForSharingAsync(teamUid).ConfigureAwait(false);
                var (encryptedFolderKey, keyType) = NsfShareRecipientHelper.EncryptFolderKeyForTeam(
                    folderKey, teamKeys, vault.Auth.AuthContext.ForbidKeyType2);

                var addData = new FolderProto.FolderAccessData
                {
                    FolderUid = folderUidBytes,
                    AccessTypeUid = teamUidBytes,
                    AccessType = FolderProto.AccessType.AtTeam,
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
                "vault/folders/v3/access_update", rq).ConfigureAwait(false);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    var action = existingAccess != null ? "update" : "grant";
                    throw new VaultException($"Failed to {action} access: {result.Message}");
                }
            }
        }

        public static async Task RevokeKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string accessor, bool? asTeam = null)
        {
            if (string.IsNullOrEmpty(folderUid))
                throw new VaultException("Folder UID cannot be empty");
            if (string.IsNullOrEmpty(accessor))
                throw new VaultException("User or team identifier cannot be empty");

            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            await KeeperNSFAccessHelpers.RequireKeeperNSFFolderSharePermissionAsync(vault, folderUid)
                .ConfigureAwait(false);

            await PrepareKeeperNSFFolderForAccessChangeAsync(vault, folderUid).ConfigureAwait(false);

            NsfShareRecipient recipient;
            if (asTeam.HasValue)
            {
                if (asTeam.Value)
                {
                    var teamUid = await NsfShareRecipientHelper.ResolveTeamUidAsync(vault.Auth, accessor)
                        .ConfigureAwait(false);
                    recipient = new NsfShareRecipient(NsfShareRecipientKind.Team, teamUid);
                }
                else
                {
                    recipient = new NsfShareRecipient(NsfShareRecipientKind.User, accessor.Trim().ToLowerInvariant());
                }
            }
            else
            {
                var classified = await NsfShareRecipientHelper.ClassifyShareRecipientAsync(vault, accessor)
                    .ConfigureAwait(false);
                if (!classified.HasValue)
                {
                    throw new VaultException($"User or team \"{accessor}\" could not be resolved.");
                }

                recipient = classified.Value;
            }

            if (recipient.Kind == NsfShareRecipientKind.Team)
            {
                await RevokeKeeperNSFFolderAccessFromTeam(vault, folderUid, recipient.Identifier).ConfigureAwait(false);
            }
            else
            {
                await RevokeKeeperNSFFolderAccessFromUser(vault, folderUid, recipient.Identifier).ConfigureAwait(false);
            }
        }

        private static async Task RevokeKeeperNSFFolderAccessFromUser(this VaultOnline vault, string folderUid, string userEmail)
        {
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

        private static async Task RevokeKeeperNSFFolderAccessFromTeam(this VaultOnline vault, string folderUid, string teamNameOrUid)
        {
            var teamUid = await NsfShareRecipientHelper.ResolveTeamUidAsync(vault.Auth, teamNameOrUid)
                .ConfigureAwait(false);
            var accessData = new FolderProto.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
                AccessType = FolderProto.AccessType.AtTeam,
            };

            var rq = new FolderProto.FolderAccessRequest();
            rq.FolderAccessRemoves.Add(accessData);

            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq).ConfigureAwait(false);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to revoke access: {result.Message}");
                }
            }
        }

        // max grant/update/revoke entries per access_update request
        private const int MaxKeeperNSFFolderAccessBatchSize = 500;

        /// <summary>
        /// Grants folder access in batches of 500. Used by IVault.GrantKeeperNSFFolderAccesses.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFFolderAccessResult>> GrantKeeperNSFFolderAccessesInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessGrantRequest> grants)
        {
            if (grants == null || grants.Count == 0)
            {
                throw new ArgumentException("At least one folder access grant is required.", nameof(grants));
            }

            for (var i = 0; i < grants.Count; i++)
            {
                if (grants[i] == null)
                {
                    throw new ArgumentException($"Grant at index {i} is null.", nameof(grants));
                }
            }

            var results = new KeeperNSFFolderAccessResult[grants.Count];
            var context = await BuildFolderAccessBatchContextAsync(
                vault,
                grants.Select(g => (g.FolderUid, g.Accessor, g.AsTeam)).ToList()).ConfigureAwait(false);

            var prepared = new List<(int Index, FolderProto.FolderAccessData Data, string FolderUid, string AccessUidB64)>();
            var seenResolved = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < grants.Count; i++)
            {
                var request = grants[i];
                var folderUid = request.FolderUid?.Trim();
                var accessor = request.Accessor?.Trim();
                var role = string.IsNullOrWhiteSpace(request.Role) ? "viewer" : request.Role.Trim();

                results[i] = new KeeperNSFFolderAccessResult
                {
                    FolderUid = folderUid,
                    Accessor = accessor,
                    Role = role,
                    Success = false,
                };

                if (string.IsNullOrEmpty(folderUid))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Folder UID cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(accessor))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Accessor cannot be empty.";
                    continue;
                }

                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF folder '{folderUid}' not found.";
                    continue;
                }

                if (context.ShareDeniedByUid.TryGetValue(folderUid, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (folder.FolderKey == null || folder.FolderKey.Length == 0)
                {
                    results[i].Status = "missing_key";
                    results[i].Message = $"Folder key is not available for '{folderUid}'.";
                    continue;
                }

                if (folder.FolderKey.Length != 32)
                {
                    results[i].Status = "invalid_key";
                    results[i].Message =
                        $"Folder key for '{folderUid}' has invalid length {folder.FolderKey.Length}; expected 32 bytes.";
                    continue;
                }

                if (!TryResolveFolderAccessRecipient(
                        context, folderUid, accessor, request.AsTeam, results[i], out var recipient, out var accessTypeUid,
                        requirePublicKey: true))
                {
                    continue;
                }

                results[i].AccessType = recipient.Kind == NsfShareRecipientKind.Team ? "team" : "user";
                var accessUidB64 = CryptoUtils.Base64UrlEncode(accessTypeUid.ToByteArray());
                var resolvedDupKey = BuildFolderAccessLookupKey(folder.FolderUid, recipient.Kind, accessUidB64);
                if (!seenResolved.Add(resolvedDupKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message = $"Duplicate grant for folder '{folderUid}' and accessor '{accessor}'.";
                    continue;
                }

                if (!TryEnsureExistingAccessLookup(context, folder.FolderUid, results[i]))
                {
                    continue;
                }

                if (context.ExistingAccessKeys.Contains(resolvedDupKey))
                {
                    results[i].Status = "already_exists";
                    results[i].Message =
                        $"Access already exists for '{accessor}' on folder '{folderUid}'. Use UpdateKeeperNSFFolderAccesses to change role or expiration.";
                    continue;
                }

                FolderProto.AccessRoleType accessRole;
                try
                {
                    accessRole = ResolveAccessRole(role);
                }
                catch (Exception ex)
                {
                    results[i].Status = "invalid_role";
                    results[i].Message = ex.Message;
                    continue;
                }

                results[i].Role = GetRoleLabel((int)accessRole);

                try
                {
                    var folderUidBytes = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode());
                    var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(request.Options);
                    FolderProto.EncryptedDataKey folderKey;
                    if (recipient.Kind == NsfShareRecipientKind.Team)
                    {
                        if (!context.TeamKeysByUid.TryGetValue(recipient.Identifier, out var teamKeys) || teamKeys == null)
                        {
                            results[i].Status = "team_key_error";
                            results[i].Message = $"Team keys are not available for '{accessor}'.";
                            continue;
                        }

                        var (encryptedFolderKey, keyType) = NsfShareRecipientHelper.EncryptFolderKeyForTeam(
                            folder.FolderKey, teamKeys, vault.Auth.AuthContext.ForbidKeyType2);
                        folderKey = new FolderProto.EncryptedDataKey
                        {
                            EncryptedKey = ByteString.CopyFrom(encryptedFolderKey),
                            EncryptedKeyType = keyType,
                        };
                    }
                    else
                    {
                        if (!context.PublicKeysByEmail.TryGetValue(recipient.Identifier, out var pkRs) || pkRs == null)
                        {
                            results[i].Status = "user_not_found";
                            results[i].Message = $"User '{accessor}' not found or has no public key.";
                            continue;
                        }

                        folderKey = EncryptFolderKeyForUser(folder.FolderKey, pkRs, vault.Auth.AuthContext.ForbidKeyType2);
                    }

                    var addData = new FolderProto.FolderAccessData
                    {
                        FolderUid = folderUidBytes,
                        AccessTypeUid = accessTypeUid,
                        AccessType = recipient.Kind == NsfShareRecipientKind.Team
                            ? FolderProto.AccessType.AtTeam
                            : FolderProto.AccessType.AtUser,
                        AccessRoleType = accessRole,
                        FolderKey = folderKey,
                    };
                    if (tlaProperties != null)
                    {
                        addData.TlaProperties = tlaProperties;
                    }

                    prepared.Add((i, addData, folder.FolderUid, accessUidB64));
                }
                catch (Exception ex)
                {
                    results[i].Status = "prepare_failed";
                    results[i].Message = ex.Message;
                }
            }

            var prepareFailed = await PrepareFoldersForAccessChangeAsync(
                vault, prepared.Select(p => p.FolderUid)).ConfigureAwait(false);
            RemovePrepareFailedEntries(prepared, results, prepareFailed);

            await SendFolderAccessBatchesAsync(
                vault,
                prepared,
                results,
                (rq, data) => rq.FolderAccessAdds.Add(data)).ConfigureAwait(false);

            return results;
        }

        /// <summary>
        /// Updates folder access in batches of 500. Used by IVault.UpdateKeeperNSFFolderAccesses.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFFolderAccessResult>> UpdateKeeperNSFFolderAccessesInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessUpdateRequest> updates)
        {
            if (updates == null || updates.Count == 0)
            {
                throw new ArgumentException("At least one folder access update is required.", nameof(updates));
            }

            for (var i = 0; i < updates.Count; i++)
            {
                if (updates[i] == null)
                {
                    throw new ArgumentException($"Update at index {i} is null.", nameof(updates));
                }
            }

            var results = new KeeperNSFFolderAccessResult[updates.Count];
            var context = await BuildFolderAccessBatchContextAsync(
                vault,
                updates.Select(u => (u.FolderUid, u.Accessor, u.AsTeam)).ToList()).ConfigureAwait(false);

            var prepared = new List<(int Index, FolderProto.FolderAccessData Data, string FolderUid, string AccessUidB64)>();
            var seenResolved = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < updates.Count; i++)
            {
                var request = updates[i];
                var folderUid = request.FolderUid?.Trim();
                var accessor = request.Accessor?.Trim();
                var role = request.Role?.Trim();

                results[i] = new KeeperNSFFolderAccessResult
                {
                    FolderUid = folderUid,
                    Accessor = accessor,
                    Role = role,
                    Success = false,
                };

                if (string.IsNullOrEmpty(folderUid))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Folder UID cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(accessor))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Accessor cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(role) && request.Options == null)
                {
                    results[i].Status = "invalid";
                    results[i].Message = "At least one of role or options is required for an access update.";
                    continue;
                }

                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF folder '{folderUid}' not found.";
                    continue;
                }

                if (context.ShareDeniedByUid.TryGetValue(folderUid, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (!TryResolveFolderAccessRecipient(
                        context, folderUid, accessor, request.AsTeam, results[i], out var recipient, out var accessTypeUid))
                {
                    continue;
                }

                results[i].AccessType = recipient.Kind == NsfShareRecipientKind.Team ? "team" : "user";
                var accessUidB64 = CryptoUtils.Base64UrlEncode(accessTypeUid.ToByteArray());
                var resolvedDupKey = BuildFolderAccessLookupKey(folder.FolderUid, recipient.Kind, accessUidB64);
                if (!seenResolved.Add(resolvedDupKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message = $"Duplicate update for folder '{folderUid}' and accessor '{accessor}'.";
                    continue;
                }

                if (!TryEnsureExistingAccessLookup(context, folder.FolderUid, results[i]))
                {
                    continue;
                }

                if (!context.ExistingAccessKeys.Contains(resolvedDupKey))
                {
                    results[i].Status = "not_found";
                    results[i].Message =
                        $"No existing access for '{accessor}' on folder '{folderUid}'. Use GrantKeeperNSFFolderAccesses to share first.";
                    continue;
                }

                FolderProto.AccessRoleType accessRole;
                try
                {
                    accessRole = string.IsNullOrEmpty(role)
                        ? context.ExistingAccessRoles.TryGetValue(resolvedDupKey, out var existingRole)
                            ? existingRole
                            : FolderProto.AccessRoleType.Viewer
                        : ResolveAccessRole(role);
                }
                catch (Exception ex)
                {
                    results[i].Status = "invalid_role";
                    results[i].Message = ex.Message;
                    continue;
                }

                results[i].Role = GetRoleLabel((int)accessRole);

                try
                {
                    var updateData = new FolderProto.FolderAccessData
                    {
                        FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                        AccessTypeUid = accessTypeUid,
                        AccessType = recipient.Kind == NsfShareRecipientKind.Team
                            ? FolderProto.AccessType.AtTeam
                            : FolderProto.AccessType.AtUser,
                        AccessRoleType = accessRole,
                    };
                    var tlaProperties = VaultShareExpirationExtensions.CreateNsfTlaProperties(request.Options);
                    if (tlaProperties != null)
                    {
                        updateData.TlaProperties = tlaProperties;
                    }

                    prepared.Add((i, updateData, folder.FolderUid, accessUidB64));
                }
                catch (Exception ex)
                {
                    results[i].Status = "prepare_failed";
                    results[i].Message = ex.Message;
                }
            }

            var prepareFailed = await PrepareFoldersForAccessChangeAsync(
                vault, prepared.Select(p => p.FolderUid)).ConfigureAwait(false);
            RemovePrepareFailedEntries(prepared, results, prepareFailed);

            await SendFolderAccessBatchesAsync(
                vault,
                prepared,
                results,
                (rq, data) => rq.FolderAccessUpdates.Add(data)).ConfigureAwait(false);

            return results;
        }

        /// <summary>
        /// Revokes folder access in batches of 500. Used by IVault.RevokeKeeperNSFFolderAccesses.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFFolderAccessResult>> RevokeKeeperNSFFolderAccessesInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessRevokeRequest> revokes)
        {
            if (revokes == null || revokes.Count == 0)
            {
                throw new ArgumentException("At least one folder access revoke is required.", nameof(revokes));
            }

            for (var i = 0; i < revokes.Count; i++)
            {
                if (revokes[i] == null)
                {
                    throw new ArgumentException($"Revoke at index {i} is null.", nameof(revokes));
                }
            }

            var results = new KeeperNSFFolderAccessResult[revokes.Count];
            var context = await BuildFolderAccessBatchContextAsync(
                vault,
                revokes.Select(r => (r.FolderUid, r.Accessor, r.AsTeam)).ToList(),
                fetchExistingAccess: false).ConfigureAwait(false);

            var prepared = new List<(int Index, FolderProto.FolderAccessData Data, string FolderUid, string AccessUidB64)>();
            var seenResolved = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < revokes.Count; i++)
            {
                var request = revokes[i];
                var folderUid = request.FolderUid?.Trim();
                var accessor = request.Accessor?.Trim();

                results[i] = new KeeperNSFFolderAccessResult
                {
                    FolderUid = folderUid,
                    Accessor = accessor,
                    Success = false,
                };

                if (string.IsNullOrEmpty(folderUid))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Folder UID cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(accessor))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Accessor cannot be empty.";
                    continue;
                }

                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF folder '{folderUid}' not found.";
                    continue;
                }

                if (context.ShareDeniedByUid.TryGetValue(folderUid, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (!TryResolveFolderAccessRecipient(
                        context, folderUid, accessor, request.AsTeam, results[i], out var recipient, out var accessTypeUid))
                {
                    continue;
                }

                results[i].AccessType = recipient.Kind == NsfShareRecipientKind.Team ? "team" : "user";
                var accessUidB64 = CryptoUtils.Base64UrlEncode(accessTypeUid.ToByteArray());
                var resolvedDupKey = BuildFolderAccessLookupKey(folder.FolderUid, recipient.Kind, accessUidB64);
                if (!seenResolved.Add(resolvedDupKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message = $"Duplicate revoke for folder '{folderUid}' and accessor '{accessor}'.";
                    continue;
                }

                var removeData = new FolderProto.FolderAccessData
                {
                    FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                    AccessTypeUid = accessTypeUid,
                    AccessType = recipient.Kind == NsfShareRecipientKind.Team
                        ? FolderProto.AccessType.AtTeam
                        : FolderProto.AccessType.AtUser,
                };
                prepared.Add((i, removeData, folder.FolderUid, accessUidB64));
            }

            var prepareFailed = await PrepareFoldersForAccessChangeAsync(
                vault, prepared.Select(p => p.FolderUid)).ConfigureAwait(false);
            RemovePrepareFailedEntries(prepared, results, prepareFailed);

            await SendFolderAccessBatchesAsync(
                vault,
                prepared,
                results,
                (rq, data) => rq.FolderAccessRemoves.Add(data)).ConfigureAwait(false);

            return results;
        }

        // holds keys, recipients, and existing ACLs while preparing a folder-access batch
        private sealed class FolderAccessBatchContext
        {
            public IReadOnlyDictionary<string, string> ShareDeniedByUid { get; set; }
            public Dictionary<string, AuthProto.PublicKeyResponse> PublicKeysByEmail { get; set; }
            public Dictionary<string, UserKeys> TeamKeysByUid { get; set; }
            public Dictionary<string, NsfShareRecipient> RecipientsByAccessorKey { get; set; }
            public HashSet<string> ExistingAccessKeys { get; set; }
            public Dictionary<string, FolderProto.AccessRoleType> ExistingAccessRoles { get; set; }
            public bool ExistingAccessLookupSucceeded { get; set; } = true;
            public string ExistingAccessLookupFailureMessage { get; set; }
            public Dictionary<string, string> ExistingAccessLookupErrorsByFolderUid { get; set; }
        }

        // loads share perms, keys, recipients, and existing access for the batch
        private static async Task<FolderAccessBatchContext> BuildFolderAccessBatchContextAsync(
            VaultOnline vault,
            IReadOnlyList<(string FolderUid, string Accessor, bool? AsTeam)> items,
            bool fetchExistingAccess = true)
        {
            var folderUids = items
                .Select(i => i.FolderUid?.Trim())
                .Where(uid => !string.IsNullOrEmpty(uid) && vault.TryGetKeeperNSFFolder(uid, out _))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var shareDeniedByUid = await KeeperNSFAccessHelpers
                .EvaluateKeeperNSFFolderSharePermissionsAsync(vault, folderUids)
                .ConfigureAwait(false);

            var allowedFolderUids = folderUids
                .Where(uid => !shareDeniedByUid.ContainsKey(uid))
                .ToList();

            var recipientsByAccessorKey = new Dictionary<string, NsfShareRecipient>(StringComparer.OrdinalIgnoreCase);
            var emails = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var teamUids = new HashSet<string>(StringComparer.Ordinal);

            foreach (var item in items)
            {
                var accessor = item.Accessor?.Trim();
                if (string.IsNullOrEmpty(accessor))
                {
                    continue;
                }

                var key = BuildAccessorResolveKey(accessor, item.AsTeam);
                if (recipientsByAccessorKey.ContainsKey(key))
                {
                    continue;
                }

                try
                {
                    NsfShareRecipient recipient;
                    if (item.AsTeam.HasValue)
                    {
                        if (item.AsTeam.Value)
                        {
                            var teamUid = await NsfShareRecipientHelper.ResolveTeamUidAsync(vault.Auth, accessor)
                                .ConfigureAwait(false);
                            recipient = new NsfShareRecipient(NsfShareRecipientKind.Team, teamUid);
                        }
                        else
                        {
                            recipient = new NsfShareRecipient(NsfShareRecipientKind.User, accessor.ToLowerInvariant());
                        }
                    }
                    else
                    {
                        var classified = await NsfShareRecipientHelper.ClassifyShareRecipientAsync(vault, accessor)
                            .ConfigureAwait(false);
                        if (!classified.HasValue)
                        {
                            continue;
                        }

                        recipient = classified.Value;
                    }

                    recipientsByAccessorKey[key] = recipient;
                    if (recipient.Kind == NsfShareRecipientKind.Team)
                    {
                        teamUids.Add(recipient.Identifier);
                    }
                    else
                    {
                        emails.Add(recipient.Identifier);
                    }
                }
                catch
                {
                    // Per-item resolve errors are reported during prepare.
                }
            }

            var publicKeysByEmail = await ResolveKeeperNSFPublicKeysAsync(vault, emails.ToList()).ConfigureAwait(false);
            var teamKeysByUid = new Dictionary<string, UserKeys>(StringComparer.Ordinal);
            foreach (var teamUid in teamUids)
            {
                try
                {
                    teamKeysByUid[teamUid] = await vault.Auth.GetTeamKeysForSharingAsync(teamUid).ConfigureAwait(false);
                }
                catch
                {
                    teamKeysByUid[teamUid] = null;
                }
            }

            var existingAccessKeys = new HashSet<string>(StringComparer.Ordinal);
            var existingAccessRoles = new Dictionary<string, FolderProto.AccessRoleType>(StringComparer.Ordinal);
            var existingAccessLookupErrors = new Dictionary<string, string>(StringComparer.Ordinal);
            var existingAccessLookupSucceeded = true;
            string existingAccessLookupFailureMessage = null;

            if (fetchExistingAccess && allowedFolderUids.Count > 0)
            {
                try
                {
                    var accessors = await KeeperNSFAccessHelpers
                        .FetchFolderAccessDataAsync(vault, allowedFolderUids, pageSize: 100, existingAccessLookupErrors)
                        .ConfigureAwait(false);
                    foreach (var access in accessors)
                    {
                        if (access?.FolderUid == null || access.FolderUid.IsEmpty
                            || access.AccessTypeUid == null || access.AccessTypeUid.IsEmpty)
                        {
                            continue;
                        }

                        var folderUid = CryptoUtils.Base64UrlEncode(access.FolderUid.ToByteArray());
                        var accessUid = CryptoUtils.Base64UrlEncode(access.AccessTypeUid.ToByteArray());
                        var kind = access.AccessType == FolderProto.AccessType.AtTeam
                            ? NsfShareRecipientKind.Team
                            : NsfShareRecipientKind.User;
                        var lookupKey = BuildFolderAccessLookupKey(folderUid, kind, accessUid);
                        existingAccessKeys.Add(lookupKey);
                        existingAccessRoles[lookupKey] = access.AccessRoleType;
                    }
                }
                catch (Exception ex)
                {
                    existingAccessLookupSucceeded = false;
                    existingAccessLookupFailureMessage =
                        $"Could not look up existing folder access: {ex.Message}";
                    Trace.TraceWarning($"KeeperNSF: {existingAccessLookupFailureMessage}");
                }
            }

            return new FolderAccessBatchContext
            {
                ShareDeniedByUid = shareDeniedByUid,
                PublicKeysByEmail = publicKeysByEmail,
                TeamKeysByUid = teamKeysByUid,
                RecipientsByAccessorKey = recipientsByAccessorKey,
                ExistingAccessKeys = existingAccessKeys,
                ExistingAccessRoles = existingAccessRoles,
                ExistingAccessLookupSucceeded = existingAccessLookupSucceeded,
                ExistingAccessLookupFailureMessage = existingAccessLookupFailureMessage,
                ExistingAccessLookupErrorsByFolderUid = existingAccessLookupErrors,
            };
        }

        // marks the item failed if we couldn't load existing ACL
        private static bool TryEnsureExistingAccessLookup(
            FolderAccessBatchContext context,
            string folderUid,
            KeeperNSFFolderAccessResult result)
        {
            if (!context.ExistingAccessLookupSucceeded)
            {
                result.Status = "lookup_failed";
                result.Message = context.ExistingAccessLookupFailureMessage
                    ?? "Could not look up existing folder access.";
                return false;
            }

            if (context.ExistingAccessLookupErrorsByFolderUid != null
                && context.ExistingAccessLookupErrorsByFolderUid.TryGetValue(folderUid, out var lookupError))
            {
                result.Status = "lookup_failed";
                result.Message = lookupError;
                return false;
            }

            return true;
        }

        // resolves user/team accessor and gets the key/uid needed for the share
        private static bool TryResolveFolderAccessRecipient(
            FolderAccessBatchContext context,
            string folderUid,
            string accessor,
            bool? asTeam,
            KeeperNSFFolderAccessResult result,
            out NsfShareRecipient recipient,
            out ByteString accessTypeUid,
            bool requirePublicKey = false)
        {
            recipient = default;
            accessTypeUid = null;

            var key = BuildAccessorResolveKey(accessor, asTeam);
            if (!context.RecipientsByAccessorKey.TryGetValue(key, out recipient))
            {
                result.Status = "recipient_not_found";
                result.Message = $"User or team \"{accessor}\" could not be resolved.";
                return false;
            }

            if (recipient.Kind == NsfShareRecipientKind.Team)
            {
                accessTypeUid = ByteString.CopyFrom(recipient.Identifier.Base64UrlDecode());
                return true;
            }

            if (!context.PublicKeysByEmail.TryGetValue(recipient.Identifier, out var pkRs)
                || pkRs == null
                || pkRs.AccountUid.IsEmpty)
            {
                result.Status = "user_not_found";
                result.Message = $"User '{accessor}' not found.";
                return false;
            }

            if (requirePublicKey && pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
            {
                result.Status = "public_key_error";
                result.Message = string.IsNullOrEmpty(pkRs.Message)
                    ? $"User '{accessor}' has no public key."
                    : pkRs.Message;
                return false;
            }

            accessTypeUid = pkRs.AccountUid;
            return true;
        }

        private static string BuildAccessorResolveKey(string accessor, bool? asTeam)
            => $"{accessor}|{asTeam?.ToString() ?? "auto"}";

        private static string BuildFolderAccessLookupKey(
            string folderUid, NsfShareRecipientKind kind, string accessUidB64)
            => $"{folderUid}|{(kind == NsfShareRecipientKind.Team ? "team" : "user")}|{accessUidB64}";

        private static async Task<Dictionary<string, string>> PrepareFoldersForAccessChangeAsync(
            VaultOnline vault, IEnumerable<string> folderUids)
        {
            var failed = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var folderUid in folderUids.Distinct(StringComparer.Ordinal))
            {
                try
                {
                    await PrepareKeeperNSFFolderForAccessChangeAsync(vault, folderUid).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    failed[folderUid] = ex.Message;
                }
            }

            return failed;
        }

        private static void RemovePrepareFailedEntries(
            List<(int Index, FolderProto.FolderAccessData Data, string FolderUid, string AccessUidB64)> prepared,
            KeeperNSFFolderAccessResult[] results,
            Dictionary<string, string> prepareFailed)
        {
            if (prepareFailed == null || prepareFailed.Count == 0)
            {
                return;
            }

            prepared.RemoveAll(item =>
            {
                if (!prepareFailed.TryGetValue(item.FolderUid, out var message))
                {
                    return false;
                }

                results[item.Index].Status = "prepare_failed";
                results[item.Index].Message = message;
                return true;
            });
        }

        private static FolderProto.EncryptedDataKey EncryptFolderKeyForUser(
            byte[] folderKey, AuthProto.PublicKeyResponse pkRs, bool forbidKeyType2)
        {
            if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
            {
                throw new KeeperApiException("public_key_error",
                    string.IsNullOrEmpty(pkRs.Message)
                        ? "User has no public key."
                        : pkRs.Message);
            }

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

            return new FolderProto.EncryptedDataKey
            {
                EncryptedKey = ByteString.CopyFrom(encryptedFolderKey),
                EncryptedKeyType = keyType,
            };
        }

        // sends prepared access adds/updates/removes in chunks of 500
        private static async Task SendFolderAccessBatchesAsync(
            VaultOnline vault,
            List<(int Index, FolderProto.FolderAccessData Data, string FolderUid, string AccessUidB64)> prepared,
            KeeperNSFFolderAccessResult[] results,
            Action<FolderProto.FolderAccessRequest, FolderProto.FolderAccessData> addToRequest)
        {
            for (var offset = 0; offset < prepared.Count; offset += MaxKeeperNSFFolderAccessBatchSize)
            {
                var chunk = prepared.Skip(offset).Take(MaxKeeperNSFFolderAccessBatchSize).ToList();
                var rq = new FolderProto.FolderAccessRequest();
                foreach (var item in chunk)
                {
                    addToRequest(rq, item.Data);
                }

                var rs = await vault.Auth
                    .ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                        "vault/folders/v3/access_update", rq)
                    .ConfigureAwait(false);

                var statusByKey = new Dictionary<string, FolderProto.FolderAccessResult>(StringComparer.Ordinal);
                var serverResults = rs?.FolderAccessResults;
                if (serverResults != null)
                {
                    foreach (var status in serverResults)
                    {
                        if (status?.FolderUid == null || status.FolderUid.IsEmpty
                            || status.AccessUid == null || status.AccessUid.IsEmpty)
                        {
                            continue;
                        }

                        var folderUid = CryptoUtils.Base64UrlEncode(status.FolderUid.ToByteArray());
                        var accessUid = CryptoUtils.Base64UrlEncode(status.AccessUid.ToByteArray());
                        var kind = status.AccessType == FolderProto.AccessType.AtTeam ? "team" : "user";
                        statusByKey[$"{folderUid}|{kind}|{accessUid}"] = status;
                    }
                }

                for (var j = 0; j < chunk.Count; j++)
                {
                    var item = chunk[j];
                    var accessType = item.Data.AccessType == FolderProto.AccessType.AtTeam ? "team" : "user";
                    var lookupKey = $"{item.FolderUid}|{accessType}|{item.AccessUidB64}";

                    if (!statusByKey.TryGetValue(lookupKey, out var modifyResult)
                        && serverResults != null
                        && j < serverResults.Count)
                    {
                        modifyResult = serverResults[j];
                    }

                    if (modifyResult == null)
                    {
                        results[item.Index].Status = "missing";
                        results[item.Index].Message = "Server returned no status for this folder access entry.";
                        continue;
                    }

                    results[item.Index].Status = Enum.GetName(typeof(FolderProto.FolderModifyStatus), modifyResult.Status)
                        ?? modifyResult.Status.ToString();
                    results[item.Index].Message = modifyResult.Message;
                    results[item.Index].Success = modifyResult.Status == FolderProto.FolderModifyStatus.Success;
                }
            }
        }

        /// <summary>
        /// Share an NSF folder with a KSM application via AT_APPLICATION.
        /// </summary>
        public static async Task GrantKeeperNSFFolderToApplicationInternal(
            this VaultOnline vault, string folderUid, string applicationUid, bool editable)
        {
            if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder) || folder.FolderKey == null)
                throw new VaultException($"Cannot share folder: folder key is not available for '{folderUid}'");
            if (!vault.TryGetKeeperRecord(applicationUid, out var appRecord) || appRecord is not ApplicationRecord application
                || application.RecordKey == null)
                throw new VaultException($"Cannot share folder: application key is not available for '{applicationUid}'");

            var accessRole = ResolveAccessRole(editable ? "content-manager" : "viewer");
            var folderUidBytes = ByteString.CopyFrom(folderUid.Base64UrlDecode());
            var appUidBytes = ByteString.CopyFrom(applicationUid.Base64UrlDecode());

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
                        if (accessor.AccessType == FolderProto.AccessType.AtApplication
                            && accessor.AccessTypeUid.Equals(appUidBytes))
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
                Trace.TraceWarning($"KeeperNSF: Could not look up existing AT_APPLICATION access for '{folderUid}': {ex.Message}");
            }

            if (existingAccess != null)
            {
                if (existingAccess.AccessRoleType == accessRole)
                {
                    return;
                }
                await vault.UpdateKeeperNSFFolderApplicationAccessInternal(folderUid, applicationUid, editable);
                return;
            }

            var addData = new FolderProto.FolderAccessData
            {
                FolderUid = folderUidBytes,
                AccessTypeUid = appUidBytes,
                AccessType = FolderProto.AccessType.AtApplication,
                AccessRoleType = accessRole,
                Permissions = GetFolderPermissionsForRole(accessRole),
                FolderKey = new FolderProto.EncryptedDataKey
                {
                    EncryptedKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(folder.FolderKey, application.RecordKey)),
                    EncryptedKeyType = FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm,
                },
            };

            var rq = new FolderProto.FolderAccessRequest();
            rq.FolderAccessAdds.Add(addData);
            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to grant application access: {result.Message}");
                }
            }
        }

        public static async Task UpdateKeeperNSFFolderApplicationAccessInternal(
            this VaultOnline vault, string folderUid, string applicationUid, bool editable)
        {
            var accessRole = ResolveAccessRole(editable ? "content-manager" : "viewer");
            var updateData = new FolderProto.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = ByteString.CopyFrom(applicationUid.Base64UrlDecode()),
                AccessType = FolderProto.AccessType.AtApplication,
                AccessRoleType = accessRole,
                Permissions = GetFolderPermissionsForRole(accessRole),
            };

            var rq = new FolderProto.FolderAccessRequest();
            rq.FolderAccessUpdates.Add(updateData);
            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to update application access: {result.Message}");
                }
            }
        }

        public static async Task RevokeKeeperNSFFolderFromApplicationInternal(
            this VaultOnline vault, string folderUid, string applicationUid)
        {
            var accessData = new FolderProto.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = ByteString.CopyFrom(applicationUid.Base64UrlDecode()),
                AccessType = FolderProto.AccessType.AtApplication,
            };

            var rq = new FolderProto.FolderAccessRequest();
            rq.FolderAccessRemoves.Add(accessData);
            var rs = await vault.Auth.ExecuteAuthRest<FolderProto.FolderAccessRequest, FolderProto.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != FolderProto.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to revoke application access: {result.Message}");
                }
            }
        }

        private static RecordSharingProto.Permissions BuildApplicationRecordSharePermission(
            string recordUid,
            byte[] recordKey,
            string applicationUid,
            byte[] applicationKey,
            bool editable,
            bool includeKey)
        {
            // Key checks only when encrypting the record key for the application.
            if (includeKey && (recordKey == null || recordKey.Length == 0))
                throw new VaultException($"Record key not available for record '{recordUid}'");
            if (includeKey && (applicationKey == null || applicationKey.Length == 0))
                throw new VaultException($"Application key not available for '{applicationUid}'");

            var recordUidBytes = ByteString.CopyFrom(recordUid.Base64UrlDecode());
            var appUidBytes = ByteString.CopyFrom(applicationUid.Base64UrlDecode());
            var accessRole = ResolveAccessRole(editable ? "content-manager" : "viewer");

            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = appUidBytes,
                RecordUid = recordUidBytes,
            };
            if (includeKey)
            {
                perm.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(recordKey, applicationKey));
                perm.UseEccKey = false;
            }

            perm.Rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = appUidBytes,
                AccessType = FolderProto.AccessType.AtApplication,
                RecordUid = recordUidBytes,
                Owner = false,
                AccessRoleType = accessRole,
            };
            return perm;
        }

        private static void ThrowIfRecordShareStatusesFailed(
            IEnumerable<RecordSharingProto.Status> statuses, string action)
        {
            if (statuses == null)
            {
                return;
            }

            foreach (var status in statuses)
            {
                if (status.Status_ != RecordSharingProto.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to {action} application record access: {status.Message}");
                }
            }
        }

        /// <summary>
        /// Share an NSF record with a KSM application via v3/share.
        /// </summary>
        public static async Task GrantKeeperNSFRecordToApplicationInternal(
            this VaultOnline vault, string recordUid, string applicationUid, bool editable)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record) || record?.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");
            if (!vault.TryGetKeeperRecord(applicationUid, out var appRecord) || appRecord is not ApplicationRecord application
                || application.RecordKey == null)
                throw new VaultException($"Application key not available for '{applicationUid}'");

            var perm = BuildApplicationRecordSharePermission(
                recordUid, record.RecordKey, applicationUid, application.RecordKey, editable, includeKey: true);
            var rq = new RecordSharingProto.Request();
            rq.CreateSharingPermissions.Add(perm);
            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq).ConfigureAwait(false);
            ThrowIfRecordShareStatusesFailed(rs.CreatedSharingStatus, "grant");
        }

        /// <summary>
        /// Update an NSF record's KSM application share role via v3/share.
        /// </summary>
        public static async Task UpdateKeeperNSFRecordApplicationAccessInternal(
            this VaultOnline vault, string recordUid, string applicationUid, bool editable)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record) || record?.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");
            if (!vault.TryGetKeeperRecord(applicationUid, out var appRecord) || appRecord is not ApplicationRecord application
                || application.RecordKey == null)
                throw new VaultException($"Application key not available for '{applicationUid}'");

            var perm = BuildApplicationRecordSharePermission(
                recordUid, record.RecordKey, applicationUid, application.RecordKey, editable, includeKey: true);
            var rq = new RecordSharingProto.Request();
            rq.UpdateSharingPermissions.Add(perm);
            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq).ConfigureAwait(false);
            ThrowIfRecordShareStatusesFailed(rs.UpdatedSharingStatus, "update");
        }

        /// <summary>
        /// Revoke a KSM application's access to an NSF record via v3/share.
        /// </summary>
        public static async Task RevokeKeeperNSFRecordFromApplicationInternal(
            this VaultOnline vault, string recordUid, string applicationUid)
        {
            byte[] recordKey = null;
            if (vault.TryGetKeeperNSFRecord(recordUid, out var record) && record != null)
            {
                recordKey = record.RecordKey;
            }

            var perm = BuildApplicationRecordSharePermission(
                recordUid, recordKey, applicationUid, applicationKey: null, editable: false, includeKey: false);
            var rq = new RecordSharingProto.Request();
            rq.RevokeSharingPermissions.Add(perm);
            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq).ConfigureAwait(false);
            ThrowIfRecordShareStatusesFailed(rs.RevokedSharingStatus, "revoke");
        }

        /// <summary>
        /// Builds folder permissions for KSM app roles.
        /// </summary>
        private static FolderProto.FolderPermissions GetFolderPermissionsForRole(FolderProto.AccessRoleType role)
        {
            var permissions = new FolderProto.FolderPermissions
            {
                CanListAccess = true,
                CanViewRecords = true,
                CanListRecords = true,
                CanListFolders = true,
            };

            if (role == FolderProto.AccessRoleType.ContentManager)
            {
                permissions.CanAdd = true;
                permissions.CanEditRecords = true;
            }

            return permissions;
        }

        public static async Task<string> CreateKeeperNSFRecordInternal(this VaultOnline vault, string title, string recordType, string folderUid, string notes, IDictionary<string, object> fields)
        {
            var results = await vault.CreateKeeperNSFRecordsInternal(new[]
            {
                new KeeperNSFRecordCreateRequest
                {
                    Title = title,
                    RecordType = recordType,
                    FolderUid = folderUid,
                    Notes = notes,
                    Fields = fields,
                },
            }).ConfigureAwait(false);

            var result = results[0];
            if (!result.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Failed to create record: {result.Status ?? "unknown error"}"
                    : $"Failed to create record: {result.Message}");
            }

            return result.RecordUid;
        }

        private const int MaxKeeperNSFRecordsAddBatchSize = 1000;

        /// <summary>
        /// Creates many NSF records in chunks of 1000. Used by IVault.CreateKeeperNSFRecords.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFRecordCreateResult>> CreateKeeperNSFRecordsInternal(
            this VaultOnline vault, IReadOnlyList<KeeperNSFRecordCreateRequest> records)
        {
            if (records == null || records.Count == 0)
            {
                throw new ArgumentException("At least one record is required.", nameof(records));
            }

            for (var i = 0; i < records.Count; i++)
            {
                if (records[i] == null)
                {
                    throw new ArgumentException($"Record at index {i} is null.", nameof(records));
                }

                if (string.IsNullOrEmpty(records[i].Title))
                {
                    throw new ArgumentException($"Record title cannot be empty (index {i}).", nameof(records));
                }
            }

            var folderUids = records
                .Select(r => r.FolderUid)
                .Where(uid => !string.IsNullOrEmpty(uid))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            foreach (var folderUid in folderUids)
            {
                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    throw new VaultException($"Keeper NSF folder '{folderUid}' not found");
                }

                if (folder.FolderKey == null)
                {
                    throw new VaultException($"Folder key not available for folder '{folderUid}'");
                }

                await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, folderUid)
                    .ConfigureAwait(false);
            }

            var preparedRecordRequestArray = new List<(KeeperNSFRecordCreateRequest Request, string RecordUid, RecordProto.RecordAdd RecordAdd)>(records.Count);
            foreach (var request in records)
            {
                var recordUid = BuildKeeperNSFRecordAdd(vault, request, out var recordAdd);
                preparedRecordRequestArray.Add((request, recordUid, recordAdd));
            }

            var results = new List<KeeperNSFRecordCreateResult>(records.Count);
            for (var offset = 0; offset < preparedRecordRequestArray.Count; offset += MaxKeeperNSFRecordsAddBatchSize)
            {
                var chunk = preparedRecordRequestArray.Skip(offset).Take(MaxKeeperNSFRecordsAddBatchSize).ToList();
                var chunkResults = await ExecuteKeeperNSFRecordsAddBatchAsync(vault, chunk).ConfigureAwait(false);
                results.AddRange(chunkResults);
            }

            return results;
        }

        // builds encrypted RecordAdd for one batch create item
        private static string BuildKeeperNSFRecordAdd(
            VaultOnline vault,
            KeeperNSFRecordCreateRequest request,
            out RecordProto.RecordAdd recordAdd)
        {
            var recordUid = CryptoUtils.GenerateUid();
            var recordKey = CryptoUtils.GenerateEncryptionKey();

            byte[] encryptionKey;
            FolderProto.FolderKeyEncryptionType keyEncryptedBy;
            if (!string.IsNullOrEmpty(request.FolderUid))
            {
                if (!vault.TryGetKeeperNSFFolder(request.FolderUid, out var folder))
                {
                    throw new VaultException($"Keeper NSF folder '{request.FolderUid}' not found");
                }

                encryptionKey = folder.FolderKey;
                keyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByParentKey;
            }
            else
            {
                encryptionKey = vault.Auth.AuthContext.DataKey;
                keyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByUserKey;
            }

            var dataObj = BuildNsfRecordData(
                request.RecordType,
                request.Title,
                request.Notes,
                request.Fields);
            var jsonData = SerializeNsfRecordData(dataObj);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, recordKey);
            var encryptedRecordKey = CryptoUtils.EncryptAesV2(recordKey, encryptionKey);

            recordAdd = new RecordProto.RecordAdd
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                RecordKeyType = FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm,
                RecordKeyEncryptedBy = keyEncryptedBy,
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Data = ByteString.CopyFrom(encryptedData),
            };

            if (!string.IsNullOrEmpty(request.FolderUid))
            {
                recordAdd.FolderUid = ByteString.CopyFrom(request.FolderUid.Base64UrlDecode());
            }

            return recordUid;
        }

        // posts one record-add chunk and maps statuses to results
        private static async Task<IReadOnlyList<KeeperNSFRecordCreateResult>> ExecuteKeeperNSFRecordsAddBatchAsync(
            VaultOnline vault,
            IReadOnlyList<(KeeperNSFRecordCreateRequest Request, string RecordUid, RecordProto.RecordAdd RecordAdd)> batch)
        {
            var requestObj = new RecordProto.RecordsAddRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            foreach (var item in batch)
            {
                requestObj.Records.Add(item.RecordAdd);
            }

            var responseObj = await vault.Auth.ExecuteAuthRest<RecordProto.RecordsAddRequest, RecordsModifyResponse>(
                "vault/records/v3/add", requestObj).ConfigureAwait(false);

            var statusByRecordUid = new Dictionary<string, Records.RecordModifyStatus>(StringComparer.Ordinal);
            foreach (var status in responseObj.Records)
            {
                if (status.RecordUid == null || status.RecordUid.IsEmpty)
                {
                    continue;
                }

                var uid = CryptoUtils.Base64UrlEncode(status.RecordUid.ToByteArray());
                statusByRecordUid[uid] = status;
            }

            var results = new List<KeeperNSFRecordCreateResult>(batch.Count);
            foreach (var item in batch)
            {
                if (!statusByRecordUid.TryGetValue(item.RecordUid, out var status))
                {
                    results.Add(new KeeperNSFRecordCreateResult
                    {
                        RecordUid = item.RecordUid,
                        Title = item.Request.Title,
                        Status = "missing",
                        Message = "Server returned no status for this record.",
                        Success = false,
                    });
                    continue;
                }

                var statusLabel = FormatRecordModifyStatus(status.Status);
                results.Add(new KeeperNSFRecordCreateResult
                {
                    RecordUid = item.RecordUid,
                    Title = item.Request.Title,
                    Status = statusLabel,
                    Message = status.Message,
                    Success = status.Status == RecordModifyResult.RsSuccess,
                });
            }

            return results;
        }

        private static string FormatRecordModifyStatus(RecordModifyResult status)
        {
            var name = Enum.GetName(typeof(RecordModifyResult), status) ?? status.ToString();
            return name.StartsWith("Rs", StringComparison.Ordinal) ? name.Substring(2) : name;
        }


        /// <summary>
        /// Creates a typed record in an NSF folder via vault/records/v3/add.
        /// </summary>
        public static async Task CreateKeeperNSFTypedRecordInternal(this VaultOnline vault, TypedRecord typed, string folderUid)
        {
            if (vault == null)
            {
                throw new ArgumentNullException(nameof(vault));
            }

            if (typed == null)
            {
                throw new ArgumentNullException(nameof(typed));
            }

            if (string.IsNullOrWhiteSpace(folderUid))
            {
                throw new VaultException("Keeper NSF folder UID is required");
            }

            if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder) || folder == null)
            {
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");
            }

            if (folder.FolderKey == null || folder.FolderKey.Length == 0)
            {
                throw new VaultException($"Folder key not available for folder '{folderUid}'");
            }

            await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, folderUid)
                .ConfigureAwait(false);

            if (string.IsNullOrEmpty(typed.Uid))
            {
                typed.Uid = CryptoUtils.GenerateUid();
            }

            if (typed.RecordKey == null || typed.RecordKey.Length == 0)
            {
                typed.RecordKey = CryptoUtils.GenerateEncryptionKey();
            }

            if (typed.Version <= 0)
            {
                typed.Version = 3;
            }

            vault.AdjustTypedRecord(typed);
            var recordData = typed.ExtractRecordV3Data();
            var jsonData = VaultExtensions.PadRecordData(JsonUtils.DumpJson(recordData));
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, typed.RecordKey);
            var encryptedRecordKey = CryptoUtils.EncryptAesV2(typed.RecordKey, folder.FolderKey);
            var clientModified = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var ra = new RecordProto.RecordAdd
            {
                RecordUid = ByteString.CopyFrom(typed.Uid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                RecordKeyType = FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm,
                RecordKeyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByParentKey,
                ClientModifiedTime = clientModified,
                Data = ByteString.CopyFrom(encryptedData),
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
            };

            foreach (var recordRef in typed.ExtractTypedRecordRefs() ?? Enumerable.Empty<string>())
            {
                if (string.IsNullOrEmpty(recordRef))
                {
                    continue;
                }

                byte[] refKey = null;
                typed.LinkedKeys?.TryGetValue(recordRef, out refKey);
                if (refKey == null && vault.TryGetKeeperRecord(recordRef, out var linked))
                {
                    refKey = linked.RecordKey;
                }

                if (refKey == null && vault.TryGetKeeperNSFRecord(recordRef, out var linkedNsf))
                {
                    refKey = linkedNsf.RecordKey;
                }

                if (refKey == null)
                {
                    Trace.TraceError($"Lost record reference while creating NSF typed record: \"{recordRef}\"");
                    continue;
                }

                ra.RecordLinks.Add(new RecordLink
                {
                    RecordUid = ByteString.CopyFrom(recordRef.Base64UrlDecode()),
                    RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(refKey, typed.RecordKey)),
                });
            }

            var rq = new RecordProto.RecordsAddRequest();
            rq.Records.Add(ra);

            var rs = await vault.Auth.ExecuteAuthRest<RecordProto.RecordsAddRequest, RecordsModifyResponse>(
                "vault/records/v3/add", rq).ConfigureAwait(false);

            if (rs.Records.Count > 0)
            {
                var result = rs.Records[0];
                if (result.Status != RecordModifyResult.RsSuccess)
                {
                    throw new VaultException($"Failed to create NSF typed record: {result.Message}");
                }
            }

            vault.KeeperNSFRecords[typed.Uid] = new KeeperNSFRecord
            {
                RecordUid = typed.Uid,
                RecordKey = typed.RecordKey,
                Title = typed.Title,
                Type = typed.TypeName,
                Notes = typed.Notes,
                Version = typed.Version,
                Revision = 0,
                ClientModifiedTime = clientModified,
                Data = JsonUtils.ParseJson<NsfRecordData>(JsonUtils.DumpJson(recordData, indent: false)),
            };
        }

        /// <summary>
        /// Updates a single Keeper NSF record by UID.
        /// Thin wrapper over <see cref="UpdateKeeperNSFRecordsInternal"/> (same pattern as create).
        /// </summary>
        public static async Task UpdateKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string title, string recordType, string notes, IDictionary<string, object> fields)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");

            var results = await vault.UpdateKeeperNSFRecordsInternal(new[]
            {
                new KeeperNSFRecordUpdateRequest
                {
                    RecordUid = recordUid,
                    Title = title,
                    RecordType = recordType,
                    Notes = notes,
                    Fields = fields,
                },
            }).ConfigureAwait(false);

            var result = results[0];
            if (!result.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Failed to update record: {result.Status ?? "unknown error"}"
                    : $"Failed to update record: {result.Message}");
            }
        }

        private const int MaxKeeperNSFRecordsUpdateBatchSize = 1000;

        /// <summary>
        /// Updates multiple Keeper NSF records in batches of up to 1000.
        /// Shared implementation used by <see cref="UpdateKeeperNSFRecordInternal"/>.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFRecordUpdateResult>> UpdateKeeperNSFRecordsInternal(
            this VaultOnline vault, IReadOnlyList<KeeperNSFRecordUpdateRequest> records)
        {
            if (records == null || records.Count == 0)
            {
                throw new ArgumentException("At least one record is required.", nameof(records));
            }

            for (var i = 0; i < records.Count; i++)
            {
                if (records[i] == null)
                {
                    throw new ArgumentException($"Record at index {i} is null.", nameof(records));
                }

                if (string.IsNullOrEmpty(records[i].RecordUid))
                {
                    throw new ArgumentException($"Record UID cannot be empty (index {i}).", nameof(records));
                }
            }

            var preparedRecordRequestArray = new List<(KeeperNSFRecordUpdateRequest Request, string Title, RecordUpdate RecordUpdate)>();
            var results = new List<KeeperNSFRecordUpdateResult>(records.Count);
            var pendingResultIndexes = new List<int>();

            foreach (var request in records)
            {
                if (!vault.TryGetKeeperNSFRecord(request.RecordUid, out var record))
                {
                    results.Add(new KeeperNSFRecordUpdateResult
                    {
                        RecordUid = request.RecordUid,
                        Title = request.Title,
                        Status = "not_found",
                        Message = $"Keeper NSF record '{request.RecordUid}' not found",
                        Success = false,
                    });
                    continue;
                }

                if (!TryPrepareKeeperNSFRecordUpdate(record, request, out var titleForResult, out var recordUpdate, out var failure))
                {
                    results.Add(failure);
                    continue;
                }

                pendingResultIndexes.Add(results.Count);
                results.Add(null);
                preparedRecordRequestArray.Add((request, titleForResult, recordUpdate));
            }

            for (var offset = 0; offset < preparedRecordRequestArray.Count; offset += MaxKeeperNSFRecordsUpdateBatchSize)
            {
                var chunk = preparedRecordRequestArray.Skip(offset).Take(MaxKeeperNSFRecordsUpdateBatchSize).ToList();
                var chunkResults = await ExecuteKeeperNSFRecordsUpdateBatchAsync(vault, chunk).ConfigureAwait(false);
                for (var i = 0; i < chunkResults.Count; i++)
                {
                    var resultIndex = pendingResultIndexes[offset + i];
                    var result = chunkResults[i];
                    if (result != null
                        && !result.Success
                        && string.Equals(result.Status, "OutOfSync", StringComparison.OrdinalIgnoreCase))
                    {
                        result = await RetryKeeperNSFRecordUpdateOutOfSyncAsync(vault, chunk[i].Request).ConfigureAwait(false);
                    }

                    results[resultIndex] = result;
                }
            }

            return results;
        }

        // clones record data, applies edits, builds RecordUpdate for the batch
        private static bool TryPrepareKeeperNSFRecordUpdate(
            KeeperNSFRecord record,
            KeeperNSFRecordUpdateRequest request,
            out string titleForResult,
            out RecordUpdate recordUpdate,
            out KeeperNSFRecordUpdateResult failure)
        {
            titleForResult = null;
            recordUpdate = null;
            failure = null;

            var recordUid = record?.RecordUid;
            if (string.IsNullOrEmpty(recordUid))
            {
                failure = new KeeperNSFRecordUpdateResult
                {
                    RecordUid = request?.RecordUid,
                    Title = request?.Title,
                    Status = "invalid_record",
                    Message = "Record UID cannot be empty",
                    Success = false,
                };
                return false;
            }

            if (record.RecordKey == null)
            {
                failure = new KeeperNSFRecordUpdateResult
                {
                    RecordUid = recordUid,
                    Title = request?.Title,
                    Status = "no_record_key",
                    Message = $"Record key not available for record '{recordUid}'",
                    Success = false,
                };
                return false;
            }

            if (record.Data == null)
            {
                failure = new KeeperNSFRecordUpdateResult
                {
                    RecordUid = recordUid,
                    Title = request?.Title,
                    Status = "no_record_data",
                    Message = $"Record '{recordUid}' has no decrypted data available. Cannot update.",
                    Success = false,
                };
                return false;
            }

            var dataObj = CloneNsfRecordData(record.Data);
            if (request.Title != null) dataObj.Title = request.Title;
            if (request.RecordType != null) dataObj.Type = request.RecordType;
            if (request.Notes != null) dataObj.Notes = request.Notes;
            ApplyNsfFieldUpdates(dataObj, request.Fields);

            titleForResult = dataObj.Title ?? request.Title;

            var jsonData = SerializeNsfRecordData(dataObj);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, record.RecordKey);

            recordUpdate = new RecordUpdate
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Revision = record.Revision,
                Data = ByteString.CopyFrom(encryptedData),
            };
            return true;
        }

        // refreshes revision and retries one record after OutOfSync
        private static async Task<KeeperNSFRecordUpdateResult> RetryKeeperNSFRecordUpdateOutOfSyncAsync(
            VaultOnline vault,
            KeeperNSFRecordUpdateRequest request)
        {
            try
            {
                var refreshed = await vault.GetRefreshedKeeperNSFRecordAsync(request.RecordUid).ConfigureAwait(false);
                if (refreshed == null)
                {
                    return new KeeperNSFRecordUpdateResult
                    {
                        RecordUid = request.RecordUid,
                        Title = request.Title,
                        Status = "OutOfSync",
                        Message = "Record is out of sync and could not be refreshed for retry.",
                        Success = false,
                    };
                }

                if (!TryPrepareKeeperNSFRecordUpdate(
                        refreshed,
                        request,
                        out var titleForResult,
                        out var recordUpdate,
                        out var failure))
                {
                    return failure;
                }

                var batch = new List<(KeeperNSFRecordUpdateRequest Request, string Title, RecordUpdate RecordUpdate)>
                {
                    (request, titleForResult, recordUpdate),
                };
                var retryResults = await ExecuteKeeperNSFRecordsUpdateBatchAsync(vault, batch).ConfigureAwait(false);
                return retryResults[0];
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Preserve unexpected failures as per-item results only for the retry path;
                // cancellation must still propagate to callers.
                return new KeeperNSFRecordUpdateResult
                {
                    RecordUid = request.RecordUid,
                    Title = request.Title,
                    Status = "OutOfSync",
                    Message = $"Out-of-sync retry failed: {ex.Message}",
                    Success = false,
                };
            }
        }

        // posts one record-update chunk and maps statuses to results
        private static async Task<IReadOnlyList<KeeperNSFRecordUpdateResult>> ExecuteKeeperNSFRecordsUpdateBatchAsync(
            VaultOnline vault,
            IReadOnlyList<(KeeperNSFRecordUpdateRequest Request, string Title, RecordUpdate RecordUpdate)> batch)
        {
            var requestObj = new RecordsUpdateRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            foreach (var item in batch)
            {
                requestObj.Records.Add(item.RecordUpdate);
            }

            var responseObj = await vault.Auth.ExecuteAuthRest<RecordsUpdateRequest, RecordsModifyResponse>(
                "vault/records/v3/update", requestObj).ConfigureAwait(false);

            var statusByRecordUid = new Dictionary<string, Records.RecordModifyStatus>(StringComparer.Ordinal);
            foreach (var status in responseObj.Records)
            {
                if (status.RecordUid == null || status.RecordUid.IsEmpty)
                {
                    continue;
                }

                var uid = CryptoUtils.Base64UrlEncode(status.RecordUid.ToByteArray());
                statusByRecordUid[uid] = status;
            }

            var results = new List<KeeperNSFRecordUpdateResult>(batch.Count);
            foreach (var item in batch)
            {
                if (!statusByRecordUid.TryGetValue(item.Request.RecordUid, out var status))
                {
                    results.Add(new KeeperNSFRecordUpdateResult
                    {
                        RecordUid = item.Request.RecordUid,
                        Title = item.Title,
                        Status = "missing",
                        Message = "Server returned no status for this record.",
                        Success = false,
                    });
                    continue;
                }

                results.Add(new KeeperNSFRecordUpdateResult
                {
                    RecordUid = item.Request.RecordUid,
                    Title = item.Title,
                    Status = FormatRecordModifyStatus(status.Status),
                    Message = status.Message,
                    Success = status.Status == RecordModifyResult.RsSuccess,
                });
            }

            return results;
        }

        /// <summary>
        /// Updates an NSF record from a <see cref="TypedRecord"/>, including script/fileRef links.
        /// Used by <see cref="VaultOnline.UpdateRecord"/> when the UID is an NSF record.
        /// Posts via <see cref="ExecuteKeeperNSFRecordsUpdateBatchAsync"/>.
        /// </summary>
        public static async Task UpdateKeeperNSFTypedRecordInternal(this VaultOnline vault, TypedRecord typed)
        {
            if (typed == null)
                throw new ArgumentNullException(nameof(typed));

            if (string.IsNullOrEmpty(typed.Uid))
                throw new VaultException("Record UID cannot be empty");

            if (!vault.TryGetKeeperNSFRecord(typed.Uid, out var nsf))
                throw new VaultException($"Keeper NSF record '{typed.Uid}' not found");

            var recordKey = typed.RecordKey ?? nsf.RecordKey;
            if (recordKey == null)
                throw new VaultException($"Record key not available for record '{typed.Uid}'");

            typed.RecordKey = recordKey;
            vault.AdjustTypedRecord(typed);

            var recordData = typed.ExtractRecordV3Data();
            var recordJson = JsonUtils.DumpJson(recordData, indent: false);
            var jsonData = VaultExtensions.PadRecordData(recordJson);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, recordKey);

            var recordUpdate = new RecordUpdate
            {
                RecordUid = ByteString.CopyFrom(typed.Uid.Base64UrlDecode()),
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Revision = nsf.Revision,
                Data = ByteString.CopyFrom(encryptedData),
            };

            var existingRefs =
                VaultExtensions.TryConvertKeeperNSFRecordToTypedRecord(nsf, out var existingTyped)
                && existingTyped != null
                    ? existingTyped.ExtractTypedRecordRefs() ?? new HashSet<string>(StringComparer.Ordinal)
                    : new HashSet<string>(StringComparer.Ordinal);

            var currentRefs = typed.ExtractTypedRecordRefs()
                              ?? new HashSet<string>(StringComparer.Ordinal);

            foreach (var newRef in currentRefs.Except(existingRefs).Where(x => !string.IsNullOrEmpty(x)))
            {
                byte[] refKey = null;
                typed.LinkedKeys?.TryGetValue(newRef, out refKey);
                if (refKey == null && vault.TryGetKeeperRecord(newRef, out var linked)
                    && linked?.RecordKey != null)
                {
                    refKey = linked.RecordKey;
                }

                if (refKey == null && vault.TryGetKeeperNSFRecord(newRef, out var linkedNsf)
                    && linkedNsf?.RecordKey != null)
                {
                    refKey = linkedNsf.RecordKey;
                }

                if (refKey == null)
                {
                    Trace.TraceError("Lost record reference while updating NSF typed record (missing record key).");
                    continue;
                }

                recordUpdate.RecordLinksAdd.Add(new RecordLink
                {
                    RecordUid = ByteString.CopyFrom(newRef.Base64UrlDecode()),
                    RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(refKey, recordKey)),
                });
            }

            recordUpdate.RecordLinksRemove.AddRange(existingRefs.Except(currentRefs)
                .Where(x => !string.IsNullOrEmpty(x))
                .Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));

            var results = await ExecuteKeeperNSFRecordsUpdateBatchAsync(
                vault,
                new[]
                {
                    (new KeeperNSFRecordUpdateRequest { RecordUid = typed.Uid, Title = typed.Title },
                        typed.Title ?? "",
                        recordUpdate),
                }).ConfigureAwait(false);
            var result = results[0];
            if (!result.Success)
            {
                throw new KeeperApiException(
                    (result.Status ?? "failed").ToSnakeCase(),
                    result.Message ?? "Failed to update record");
            }

            // Prefer server-backed NSF row after update.
            var refreshed = await vault.GetRefreshedKeeperNSFRecordAsync(typed.Uid).ConfigureAwait(false);
            if (refreshed != null)
            {
                nsf = refreshed;
            }
            else
            {
                nsf.Revision = nsf.Revision + 1;
            }

            nsf.Title = typed.Title;
            nsf.Type = typed.TypeName;
            nsf.Notes = typed.Notes;
            nsf.DataJson = recordJson;
            nsf.Data = JsonUtils.ParseJson<NsfRecordData>(recordJson);
            nsf.ClientModifiedTime = recordUpdate.ClientModifiedTime;
            vault.KeeperNSFRecords[nsf.RecordUid] = nsf;
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

        private static async Task<RecordSharingProto.Permissions> BuildRecordDenySharePermissions(
            VaultOnline vault, string recordUid, string userEmail)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                throw new VaultException($"Keeper NSF record '{recordUid}' not found");
            if (record.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");

            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq).ConfigureAwait(false);
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

            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                UseEccKey = useEcc,
            };
            perm.Rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = FolderProto.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Owner = false,
                DeniedAccess = true,
            };
            return perm;
        }

        private static async Task DenyInheritedKeeperNSFRecordShareAsync(
            VaultOnline vault, string recordUid, string userEmail)
        {
            var perm = await BuildRecordDenySharePermissions(vault, recordUid, userEmail).ConfigureAwait(false);
            var rq = new RecordSharingProto.Request();
            rq.CreateSharingPermissions.Add(perm);
            var rs = await vault.Auth.ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                "vault/records/v3/share", rq).ConfigureAwait(false);

            foreach (var status in rs.CreatedSharingStatus)
            {
                if (status.Status_ != RecordSharingProto.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to deny inherited record access: {status.Message}");
                }
            }
        }

        /// <summary>
        /// Grants a user access to a single Keeper NSF record.
        /// Thin wrapper over <see cref="ShareKeeperNSFRecordsInternal"/> (same pattern as create).
        /// </summary>
        public static async Task ShareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail, string role, SharedFolderRecordOptions options = null)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            var results = await vault.ShareKeeperNSFRecordsInternal(new[]
            {
                new KeeperNSFRecordShareRequest
                {
                    RecordUid = recordUid,
                    UserEmail = userEmail,
                    Role = string.IsNullOrWhiteSpace(role) ? "viewer" : role,
                    Options = options,
                },
            }).ConfigureAwait(false);

            var result = results[0];
            if (!result.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Failed to share record: {result.Status ?? "unknown error"}"
                    : $"Failed to share record: {result.Message}");
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

        /// <summary>
        /// Revokes a user's access from a single Keeper NSF record.
        /// Thin wrapper over <see cref="UnshareKeeperNSFRecordsInternal"/> (same pattern as create).
        /// </summary>
        public static async Task UnshareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail)
        {
            if (string.IsNullOrEmpty(recordUid))
                throw new VaultException("Record UID cannot be empty");
            if (string.IsNullOrEmpty(userEmail))
                throw new VaultException("User email cannot be empty");

            var results = await vault.UnshareKeeperNSFRecordsInternal(new[]
            {
                new KeeperNSFRecordUnshareRequest
                {
                    RecordUid = recordUid,
                    UserEmail = userEmail,
                },
            }).ConfigureAwait(false);

            var result = results[0];
            if (!result.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Failed to revoke record access: {result.Status ?? "unknown error"}"
                    : $"Failed to revoke record access: {result.Message}");
            }
        }

        // max share/unshare entries per request
        private const int MaxKeeperNSFRecordsShareBatchSize = 1000;

        /// <summary>
        /// Shares records in chunks of 1000. Used by IVault.ShareKeeperNSFRecords.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFRecordShareResult>> ShareKeeperNSFRecordsInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordShareRequest> shares)
        {
            if (shares == null || shares.Count == 0)
            {
                throw new ArgumentException("At least one share is required.", nameof(shares));
            }

            var results = new KeeperNSFRecordShareResult[shares.Count];
            for (var i = 0; i < shares.Count; i++)
            {
                if (shares[i] == null)
                {
                    throw new ArgumentException($"Share at index {i} is null.", nameof(shares));
                }
            }

            var uniqueRecordUids = shares
                .Select(s => s.RecordUid?.Trim())
                .Where(uid => !string.IsNullOrEmpty(uid) && vault.TryGetKeeperNSFRecord(uid, out _))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            var shareDeniedByUid = await KeeperNSFAccessHelpers
                .EvaluateKeeperNSFRecordSharePermissionsAsync(vault, uniqueRecordUids)
                .ConfigureAwait(false);

            var uniqueEmails = shares
                .Select(s => s.UserEmail?.Trim())
                .Where(email => !string.IsNullOrEmpty(email))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var publicKeysByEmail = await ResolveKeeperNSFPublicKeysAsync(vault, uniqueEmails).ConfigureAwait(false);

            var seenShareKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var prepared = new List<(int Index, KeeperNSFRecordShareRequest Request, RecordSharingProto.Permissions Permission)>();
            for (var i = 0; i < shares.Count; i++)
            {
                var request = shares[i];
                var recordUid = request.RecordUid?.Trim();
                var userEmail = request.UserEmail?.Trim();
                var role = string.IsNullOrWhiteSpace(request.Role) ? "viewer" : request.Role.Trim();

                results[i] = new KeeperNSFRecordShareResult
                {
                    RecordUid = recordUid,
                    UserEmail = userEmail,
                    Role = role,
                    Success = false,
                };

                if (string.IsNullOrEmpty(recordUid))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Record UID cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "User email cannot be empty.";
                    continue;
                }

                var shareKey = $"{recordUid}|{userEmail}";
                if (!seenShareKeys.Add(shareKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message =
                        $"Duplicate share for record '{recordUid}' and user '{userEmail}' in this request.";
                    continue;
                }

                if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF record '{recordUid}' not found.";
                    continue;
                }

                if (shareDeniedByUid.TryGetValue(recordUid, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (record.RecordKey == null)
                {
                    results[i].Status = "missing_key";
                    results[i].Message = $"Record key not available for record '{recordUid}'.";
                    continue;
                }

                if (!publicKeysByEmail.TryGetValue(userEmail, out var pkRs) || pkRs == null)
                {
                    results[i].Status = "user_not_found";
                    results[i].Message = $"User '{userEmail}' not found or has no public key.";
                    continue;
                }

                if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                {
                    results[i].Status = "public_key_error";
                    results[i].Message = string.IsNullOrEmpty(pkRs.Message)
                        ? $"User '{userEmail}' not found or has no public key."
                        : pkRs.Message;
                    continue;
                }

                try
                {
                    var permission = BuildRecordSharePermissionsFromPublicKey(
                        recordUid, record.RecordKey, role, pkRs, request.Options);
                    prepared.Add((i, request, permission));
                }
                catch (Exception ex)
                {
                    results[i].Status = "prepare_failed";
                    results[i].Message = ex.Message;
                }
            }

            var pendingUpdate = new List<(int Index, RecordSharingProto.Permissions Permission)>();
            for (var offset = 0; offset < prepared.Count; offset += MaxKeeperNSFRecordsShareBatchSize)
            {
                var chunk = prepared.Skip(offset).Take(MaxKeeperNSFRecordsShareBatchSize).ToList();
                var createRq = new RecordSharingProto.Request();
                foreach (var item in chunk)
                {
                    createRq.CreateSharingPermissions.Add(item.Permission);
                }

                var createRs = await vault.Auth
                    .ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                        "vault/records/v3/share", createRq)
                    .ConfigureAwait(false);

                var statusByKey = IndexShareStatuses(createRs.CreatedSharingStatus);
                for (var chunkIndex = 0; chunkIndex < chunk.Count; chunkIndex++)
                {
                    var item = chunk[chunkIndex];
                    var key = BuildShareStatusKey(item.Permission.RecordUid, item.Permission.RecipientUid);
                    if (!statusByKey.TryGetValue(key, out var status)
                        && chunkIndex < createRs.CreatedSharingStatus.Count)
                    {
                        status = createRs.CreatedSharingStatus[chunkIndex];
                    }

                    if (status == null)
                    {
                        results[item.Index].Status = "missing";
                        results[item.Index].Message = "Server returned no status for this share.";
                        continue;
                    }

                    if (status.Status_ == RecordSharingProto.SharingStatus.AlreadyShared)
                    {
                        pendingUpdate.Add((item.Index, item.Permission));
                        continue;
                    }

                    ApplyShareStatusToResult(results[item.Index], status);
                }
            }

            for (var offset = 0; offset < pendingUpdate.Count; offset += MaxKeeperNSFRecordsShareBatchSize)
            {
                var chunk = pendingUpdate.Skip(offset).Take(MaxKeeperNSFRecordsShareBatchSize).ToList();
                var updateRq = new RecordSharingProto.Request();
                foreach (var item in chunk)
                {
                    updateRq.UpdateSharingPermissions.Add(item.Permission);
                }

                var updateRs = await vault.Auth
                    .ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                        "vault/records/v3/share", updateRq)
                    .ConfigureAwait(false);

                var statusByKey = IndexShareStatuses(updateRs.UpdatedSharingStatus);
                for (var chunkIndex = 0; chunkIndex < chunk.Count; chunkIndex++)
                {
                    var item = chunk[chunkIndex];
                    var key = BuildShareStatusKey(item.Permission.RecordUid, item.Permission.RecipientUid);
                    if (!statusByKey.TryGetValue(key, out var status)
                        && chunkIndex < updateRs.UpdatedSharingStatus.Count)
                    {
                        status = updateRs.UpdatedSharingStatus[chunkIndex];
                    }

                    if (status == null)
                    {
                        results[item.Index].Status = "missing";
                        results[item.Index].Message = "Server returned no status for this share update.";
                        continue;
                    }

                    ApplyShareStatusToResult(results[item.Index], status);
                }
            }

            return results;
        }

        /// <summary>
        /// Unshares records in chunks of 1000. Used by IVault.UnshareKeeperNSFRecords.
        /// </summary>
        public static async Task<IReadOnlyList<KeeperNSFRecordUnshareResult>> UnshareKeeperNSFRecordsInternal(
            this VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordUnshareRequest> unshares)
        {
            if (unshares == null || unshares.Count == 0)
            {
                throw new ArgumentException("At least one unshare is required.", nameof(unshares));
            }

            var results = new KeeperNSFRecordUnshareResult[unshares.Count];
            for (var i = 0; i < unshares.Count; i++)
            {
                if (unshares[i] == null)
                {
                    throw new ArgumentException($"Unshare at index {i} is null.", nameof(unshares));
                }
            }

            var uniqueRecordUids = unshares
                .Select(s => s.RecordUid?.Trim())
                .Where(uid => !string.IsNullOrEmpty(uid) && vault.TryGetKeeperNSFRecord(uid, out _))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            var shareDeniedByUid = await KeeperNSFAccessHelpers
                .EvaluateKeeperNSFRecordSharePermissionsAsync(vault, uniqueRecordUids)
                .ConfigureAwait(false);

            var uniqueEmails = unshares
                .Select(s => s.UserEmail?.Trim())
                .Where(email => !string.IsNullOrEmpty(email))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var publicKeysByEmail = await ResolveKeeperNSFPublicKeysAsync(vault, uniqueEmails).ConfigureAwait(false);

            RecordDetailsProto.RecordAccessResponse accessDetails = null;
            var accessLookupSucceeded = false;
            try
            {
                accessDetails = await KeeperNSFAccessHelpers
                    .FetchRecordAccessDetailsAsync(vault, uniqueRecordUids)
                    .ConfigureAwait(false);
                accessLookupSucceeded = true;
            }
            catch (Exception ex)
            {
                Trace.TraceWarning(
                    $"KeeperNSF: Could not batch-fetch record access for unshare; will revoke and deny: {ex.Message}");
            }

            var accessFlags = BuildRecordUserAccessFlags(accessDetails);

            var seenUnshareKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var pendingRevoke = new List<(int Index, RecordSharingProto.Permissions Permission)>();
            var pendingDeny = new List<(int Index, RecordSharingProto.Permissions Permission)>();
            var needRevoke = new bool[unshares.Count];
            var needDeny = new bool[unshares.Count];
            var revokeOk = new bool[unshares.Count];
            var denyOk = new bool[unshares.Count];
            var revokeStatus = new RecordSharingProto.Status[unshares.Count];
            var denyStatus = new RecordSharingProto.Status[unshares.Count];

            for (var i = 0; i < unshares.Count; i++)
            {
                var request = unshares[i];
                var recordUid = request.RecordUid?.Trim();
                var userEmail = request.UserEmail?.Trim();

                results[i] = new KeeperNSFRecordUnshareResult
                {
                    RecordUid = recordUid,
                    UserEmail = userEmail,
                    Success = false,
                };

                if (string.IsNullOrEmpty(recordUid))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Record UID cannot be empty.";
                    continue;
                }

                if (string.IsNullOrEmpty(userEmail))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "User email cannot be empty.";
                    continue;
                }

                var unshareKey = $"{recordUid}|{userEmail}";
                if (!seenUnshareKeys.Add(unshareKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message =
                        $"Duplicate unshare for record '{recordUid}' and user '{userEmail}' in this request.";
                    continue;
                }

                if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF record '{recordUid}' not found.";
                    continue;
                }

                if (shareDeniedByUid.TryGetValue(recordUid, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (!publicKeysByEmail.TryGetValue(userEmail, out var pkRs) || pkRs == null)
                {
                    results[i].Status = "user_not_found";
                    results[i].Message = $"User '{userEmail}' not found or has no public key.";
                    continue;
                }

                if (pkRs.AccountUid.IsEmpty)
                {
                    results[i].Status = "user_not_found";
                    results[i].Message = $"User '{userEmail}' not found.";
                    continue;
                }

                var accountUid = CryptoUtils.Base64UrlEncode(pkRs.AccountUid.ToByteArray());
                var hasDirect = false;
                var hasInherited = false;
                if (accessLookupSucceeded
                    && accessFlags.TryGetValue((recordUid, accountUid), out var flags))
                {
                    hasDirect = flags.HasDirect;
                    hasInherited = flags.HasInherited;
                }
                else if (!accessLookupSucceeded)
                {
                    // Unknown access model: revoke direct share and deny inherited (safe fallback).
                    hasDirect = true;
                    hasInherited = true;
                }

                RecordSharingProto.Permissions denyPermission = null;
                if (hasInherited)
                {
                    if (record.RecordKey == null)
                    {
                        results[i].Status = "missing_key";
                        results[i].Message = $"Record key not available for record '{recordUid}'.";
                        continue;
                    }

                    if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                    {
                        results[i].Status = "public_key_error";
                        results[i].Message = string.IsNullOrEmpty(pkRs.Message)
                            ? $"User '{userEmail}' not found or has no public key."
                            : pkRs.Message;
                        continue;
                    }

                    try
                    {
                        denyPermission = BuildRecordDenySharePermissionsFromPublicKey(
                            recordUid, record.RecordKey, pkRs);
                    }
                    catch (Exception ex)
                    {
                        results[i].Status = "prepare_failed";
                        results[i].Message = ex.Message;
                        continue;
                    }
                }

                if (hasDirect || (!hasDirect && !hasInherited))
                {
                    needRevoke[i] = true;
                    pendingRevoke.Add((i, BuildRecordRevokePermissions(recordUid, pkRs.AccountUid)));
                }

                if (denyPermission != null)
                {
                    needDeny[i] = true;
                    pendingDeny.Add((i, denyPermission));
                }
            }

            for (var offset = 0; offset < pendingRevoke.Count; offset += MaxKeeperNSFRecordsShareBatchSize)
            {
                var chunk = pendingRevoke.Skip(offset).Take(MaxKeeperNSFRecordsShareBatchSize).ToList();
                var revokeRq = new RecordSharingProto.Request();
                foreach (var item in chunk)
                {
                    revokeRq.RevokeSharingPermissions.Add(item.Permission);
                }

                var revokeRs = await vault.Auth
                    .ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                        "vault/records/v3/share", revokeRq)
                    .ConfigureAwait(false);

                var statusByKey = IndexShareStatuses(revokeRs.RevokedSharingStatus);
                for (var chunkIndex = 0; chunkIndex < chunk.Count; chunkIndex++)
                {
                    var item = chunk[chunkIndex];
                    var key = BuildShareStatusKey(item.Permission.RecordUid, item.Permission.RecipientUid);
                    if (!statusByKey.TryGetValue(key, out var status)
                        && chunkIndex < revokeRs.RevokedSharingStatus.Count)
                    {
                        status = revokeRs.RevokedSharingStatus[chunkIndex];
                    }

                    revokeStatus[item.Index] = status;
                    revokeOk[item.Index] = status != null
                        && (status.Status_ == RecordSharingProto.SharingStatus.Success
                            || status.Status_ == RecordSharingProto.SharingStatus.PendingAccept);
                }
            }

            for (var offset = 0; offset < pendingDeny.Count; offset += MaxKeeperNSFRecordsShareBatchSize)
            {
                var chunk = pendingDeny.Skip(offset).Take(MaxKeeperNSFRecordsShareBatchSize).ToList();
                var denyRq = new RecordSharingProto.Request();
                foreach (var item in chunk)
                {
                    denyRq.CreateSharingPermissions.Add(item.Permission);
                }

                var denyRs = await vault.Auth
                    .ExecuteAuthRest<RecordSharingProto.Request, RecordSharingProto.Response>(
                        "vault/records/v3/share", denyRq)
                    .ConfigureAwait(false);

                var statusByKey = IndexShareStatuses(denyRs.CreatedSharingStatus);
                for (var chunkIndex = 0; chunkIndex < chunk.Count; chunkIndex++)
                {
                    var item = chunk[chunkIndex];
                    var key = BuildShareStatusKey(item.Permission.RecordUid, item.Permission.RecipientUid);
                    if (!statusByKey.TryGetValue(key, out var status)
                        && chunkIndex < denyRs.CreatedSharingStatus.Count)
                    {
                        status = denyRs.CreatedSharingStatus[chunkIndex];
                    }

                    denyStatus[item.Index] = status;
                    denyOk[item.Index] = status != null
                        && (status.Status_ == RecordSharingProto.SharingStatus.Success
                            || status.Status_ == RecordSharingProto.SharingStatus.PendingAccept);
                }
            }

            for (var i = 0; i < unshares.Count; i++)
            {
                if (!string.IsNullOrEmpty(results[i].Status) && !needRevoke[i] && !needDeny[i])
                {
                    continue;
                }

                if (!needRevoke[i] && !needDeny[i])
                {
                    if (string.IsNullOrEmpty(results[i].Status))
                    {
                        results[i].Status = "skipped";
                        results[i].Message = "No revoke or deny action was prepared.";
                    }

                    continue;
                }

                var revokeFailed = needRevoke[i] && !revokeOk[i];
                var denyFailed = needDeny[i] && !denyOk[i];
                if (revokeFailed || denyFailed)
                {
                    var failedStatus = revokeFailed ? revokeStatus[i] : denyStatus[i];
                    results[i].Status = failedStatus != null
                        ? FormatSharingStatus(failedStatus.Status_)
                        : "missing";
                    results[i].Message = failedStatus?.Message
                        ?? (revokeFailed
                            ? "Server returned no status for this revoke."
                            : "Server returned no status for this deny.");
                    results[i].Success = false;
                    continue;
                }

                var okStatus = needRevoke[i] ? revokeStatus[i] : denyStatus[i];
                results[i].Status = okStatus != null
                    ? FormatSharingStatus(okStatus.Status_)
                    : "Success";
                results[i].Message = okStatus?.Message;
                results[i].Success = true;
            }

            return results;
        }

        private static Dictionary<(string RecordUid, string AccountUid), (bool HasDirect, bool HasInherited)>
            BuildRecordUserAccessFlags(RecordDetailsProto.RecordAccessResponse accessDetails)
        {
            var map = new Dictionary<(string, string), (bool, bool)>(new RecordAccountUidComparer());
            if (accessDetails?.RecordAccesses == null)
            {
                return map;
            }

            foreach (var ra in accessDetails.RecordAccesses)
            {
                var data = ra?.Data;
                if (data == null) continue;
                if (data.AccessType != FolderProto.AccessType.AtUser) continue;
                if (data.Owner) continue;
                if (data.RecordUid == null || data.RecordUid.IsEmpty) continue;
                if (data.AccessTypeUid == null || data.AccessTypeUid.IsEmpty) continue;

                var recordUid = CryptoUtils.Base64UrlEncode(data.RecordUid.ToByteArray());
                var accountUid = CryptoUtils.Base64UrlEncode(data.AccessTypeUid.ToByteArray());
                var key = (recordUid, accountUid);
                map.TryGetValue(key, out var flags);
                if (data.Inherited)
                {
                    flags.Item2 = true;
                }
                else
                {
                    flags.Item1 = true;
                }

                map[key] = flags;
            }

            return map;
        }

        private sealed class RecordAccountUidComparer : IEqualityComparer<(string RecordUid, string AccountUid)>
        {
            public bool Equals((string RecordUid, string AccountUid) x, (string RecordUid, string AccountUid) y)
            {
                return string.Equals(x.RecordUid, y.RecordUid, StringComparison.Ordinal)
                    && string.Equals(x.AccountUid, y.AccountUid, StringComparison.Ordinal);
            }

            public int GetHashCode((string RecordUid, string AccountUid) obj)
            {
                unchecked
                {
                    return ((obj.RecordUid?.GetHashCode() ?? 0) * 397) ^ (obj.AccountUid?.GetHashCode() ?? 0);
                }
            }
        }

        private static RecordSharingProto.Permissions BuildRecordRevokePermissions(
            string recordUid,
            ByteString recipientUid)
        {
            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = recipientUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            perm.Rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = recipientUid,
                AccessType = FolderProto.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            return perm;
        }

        private static RecordSharingProto.Permissions BuildRecordDenySharePermissionsFromPublicKey(
            string recordUid,
            byte[] recordKey,
            AuthProto.PublicKeyResponse pkRs)
        {
            byte[] encryptedRecordKey;
            bool useEcc;
            if (!pkRs.PublicKey.IsEmpty)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptRsa(recordKey, rsaPk);
                useEcc = false;
            }
            else
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptEc(recordKey, ecPk);
                useEcc = true;
            }

            var perm = new RecordSharingProto.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                UseEccKey = useEcc,
            };
            perm.Rules = new FolderProto.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = FolderProto.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Owner = false,
                DeniedAccess = true,
            };
            return perm;
        }

        // fetches public keys for share recipients
        private static async Task<Dictionary<string, AuthProto.PublicKeyResponse>> ResolveKeeperNSFPublicKeysAsync(
            VaultOnline vault,
            IReadOnlyList<string> emails)
        {
            var map = new Dictionary<string, AuthProto.PublicKeyResponse>(StringComparer.OrdinalIgnoreCase);
            if (emails == null || emails.Count == 0)
            {
                return map;
            }

            for (var offset = 0; offset < emails.Count; offset += MaxKeeperNSFRecordsShareBatchSize)
            {
                var chunk = emails.Skip(offset).Take(MaxKeeperNSFRecordsShareBatchSize).ToList();
                var pkRq = new AuthProto.GetPublicKeysRequest();
                foreach (var email in chunk)
                {
                    pkRq.Usernames.Add(email);
                }

                var pkRss = await vault.Auth
                    .ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                        "vault/get_public_keys", pkRq)
                    .ConfigureAwait(false);

                foreach (var pkRs in pkRss.KeyResponses)
                {
                    // Only map by username. Positional fallback is unsafe when the server
                    // omits or reorders usernames (could encrypt a record key to the wrong account).
                    if (string.IsNullOrEmpty(pkRs.Username) || pkRs.AccountUid.IsEmpty)
                    {
                        continue;
                    }

                    map[pkRs.Username] = pkRs;
                }
            }

            return map;
        }

        // builds encrypted share permissions from a user's public key
        private static RecordSharingProto.Permissions BuildRecordSharePermissionsFromPublicKey(
            string recordUid,
            byte[] recordKey,
            string role,
            AuthProto.PublicKeyResponse pkRs,
            SharedFolderRecordOptions options)
        {
            byte[] encryptedRecordKey;
            bool useEcc;
            if (!pkRs.PublicKey.IsEmpty)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptRsa(recordKey, rsaPk);
                useEcc = false;
            }
            else
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptEc(recordKey, ecPk);
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
            {
                rules.TlaProperties = tlaProperties;
            }

            perm.Rules = rules;
            return perm;
        }

        // indexes share response statuses by record+recipient key
        private static Dictionary<string, RecordSharingProto.Status> IndexShareStatuses(
            IEnumerable<RecordSharingProto.Status> statuses)
        {
            var map = new Dictionary<string, RecordSharingProto.Status>(StringComparer.Ordinal);
            if (statuses == null)
            {
                return map;
            }

            foreach (var status in statuses)
            {
                if (status?.RecordUid == null || status.RecordUid.IsEmpty
                    || status.RecipientUid == null || status.RecipientUid.IsEmpty)
                {
                    continue;
                }

                map[BuildShareStatusKey(status.RecordUid, status.RecipientUid)] = status;
            }

            return map;
        }

        // lookup key for matching a share status to a prepared item
        private static string BuildShareStatusKey(ByteString recordUid, ByteString recipientUid)
        {
            return $"{CryptoUtils.Base64UrlEncode(recordUid.ToByteArray())}|{CryptoUtils.Base64UrlEncode(recipientUid.ToByteArray())}";
        }

        // copies share status fields onto the per-item result
        private static void ApplyShareStatusToResult(
            KeeperNSFRecordShareResult result,
            RecordSharingProto.Status status)
        {
            result.Status = FormatSharingStatus(status.Status_);
            result.Message = status.Message;
            result.Success = status.Status_ == RecordSharingProto.SharingStatus.Success
                || status.Status_ == RecordSharingProto.SharingStatus.PendingAccept;
        }

        private static string FormatSharingStatus(RecordSharingProto.SharingStatus status)
        {
            return Enum.GetName(typeof(RecordSharingProto.SharingStatus), status) ?? status.ToString();
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

            var accessRs = await KeeperNSFAccessHelpers.FetchRecordAccessDetailsAsync(vault, recordUids)
                .ConfigureAwait(false);

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
                            if (dryRun)
                            {
                                result.Denies.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, ChangeType = "deny",
                                    Success = true, Message = "dry-run",
                                });
                            }
                            else
                            {
                                try
                                {
                                    await DenyInheritedKeeperNSFRecordShareAsync(
                                        vault, access.RecordUid, access.AccessorName);
                                    result.Denies.Add(new KeeperNSFPermissionChange
                                    {
                                        RecordUid = access.RecordUid, Email = access.AccessorName,
                                        CurrentRole = curRole, ChangeType = "deny", Success = true,
                                    });
                                }
                                catch (Exception ex)
                                {
                                    result.Denies.Add(new KeeperNSFPermissionChange
                                    {
                                        RecordUid = access.RecordUid, Email = access.AccessorName,
                                        CurrentRole = curRole, ChangeType = "deny",
                                        Success = false, Message = ex.Message,
                                    });
                                }
                            }
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

                if (TryDecryptKeeperNSFRecordDetailsData(vault, recordData, recordUid, out var decrypted, out _))
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

        private const int MaxRecordDetailsUidsPerRequest = 100;

        private static async Task<RecordDetailsProto.RecordDataResponse> FetchKeeperNSFRecordDetailsDataAsync(
            this VaultOnline vault, IReadOnlyList<string> recordUids)
        {
            if (recordUids == null || recordUids.Count == 0)
            {
                throw new KeeperInvalidParameter("GetKeeperNSFRecordDetails", nameof(recordUids), "", "at least one record UID required");
            }

            var validUids = new List<string>();
            foreach (var uid in recordUids.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                var trimmed = uid.Trim();
                var uidBytes = trimmed.Base64UrlDecode();
                if (uidBytes == null || uidBytes.Length == 0)
                {
                    Trace.TraceWarning($"KeeperNSF: Skipping record details request with malformed UID '{uid}'");
                    continue;
                }

                validUids.Add(trimmed);
            }

            if (validUids.Count == 0)
            {
                throw new KeeperInvalidParameter("GetKeeperNSFRecordDetails", nameof(recordUids), "", "no valid record UIDs");
            }

            var merged = new RecordDetailsProto.RecordDataResponse();
            for (var offset = 0; offset < validUids.Count; offset += MaxRecordDetailsUidsPerRequest)
            {
                var chunk = validUids.Skip(offset).Take(MaxRecordDetailsUidsPerRequest);
                var chunkResponse = await vault.FetchKeeperNSFRecordDetailsDataChunkAsync(chunk).ConfigureAwait(false);
                merged.Data.AddRange(chunkResponse.Data);
                merged.ForbiddenRecords.AddRange(chunkResponse.ForbiddenRecords);
            }

            return merged;
        }

        private static async Task<RecordDetailsProto.RecordDataResponse> FetchKeeperNSFRecordDetailsDataChunkAsync(
            this VaultOnline vault, IEnumerable<string> recordUids)
        {
            var request = new RecordDetailsProto.RecordDataRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };

            foreach (var uid in recordUids)
            {
                request.RecordUids.Add(ByteString.CopyFrom(uid.Base64UrlDecode()));
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
                    return string.Equals(uid, trimmedUid, StringComparison.Ordinal);
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

            if (!TryDecryptKeeperNSFRecordDetailsData(vault, recordData, recordUid, out var data, out var dataJson))
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
                DataJson = dataJson,
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
            VaultOnline vault, Records.RecordData recordData, string recordUid, out NsfRecordData data, out byte[] dataJson)
        {
            data = null;
            dataJson = null;
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

            dataJson = decryptedBytes;
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
