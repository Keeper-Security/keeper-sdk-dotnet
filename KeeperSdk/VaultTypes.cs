﻿//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace KeeperSecurity.Sdk
{
    public class PasswordRecord
    {
        public string Uid { get; set; }
        public bool Owner { get; set; }
        public bool Shared { get; set; }

        public string Title { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Link { get; set; }
        public string Notes { get; set; }
        public DateTimeOffset ClientModified { get; internal set; }
        public IList<CustomField> Custom { get; } = new List<CustomField>();
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();
        public IList<ExtraField> ExtraFields { get; } = new List<ExtraField>();
        public byte[] RecordKey { get; set; }

        public CustomField DeleteCustomField(string name)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf != null)
            {
                if (Custom.Remove(cf))
                {
                    return cf;
                }
            }

            return null;
        }

        public CustomField SetCustomField(string name, string value)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf == null)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return null;
                }

                cf = new CustomField
                {
                    Name = name
                };
                Custom.Add(cf);
            }
            cf.Value = value;

            return cf;
        }
    }

    public class CustomField
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
    }

    public class ExtraField
    {
        public string Id { get; set; }
        public string FieldType { get; set; }
        public string FieldTitle { get; set; }
        public Dictionary<string, object> Custom { get; } = new Dictionary<string, object>();
    }

    public class AttachmentFileThumb
    {
        public string Id { get; internal set; }
        public string Type { get; internal set; }
        public int Size { get; internal set; }
    }

    public class AttachmentFile
    {
        public string Id { get; set; }
        public string Key { get; set; }
        public string Name { get; set; }
        public string Title { get; set; }
        public string Type { get; set; }
        public long Size { get; set; }
        public DateTimeOffset LastModified { get; set; }

        public AttachmentFileThumb[] Thumbnails { get; internal set; }
    }

    public enum UserType
    {
        User = 1,
        Team = 2
    }

    public class SharedFolderPermission
    {
        public string UserId { get; internal set; }
        public UserType UserType { get; internal set; }
        public bool ManageRecords { get; internal set; }
        public bool ManageUsers { get; internal set; }
    }

    public class SharedFolderRecord
    {
        public string RecordUid { get; internal set; }
        public bool CanShare { get; internal set; }
        public bool CanEdit { get; internal set; }
    }

    public class SharedFolder
    {
        public string Uid { get; set; }
        public string Name { get; set; }

        public bool DefaultManageRecords { get; set; }
        public bool DefaultManageUsers { get; set; }
        public bool DefaultCanEdit { get; set; }
        public bool DefaultCanShare { get; set; }

        public List<SharedFolderPermission> UsersPermissions { get; } = new List<SharedFolderPermission>();
        public List<SharedFolderRecord> RecordPermissions { get; } = new List<SharedFolderRecord>();

        public byte[] SharedFolderKey { get; set; }
    }

    public class EnterpriseTeam
    {
        public EnterpriseTeam()
        {
        }

        internal EnterpriseTeam(IEnterpriseTeam et, byte[] teamKey)
        {
            TeamKey = teamKey;
            var pk = et.TeamPrivateKey.Base64UrlDecode();
            TeamPrivateKey = CryptoUtils.LoadPrivateKey(CryptoUtils.DecryptAesV1(pk, teamKey));
            TeamUid = et.TeamUid;
            Name = et.Name;
            RestrictEdit = et.RestrictEdit;
            RestrictShare = et.RestrictShare;
            RestrictView = et.RestrictView;
        }

        public string TeamUid { get; set; }
        public string Name { get; set; }
        public bool RestrictEdit { get; set; }
        public bool RestrictShare { get; set; }
        public bool RestrictView { get; set; }

        public byte[] TeamKey { get; set; }
        public RsaPrivateCrtKeyParameters TeamPrivateKey { get; internal set; }
    }

    public enum FolderType
    {
        UserFolder,
        SharedFolder,
        SharedFolderFolder
    }

    public class FolderNode
    {
        public string ParentUid { get; set; }
        public string FolderUid { get; set; }
        public string SharedFolderUid { get; set; }
        public FolderType FolderType { get; set; } = FolderType.UserFolder;
        public string Name { get; set; }
        public IList<string> Subfolders { get; } = new List<string>();
        public IList<string> Records { get; } = new List<string>();
    }

    public interface IRecordAccessPath
    {
        string RecordUid { get; }
        string SharedFolderUid { get; set; }
        string TeamUid { get; set; }
    }

    public interface ISharedFolderAccessPath
    {
        string SharedFolderUid { get; set; }
        string TeamUid { get; set; }
    }

    [DataContract]
    internal class RecordUpdateUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] FileIds;

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class RecordUpdateRecord : IRecordAccessPath
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }

        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string RecordKey;

        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string Extra;

        [DataMember(Name = "udata", EmitDefaultValue = false)]
        public RecordUpdateUData Udata;

        [DataMember(Name = "non_shared_data", EmitDefaultValue = false)]
        public string NonSharedData;

        [DataMember(Name = "revision")] public long Revision;

        [DataMember(Name = "version")] public long Version = 2;

        [DataMember(Name = "client_modified_time")]
        public long ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

#pragma warning disable 0649
    [DataContract]
    internal class RecordUpdateCommand : AuthenticatedCommand
    {
        public RecordUpdateCommand() : base("record_update")
        {
        }

        [DataMember(Name = "pt")] public string pt = DateTime.Now.Ticks.ToString("x");

        [DataMember(Name = "client_time")] public long ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "add_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] AddRecords;

        [DataMember(Name = "update_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] UpdateRecords;

        [DataMember(Name = "remove_records", EmitDefaultValue = false)]
        public string[] RemoveRecords;

        [DataMember(Name = "delete_records", EmitDefaultValue = false)]
        public string[] DeleteRecords;
    }

    [DataContract]
    internal class RecordUpdateStatus
    {
        [DataMember(Name = "record_uid")] public string RecordUid;

        [DataMember(Name = "status_code")] public string StatusCode;
    }

    [DataContract]
    internal class RecordUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_records")] public RecordUpdateStatus[] AddRecords;

        [DataMember(Name = "update_records")] public RecordUpdateRecord[] UpdateRecords;

        [DataMember(Name = "remove_records")] public RecordUpdateStatus[] RemoveRecords;

        [DataMember(Name = "delete_records")] public RecordUpdateStatus[] DeleteRecords;

        [DataMember(Name = "revision")] public long Revision;
    }

    [DataContract]
    internal class RecordAddCommand : AuthenticatedCommand
    {
        public RecordAddCommand() : base("record_add")
        {
        }

        [DataMember(Name = "record_uid")] public string RecordUid;

        [DataMember(Name = "record_key")] public string RecordKey;

        [DataMember(Name = "record_type")] public string RecordType; // password

        [DataMember(Name = "folder_type")] // one of: user_folder, shared_folder, shared_folder_folder
        public string FolderType;

        [DataMember(Name = "how_long_ago")] public int HowLongAgo = 0;

        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string FolderUid;

        [DataMember(Name = "folder_key", EmitDefaultValue = false)]
        public string FolderKey;

        [DataMember(Name = "data")] public string Data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string Extra;

        [DataMember(Name = "non_shared_data", EmitDefaultValue = false)]
        public string NonSharedData;

        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] FileIds;
    }

#pragma warning restore 0649
}