//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
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
        public IList<CustomField> Custom { get; } = new List<CustomField>();
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();

        public byte[] RecordKey { get; internal set; }
    }

    public class CustomField
    {
        public string Name { get; set; }
        public string Value { get; set; }
        public string Type { get; set; }
    }

    public class AttachmentFileThumb
    {
        public string Id { get; internal set; }
        public string Type { get; internal set; }
        public int Size { get; internal set; }
    }

    public class AttachmentFile
    {
        public string Id { get; internal set; }
        public string Key { get; internal set; }
        public string Name { get; internal set; }
        public string Title { get; internal set; }
        public string Type { get; internal set; }
        public long Size { get; internal set; }
        public DateTimeOffset LastModified { get; internal set; }

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
        public SharedFolder() { }

        public string Uid { get; set; }
        public string Name { get; set; }

        public bool DefaultManageRecords { get; set; }
        public bool DefaultManageUsers { get; set; }
        public bool DefaultCanEdit { get; set; }
        public bool DefaultCanShare { get; set; }

        public List<SharedFolderPermission> UsersPermissions { get; } = new List<SharedFolderPermission>();
        public List<SharedFolderRecord> RecordPermissions { get; } = new List<SharedFolderRecord>();

        public byte[] SharedFolderKey { get; internal set; }
    }

    public class EnterpriseTeam
    {
        public EnterpriseTeam() { }
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

        public byte[] TeamKey { get; internal set; }
        public RsaPrivateCrtKeyParameters TeamPrivateKey { get; internal set; }
    }

    public enum FolderType { UserFolder, SharedFolder, SharedFolderForder }
    public class FolderNode
    {
        public string ParentUid { get; internal set; }
        public string FolderUid { get; internal set; }
        public string SharedFolderUid { get; internal set; }
        public FolderType FolderType { get; internal set; } = FolderType.UserFolder;
        public string Name { get; internal set; }
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
        public string[] fileIds;
        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class RecordUpdateRecord : IRecordAccessPath
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string recordKey;

        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string extra;

        [DataMember(Name = "udata", EmitDefaultValue = false)]
        public RecordUpdateUData udata;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "version")]
        public long version = 2;

        [DataMember(Name = "client_modified_time")]
        public long clientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public string RecordUid { get => recordUid; }
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

#pragma warning disable 0649
    [DataContract]
    internal class RecordUpdateCommand : AuthorizedCommand
    {
        public RecordUpdateCommand() : base("record_update") { }

        [DataMember(Name = "pt")]
        public string pt = DateTime.Now.Ticks.ToString("x");

        [DataMember(Name = "client_time")]
        public long clientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "add_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] addRecords;

        [DataMember(Name = "update_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] updateRecords;

        [DataMember(Name = "remove_records", EmitDefaultValue = false)]
        public string[] removeRecords;

        [DataMember(Name = "delete_records", EmitDefaultValue = false)]
        public string[] deleteRecords;
    }

    [DataContract]
    internal class RecordUpdateStatus
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "status_code")]
        public string statusCode;
    }

    [DataContract]
    internal class RecordUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_records")]
        public RecordUpdateStatus[] addRecords;

        [DataMember(Name = "update_records")]
        public RecordUpdateRecord[] updateRecords;

        [DataMember(Name = "remove_records")]
        public RecordUpdateStatus[] removeRecords;

        [DataMember(Name = "delete_records")]
        public RecordUpdateStatus[] deleteRecords;

        [DataMember(Name = "revision")]
        public long revision;
    }

    [DataContract]
    internal class RecordAddCommand : AuthorizedCommand
    {
        public RecordAddCommand() : base("record_add") { }

        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "record_key")]
        public string recordKey;

        [DataMember(Name = "record_type")]
        public string recordType;  // password
        
        [DataMember(Name = "folder_type")] // one of: user_folder, shared_folder, shared_folder_folder
        public string folderType;

        [DataMember(Name = "how_long_ago")]
        public int howLongAgo = 0;

        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string folderUid;

        [DataMember(Name = "folder_key", EmitDefaultValue = false)]
        public string folderKey;

        [DataMember(Name = "data")]
        public string data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string extra;

        [DataMember(Name = "non_shared_data", EmitDefaultValue = false)]
        public string nonSharedData;

        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] fileIds;
    }

#pragma warning restore 0649
}
