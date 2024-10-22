using System;
using System.Runtime.Serialization;
#if NET472_OR_GREATER 
using KeeperSecurity.Utils;
#endif

namespace KeeperSecurity.Commands
{
    [DataContract]
    public class SyncDownCommand : AuthenticatedCommand
    {
        public SyncDownCommand() : base("sync_down")
        {
            ClientTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        }
        [DataMember(Name = "revision")] public long Revision;
        [DataMember(Name = "include")] public string[] Include;
        [DataMember(Name = "device_name")] public string DeviceName;
        [DataMember(Name = "client_time")] public long ClientTime;
    }

    [DataContract]
    public class SyncDownResponse : KeeperApiResponse
    {
        [DataMember(Name = "full_sync")] public bool FullSync;
        [DataMember(Name = "revision")] public long Revision;
        [DataMember(Name = "records")] public SyncDownRecord[] Records;
        [DataMember(Name = "shared_folders")] public SyncDownSharedFolder[] SharedFolders;
        [DataMember(Name = "teams")] public SyncDownTeam[] Teams;
        [DataMember(Name = "non_shared_data")] public SyncDownNonSharedData[] NonSharedData;
        [DataMember(Name = "record_meta_data")]
        public SyncDownRecordMetaData[] RecordMetaData;
        [DataMember(Name = "pending_shares_from")]
        public string[] PendingSharesFrom;
        [DataMember(Name = "sharing_changes")] public SyncDownSharingChanges[] SharingChanges;
        [DataMember(Name = "removed_shared_folders")]
        public string[] RemovedSharedFolders;
        [DataMember(Name = "removed_records")] public string[] RemovedRecords;
        [DataMember(Name = "removed_teams")] public string[] RemovedTeams;
        [DataMember(Name = "removed_links")] public SyncDownRecordLink[] RemovedLinks;
        [DataMember(Name = "user_folders")] public SyncDownUserFolder[] UserFolders;
        [DataMember(Name = "user_folder_records")]
        public SyncDownFolderRecord[] UserFolderRecords;
        [DataMember(Name = "user_folders_removed")]
        public SyncDownFolderNode[] UserFoldersRemoved;
        [DataMember(Name = "user_folders_removed_records")]
        public SyncDownFolderRecordNode[] UserFoldersRemovedRecords;
        [DataMember(Name = "user_folder_shared_folders")]
        public SyncDownUserFolderSharedFolder[] UserFolderSharedFolders;
        [DataMember(Name = "user_folder_shared_folders_removed")]
        public SyncDownUserFolderSharedFolder[] UserFolderSharedFoldersRemoved;
        [DataMember(Name = "shared_folder_folders")]
        public SyncDownSharedFolderFolder[] SharedFolderFolders;
        [DataMember(Name = "shared_folder_folder_removed")]
        public SyncDownSharedFolderFolderNode[] SharedFolderFolderRemoved;
        [DataMember(Name = "shared_folder_folder_records")]
        public SyncDownSharedFolderFolderRecordNode[] SharedFolderFolderRecords;
        [DataMember(Name = "shared_folder_folder_records_removed")]
        public SyncDownSharedFolderFolderRecordNode[] SharedFolderFolderRecordsRemoved;
    }

    [DataContract]
    public class SyncDownRecord
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "revision")] public long Revision { get; set; }
        [DataMember(Name = "version")] public int Version { get; set; }
        [DataMember(Name = "shared")] public bool Shared { get; set; }
        [DataMember(Name = "client_modified_time")]
        internal double _client_modified_time;
        public long ClientModifiedTime
        {
            get => (long) _client_modified_time;
            set => _client_modified_time = value;
        }
        [DataMember(Name = "data")] public string Data { get; set; }
        [DataMember(Name = "extra")] public string Extra { get; set; }
        [DataMember(Name = "owner_uid")] public string OwnerRecordId;
        [DataMember(Name = "link_key")] public string LinkKey;
        [DataMember(Name = "file_size")] internal long? FileSize;
        [DataMember(Name = "thumbnail_size")] internal long? ThumbnailSize;
        [DataMember(Name = "udata")] public SyncDownRecordUData udata;
        public string Udata { get; set; }
    }

    [DataContract]
    public class SyncDownSharedFolder
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
        [DataMember(Name = "revision")] public long Revision { get; set; }
        [DataMember(Name = "shared_folder_key")]
        public string SharedFolderKey { get; set; }
        [DataMember(Name = "key_type")] public int? KeyType { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "full_sync")] public bool? FullSync;
        [DataMember(Name = "manage_records")] public bool? ManageRecords { get; set; }
        [DataMember(Name = "manage_users")] public bool? ManageUsers { get; set; }
        [DataMember(Name = "default_manage_records")]
        public bool DefaultManageRecords { get; set; }
        [DataMember(Name = "default_manage_users")]
        public bool DefaultManageUsers { get; set; }
        [DataMember(Name = "default_can_edit")]
        public bool DefaultCanEdit { get; set; }
        [DataMember(Name = "default_can_share")]
        public bool DefaultCanShare { get; set; }
        [DataMember(Name = "records")] public SyncDownSharedFolderRecord[] Records;
        [DataMember(Name = "users")] public SyncDownSharedFolderUser[] Users;
        [DataMember(Name = "teams")] public SyncDownSharedFolderTeam[] Teams;
        [DataMember(Name = "records_removed")] public string[] RecordsRemoved;
        [DataMember(Name = "users_removed")] public string[] UsersRemoved;
        [DataMember(Name = "teams_removed")] public string[] TeamsRemoved;
    }

    [DataContract]
    public class SyncDownTeam
    {
        [DataMember(Name = "team_uid")] public string TeamUid { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "team_key")] public string TeamKey { get; set; }
        [DataMember(Name = "team_key_type")] public int KeyType { get; set; }
        [DataMember(Name = "team_private_key")]
        public string TeamRsaPrivateKey { get; set; }
        [DataMember(Name = "restrict_edit")] public bool RestrictEdit { get; set; }
        [DataMember(Name = "restrict_share")] public bool RestrictShare { get; set; }
        [DataMember(Name = "restrict_view")] public bool RestrictView { get; set; }
        [DataMember(Name = "removed_shared_folders")]
        public string[] RemovedSharedFolders;
        [DataMember(Name = "shared_folder_keys")]
        public SyncDownSharedFolderKey[] SharedFolderKeys;
    }

    [DataContract]
    public class SyncDownSharedFolderRecord
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "record_key")] public string RecordKey { get; set; }
        [DataMember(Name = "can_share")] public bool CanShare { get; set; }
        [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
    }

    [DataContract]
    public class SyncDownSharedFolderTeam
    {
        [DataMember(Name = "team_uid")] public string TeamUid { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
        [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
    }

    [DataContract]
    public class SyncDownSharedFolderKey
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
        [DataMember(Name = "shared_folder_key")]
        public string SharedFolderKey { get; set; }
        [DataMember(Name = "key_type")] public int KeyType { get; set; }
    }


    [DataContract]
    public class SyncDownSharedFolderUser
    {
        [DataMember(Name = "username")] public string Username { get; set; }
        [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
        [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
    }

    [DataContract]
    public class SyncDownRecordMetaData
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "owner")] public bool Owner { get; set; }
        [DataMember(Name = "record_key")] public string RecordKey { get; set; }
        [DataMember(Name = "record_key_type")] public int RecordKeyType { get; set; }
        [DataMember(Name = "can_share")] public bool CanShare { get; set; }
        [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
    }

    [DataContract]
    public class SyncDownFolderNode
    {
        [DataMember(Name = "folder_uid")] public string FolderUid;
    }

    [DataContract]
    public class SyncDownSharedFolderFolderNode
    {
        [DataMember(Name = "folder_uid")] public string FolderUid { get; set; }
        [DataMember(Name = "parent_uid")] public string ParentUid { get; set; }
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
    }

    [DataContract]
    public class SyncDownFolderRecordNode
    {
        [DataMember(Name = "folder_uid")] public string FolderUid;
        [DataMember(Name = "record_uid")] public string RecordUid;
    }

    [DataContract]
    public class SyncDownSharedFolderFolderRecordNode
    {
        [DataMember(Name = "folder_uid")] public string FolderUid;
        [DataMember(Name = "record_uid")] public string RecordUid;
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid;
    }

    [DataContract]
    public class SyncDownFolderRecord
    {
        [DataMember(Name = "folder_uid")] public string FolderUid { get; set; }
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "revision")] public long Revision;
    }

    [DataContract]
    public class SyncDownUserFolder
    {
        [DataMember(Name = "folder_uid")] public string FolderUid { get; set; }
        [DataMember(Name = "parent_uid")] public string ParentUid { get; set; }
        [DataMember(Name = "user_folder_key")] public string FolderKey { get; set; }
        [DataMember(Name = "key_type")] public int KeyType;
        [DataMember(Name = "revision")] public long Revision { get; set; }
        [DataMember(Name = "type")] public string FolderType { get; set; }
        [DataMember(Name = "data")] public string Data { get; set; }
    }

    [DataContract]
    public class SyncDownSharedFolderFolder
    {
        [DataMember(Name = "folder_uid")] public string FolderUid { get; set; }
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
        [DataMember(Name = "parent_uid")] public string ParentUid { get; set; }
        [DataMember(Name = "shared_folder_folder_key")]
        public string SharedFolderFolderKey;
        [DataMember(Name = "revision")] public long Revision { get; set; }
        [DataMember(Name = "type")] public string FolderType { get; set; }
        [DataMember(Name = "data")] public string Data { get; set; }
    }

    [DataContract]
    public class SyncDownUserFolderSharedFolder
    {
        [DataMember(Name = "folder_uid")] public string FolderUid;
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
    }

    [DataContract]
    public class SyncDownRecordLink
    {
        [DataMember(Name = "record_uid")] public string RecordUid;
        [DataMember(Name = "owner_uid")] public string OwnerUid;
    }

    [DataContract]
    public class SyncDownSharingChanges
    {
        [DataMember(Name = "record_uid")] public string RecordUid;
        [DataMember(Name = "shared")] public bool Shared;
    }

    [DataContract]
    public class SyncDownNonSharedData
    {
        [DataMember(Name = "record_uid")] public string RecordUid;
        [DataMember(Name = "data")] public string Data;
    }

    [DataContract]
    public class SyncDownRecordUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] FileIds;
        [DataMember(Name = "file_size", EmitDefaultValue = false)]
        public long? FileSize { get; set; }
        [DataMember(Name = "thumbnail_size", EmitDefaultValue = false)]
        public long? ThumbnailSize { get; set; }
        public ExtensionDataObject ExtensionData { get; set; }
    }
}