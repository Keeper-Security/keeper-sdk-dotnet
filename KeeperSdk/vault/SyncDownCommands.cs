using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Commands
{
    [DataContract]
    public class SyncDownCommand : AuthenticatedCommand
    {
        public SyncDownCommand() : base("sync_down")
        {
            clientTime = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        }

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "include")]
        public string[] include;

        [DataMember(Name = "device_name")]
        public string deviceName;

        [DataMember(Name = "client_time")]
        public long clientTime;
    }

#pragma warning disable 0649
    [DataContract]
    public class SyncDownResponse : KeeperApiResponse
    {
        [DataMember(Name = "full_sync")]
        public bool fullSync;

        [DataMember(Name = "revision")]
        public long revision;

        [DataMember(Name = "records")]
        public SyncDownRecord[] records;

        [DataMember(Name = "shared_folders")]
        public SyncDownSharedFolder[] sharedFolders;

        [DataMember(Name = "teams")]
        public SyncDownTeam[] teams;

        [DataMember(Name = "non_shared_data")]
        public SyncDownNonSharedData[] nonSharedData;

        [DataMember(Name = "record_meta_data")]
        public SyncDownRecordMetaData[] recordMetaData;

        [DataMember(Name = "pending_shares_from")]
        public string[] pendingSharesFrom;

        [DataMember(Name = "sharing_changes")]
        public SyncDownSharingChanges[] sharingChanges;

        [DataMember(Name = "removed_shared_folders")]
        public string[] removedSharedFolders;

        [DataMember(Name = "removed_records")]
        public string[] removedRecords;

        [DataMember(Name = "removed_teams")]
        public string[] removedTeams;

        [DataMember(Name = "user_folders")]
        public SyncDownUserFolder[] userFolders;

        [DataMember(Name = "user_folder_records")]
        public SyncDownFolderRecord[] userFolderRecords;

        [DataMember(Name = "user_folders_removed")]
        public SyncDownFolderNode[] userFoldersRemoved;

        [DataMember(Name = "user_folders_removed_records")]
        public SyncDownFolderRecordNode[] userFoldersRemovedRecords;

        [DataMember(Name = "user_folder_shared_folders")]
        public SyncDownUserFolderSharedFolder[] userFolderSharedFolders;

        [DataMember(Name = "user_folder_shared_folders_removed")]
        public SyncDownUserFolderSharedFolder[] userFolderSharedFoldersRemoved;

        [DataMember(Name = "shared_folder_folders")]
        public SyncDownSharedFolderFolder[] sharedFolderFolders;

        [DataMember(Name = "shared_folder_folder_removed")]
        public SyncDownSharedFolderFolderNode[] sharedFolderFolderRemoved;

        [DataMember(Name = "shared_folder_folder_records")]
        public SyncDownSharedFolderFolderRecordNode[] sharedFolderFolderRecords;

        [DataMember(Name = "shared_folder_folder_records_removed")]
        public SyncDownSharedFolderFolderRecordNode[] sharedFolderFolderRecordsRemoved;
    }

    [DataContract]
    public class SyncDownRecord : IPasswordRecord
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [DataMember(Name = "version")]
        public long Version { get; set; }

        [DataMember(Name = "shared")]
        public bool Shared { get; set; }

        [DataMember(Name = "client_modified_time")]
        public long ClientModifiedTime { get; set; }

        [DataMember(Name = "data")]
        public string Data { get; set; }

        [DataMember(Name = "extra")]
        public string Extra { get; set; }

        [DataMember(Name = "udata")]
        public SyncDownRecordUData udata;

        public string Udata { get; set; }

        public bool Owner { get; set; }

        string IUid.Uid => RecordUid;
    }

    [DataContract]
    public class SyncDownSharedFolder : ISharedFolder
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [DataMember(Name = "shared_folder_key")]
        public string SharedFolderKey { get; set; }

        [DataMember(Name = "key_type")]
        public int? KeyType { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "full_sync")]
        public bool? fullSync;

        [DataMember(Name = "manage_records")]
        public bool? ManageRecords { get; set; }

        [DataMember(Name = "manage_users")]
        public bool? ManageUsers { get; set; }

        [DataMember(Name = "default_manage_records")]
        public bool DefaultManageRecords { get; set; }

        [DataMember(Name = "default_manage_users")]
        public bool DefaultManageUsers { get; set; }

        [DataMember(Name = "default_can_edit")]
        public bool DefaultCanEdit { get; set; }

        [DataMember(Name = "default_can_share")]
        public bool DefaultCanShare { get; set; }

        [DataMember(Name = "records")]
        public SyncDownSharedFolderRecord[] records;

        [DataMember(Name = "users")]
        public SyncDownSharedFolderUser[] users;

        [DataMember(Name = "teams")]
        public SyncDownSharedFolderTeam[] teams;

        [DataMember(Name = "records_removed")]
        public string[] recordsRemoved;

        [DataMember(Name = "users_removed")]
        public string[] usersRemoved;

        [DataMember(Name = "teams_removed")]
        public string[] teamsRemoved;

        string IUid.Uid => SharedFolderUid;
    }

    [DataContract]
    public class SyncDownTeam : IEnterpriseTeam
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "team_key")]
        public string TeamKey { get; set; }

        [DataMember(Name = "team_key_type")]
        public int KeyType { get; set; }

        [DataMember(Name = "team_private_key")]
        public string TeamPrivateKey { get; set; }

        [DataMember(Name = "restrict_edit")]
        public bool RestrictEdit { get; set; }

        [DataMember(Name = "restrict_share")]
        public bool RestrictShare { get; set; }

        [DataMember(Name = "restrict_view")]
        public bool RestrictView { get; set; }

        [DataMember(Name = "removed_shared_folders")]
        public string[] removedSharedFolders;

        [DataMember(Name = "shared_folder_keys")]
        public SyncDownSharedFolderKey[] sharedFolderKeys;

        string IUid.Uid => TeamUid;
    }

    [DataContract]
    public class SyncDownSharedFolderRecord
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "record_key")]
        public string RecordKey { get; set; }

        [DataMember(Name = "can_share")]
        public bool CanShare { get; set; }

        [DataMember(Name = "can_edit")]
        public bool CanEdit { get; set; }
    }

    [DataContract]
    public class SyncDownSharedFolderTeam : ISharedFolderPermission
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "manage_records")]
        public bool ManageRecords { get; set; }

        [DataMember(Name = "manage_users")]
        public bool ManageUsers { get; set; }

        public string SharedFolderUid { get; set; }

        string ISharedFolderPermission.UserId => TeamUid;
        int ISharedFolderPermission.UserType => (int) UserType.Team;
        string IUidLink.SubjectUid => SharedFolderUid;
        string IUidLink.ObjectUid => TeamUid;
    }

    [DataContract]
    public class SyncDownSharedFolderKey : ISharedFolderKey
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "shared_folder_key")]
        public string SharedFolderKey { get; set; }

        [DataMember(Name = "key_type")]
        public int KeyType { get; set; }

        public string TeamUid { get; set; }

        string IUidLink.SubjectUid => SharedFolderUid;
        string IUidLink.ObjectUid => TeamUid;
    }


    [DataContract]
    public class SyncDownSharedFolderUser : ISharedFolderPermission
    {
        [DataMember(Name = "username")]
        public string Username { get; set; }

        [DataMember(Name = "manage_records")]
        public bool ManageRecords { get; set; }

        [DataMember(Name = "manage_users")]
        public bool ManageUsers { get; set; }

        public string SharedFolderUid { get; set; }

        string IUidLink.SubjectUid => SharedFolderUid;
        string IUidLink.ObjectUid => Username;
        string ISharedFolderPermission.UserId => Username;
        int ISharedFolderPermission.UserType => (int) UserType.User;
    }

    [DataContract]
    public class SyncDownRecordMetaData : IRecordMetadata
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "owner")]
        public bool Owner { get; set; }

        [DataMember(Name = "record_key")]
        public string RecordKey { get; set; }

        [DataMember(Name = "record_key_type")]
        public int RecordKeyType { get; set; }

        [DataMember(Name = "can_share")]
        public bool CanShare { get; set; }

        [DataMember(Name = "can_edit")]
        public bool CanEdit { get; set; }

        public string SharedFolderUid { get; set; }
        string IUidLink.SubjectUid => RecordUid;
        string IUidLink.ObjectUid => SharedFolderUid;
    }

    [DataContract]
    public class SyncDownFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;
    }

    [DataContract]
    public class SyncDownSharedFolderFolderNode
    {
        [DataMember(Name = "folder_uid")]
        public string FolderUid { get; set; }

        [DataMember(Name = "parent_uid")]
        public string ParentUid { get; set; }

        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }
    }

    [DataContract]
    public class SyncDownFolderRecordNode
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "record_uid")]
        public string recordUid;

        public string FolderUid => folderUid;
        public string RecordUid => recordUid;
    }

    [DataContract]
    public class SyncDownSharedFolderFolderRecordNode : IFolderRecordLink
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "shared_folder_uid")]
        public string sharedFolderUid;

        string IFolderRecordLink.FolderUid => folderUid ?? sharedFolderUid;
        string IFolderRecordLink.RecordUid => recordUid;

        string IUidLink.SubjectUid => folderUid ?? sharedFolderUid;
        string IUidLink.ObjectUid => recordUid;
    }

    [DataContract]
    public class SyncDownFolderRecord : IFolderRecordLink
    {
        [DataMember(Name = "folder_uid")]
        public string FolderUid { get; set; }

        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "revision")]
        public long revision;

        string IUidLink.SubjectUid => FolderUid;
        string IUidLink.ObjectUid => RecordUid;
    }

    [DataContract]
    public class SyncDownUserFolder : IFolder
    {
        [DataMember(Name = "folder_uid")]
        public string FolderUid { get; set; }

        [DataMember(Name = "parent_uid")]
        public string ParentUid { get; set; }

        [DataMember(Name = "user_folder_key")]
        public string FolderKey { get; set; }

        [DataMember(Name = "key_type")]
        public int keyType;

        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [DataMember(Name = "type")]
        public string FolderType { get; set; }

        [DataMember(Name = "data")]
        public string Data { get; set; }

        string IFolder.SharedFolderUid => null;

        string IUid.Uid => FolderUid;
    }

    [DataContract]
    public class SyncDownSharedFolderFolder : IFolder
    {
        [DataMember(Name = "folder_uid")]
        public string FolderUid { get; set; }

        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "parent_uid")]
        public string ParentUid { get; set; }

        [DataMember(Name = "shared_folder_folder_key")]
        public string SharedFolderFolderKey;

        string IFolder.FolderKey => SharedFolderFolderKey;

        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [DataMember(Name = "type")]
        public string FolderType { get; set; }

        [DataMember(Name = "data")]
        public string Data { get; set; }

        string IUid.Uid => FolderUid;
    }

    [DataContract]
    public class SyncDownUserFolderSharedFolder : IFolder
    {
        [DataMember(Name = "folder_uid")]
        public string folderUid;

        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }

        public string FolderUid => SharedFolderUid;
        string IFolder.ParentUid => folderUid ?? "";
        string IFolder.FolderType => "shared_folder";
        string IFolder.FolderKey => null;
        long IFolder.Revision => 0;
        string IFolder.Data => null;

        string IUid.Uid => FolderUid;
    }

    [DataContract]
    public class SyncDownSharingChanges
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "shared")]
        public bool shared;
    }

    [DataContract]
    public class SyncDownNonSharedData : INonSharedData
    {
        [DataMember(Name = "record_uid")]
        public string recordUid;

        [DataMember(Name = "data")]
        public string data;

        public string RecordUid => recordUid;

        public string Data
        {
            get => data;
            set => data = value;
        }

        public string Uid => RecordUid;
    }

    [DataContract]
    public class FolderData
    {
        [DataMember(Name = "name")]
        public string name;
    }

#pragma warning restore 0649

#pragma warning disable 0649
    [DataContract]
    public class RecordDataCustom
    {
        [DataMember(Name = "name")]
        public string name = "";

        [DataMember(Name = "value")]
        public string value = "";

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;
    }

    [DataContract]
    public class RecordData
    {
        [DataMember(Name = "title")]
        public string title = "";

        [DataMember(Name = "folder")]
        public string folder = "";

        [DataMember(Name = "secret1")]
        public string secret1 = "";

        [DataMember(Name = "secret2")]
        public string secret2 = "";

        [DataMember(Name = "link")]
        public string link = "";

        [DataMember(Name = "notes")]
        public string notes = "";

        [DataMember(Name = "custom", EmitDefaultValue = false)]
        public RecordDataCustom[] custom;
    }

    [DataContract]
    public class RecordExtraFileThumb
    {
        [DataMember(Name = "id")]
        public string id = "";

        [DataMember(Name = "type")]
        public string type = "";

        [DataMember(Name = "size")]
        public int? size;
    }

    [DataContract]
    public class RecordExtraFile
    {
        [DataMember(Name = "id")]
        public string id = "";

        [DataMember(Name = "name")]
        public string name = "";

        [DataMember(Name = "key")]
        public string key;

        [DataMember(Name = "size", EmitDefaultValue = false)]
        public long? size;

        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string title;

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;

        [DataMember(Name = "lastModified", EmitDefaultValue = false)]
        public long? lastModified;

        [DataMember(Name = "thumbs")]
        public RecordExtraFileThumb[] thumbs;
    }

    [DataContract]
    public class RecordExtra : IExtensibleDataObject
    {
        [DataMember(Name = "files", EmitDefaultValue = false)]
        public RecordExtraFile[] files;

        [DataMember(Name = "fields", EmitDefaultValue = false)]
        public Dictionary<string, object>[] fields;

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    public class SyncDownRecordUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids")]
        public string[] fileIds;

        public ExtensionDataObject ExtensionData { get; set; }
    }


#pragma warning restore 0649
}