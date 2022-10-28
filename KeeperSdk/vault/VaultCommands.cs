using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using KeeperSecurity.Vault;
#if NET452_OR_GREATER
using KeeperSecurity.Utils;
#endif

namespace KeeperSecurity.Commands
{
    /// <exclude/>
    [DataContract]
    public class RecordAccessPath : IRecordAccessPath
    {
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class RecordAddCommand : AuthenticatedCommand
    {
        public RecordAddCommand() : base("record_add")
        {
        }

        [DataMember(Name = "record_uid")]
        public string RecordUid;

        [DataMember(Name = "record_key")]
        public string RecordKey;

        [DataMember(Name = "record_type")]
        public string RecordType; // password

        [DataMember(Name = "folder_type")] // one of: user_folder, shared_folder, shared_folder_folder
        public string FolderType;

        [DataMember(Name = "how_long_ago")]
        public int HowLongAgo = 0;

        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string FolderUid;

        [DataMember(Name = "folder_key", EmitDefaultValue = false)]
        public string FolderKey;

        [DataMember(Name = "data")]
        public string Data;

        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string Extra;

        [DataMember(Name = "non_shared_data", EmitDefaultValue = false)]
        public string NonSharedData;

        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] FileIds;
    }

    /// <exclude/>
    [DataContract]
    public class RecordUpdateUData : IExtensibleDataObject
    {
        [DataMember(Name = "file_ids", EmitDefaultValue = false)]
        public string[] FileIds;

        public ExtensionDataObject ExtensionData { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class RecordNonSharedData : IExtensibleDataObject
    {
        public ExtensionDataObject ExtensionData { get; set; }
    }


    /// <exclude/>
    [DataContract]
    public class RecordUpdateRecord : IRecordAccessPath
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

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

        [DataMember(Name = "revision")]
        public long Revision;

        [DataMember(Name = "version")]
        public long Version = 2;

        [DataMember(Name = "client_modified_time")]
        public long ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class RecordUpdateCommand : AuthenticatedCommand
    {
        public RecordUpdateCommand() : base("record_update")
        {
        }

        [DataMember(Name = "pt")]
        public string pt = DateTime.Now.Ticks.ToString("x");

        [DataMember(Name = "client_time")]
        public long ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "add_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] AddRecords;

        [DataMember(Name = "update_records", EmitDefaultValue = false)]
        public RecordUpdateRecord[] UpdateRecords;

        [DataMember(Name = "remove_records", EmitDefaultValue = false)]
        public string[] RemoveRecords;

        [DataMember(Name = "delete_records", EmitDefaultValue = false)]
        public string[] DeleteRecords;
    }

    /// <exclude/>
    [DataContract]
    public class RecordUpdateStatus
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid;

        [DataMember(Name = "status_code")]
        public string StatusCode;
    }

    /// <exclude/>
    [DataContract]
    public class RecordUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_records")]
        public RecordUpdateStatus[] AddRecords;

        [DataMember(Name = "update_records")]
        public RecordUpdateRecord[] UpdateRecords;

        [DataMember(Name = "remove_records")]
        public RecordUpdateStatus[] RemoveRecords;

        [DataMember(Name = "delete_records")]
        public RecordUpdateStatus[] DeleteRecords;

        [DataMember(Name = "revision")]
        public long Revision;
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateCommand : AuthenticatedCommand, ISharedFolderAccessPath
    {
        public SharedFolderUpdateCommand() : base("shared_folder_update")
        {
            pt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        }

        [DataMember(Name = "pt", EmitDefaultValue = false)]
        public string pt;

        [DataMember(Name = "operation")]
        public string operation;

        [DataMember(Name = "shared_folder_uid")]
        public string shared_folder_uid;

        [DataMember(Name = "from_team_uid", EmitDefaultValue = false)]
        public string from_team_uid;

        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string name;

        [DataMember(Name = "revision", EmitDefaultValue = false)]
        public long? revision;

        [DataMember(Name = "force_update", EmitDefaultValue = false)]
        public bool? forceUpdate;

        [DataMember(Name = "default_manage_users", EmitDefaultValue = false)]
        public bool? DefaultManageUsers { get; set; }

        [DataMember(Name = "default_manage_records", EmitDefaultValue = false)]
        public bool? DefaultManageRecords { get; set; }

        [DataMember(Name = "default_can_edit", EmitDefaultValue = false)]
        public bool? DefaultCanEdit { get; set; }

        [DataMember(Name = "default_can_share", EmitDefaultValue = false)]
        public bool? DefaultCanShare { get; set; }

        [DataMember(Name = "add_users", EmitDefaultValue = false)]
        public SharedFolderUpdateUser[] addUsers;

        [DataMember(Name = "update_users", EmitDefaultValue = false)]
        public SharedFolderUpdateUser[] updateUsers;

        [DataMember(Name = "remove_users", EmitDefaultValue = false)]
        public SharedFolderUpdateUser[] removeUsers;

        [DataMember(Name = "add_teams", EmitDefaultValue = false)]
        public SharedFolderUpdateTeam[] addTeams;

        [DataMember(Name = "update_teams", EmitDefaultValue = false)]
        public SharedFolderUpdateTeam[] updateTeams;

        [DataMember(Name = "remove_teams", EmitDefaultValue = false)]
        public SharedFolderUpdateTeam[] removeTeams;

        [DataMember(Name = "add_records", EmitDefaultValue = false)]
        public SharedFolderUpdateRecord[] addRecords;

        [DataMember(Name = "update_records", EmitDefaultValue = false)]
        public SharedFolderUpdateRecord[] updateRecords;

        [DataMember(Name = "remove_records", EmitDefaultValue = false)]
        public SharedFolderUpdateRecord[] removeRecords;

        public string SharedFolderUid
        {
            get => shared_folder_uid;
            set => shared_folder_uid = value;
        }

        public string TeamUid
        {
            get => from_team_uid;
            set => from_team_uid = value;
        }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateUser
    {
        [DataMember(Name = "username", EmitDefaultValue = false)]
        public string Username { get; set; }

        [DataMember(Name = "manage_users", EmitDefaultValue = false)]
        public bool? ManageUsers { get; set; }

        [DataMember(Name = "manage_records", EmitDefaultValue = false)]
        public bool? ManageRecords { get; set; }

        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)]
        public string SharedFolderKey { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateTeam
    {
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }

        [DataMember(Name = "manage_users", EmitDefaultValue = false)]
        public bool? ManageUsers { get; set; }

        [DataMember(Name = "manage_records", EmitDefaultValue = false)]
        public bool? ManageRecords { get; set; }

        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)]
        public string SharedFolderKey { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateRecord : IRecordAccessPath
    {
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }

        [DataMember(Name = "can_edit", EmitDefaultValue = false)]
        public bool? CanEdit { get; set; }

        [DataMember(Name = "can_share", EmitDefaultValue = false)]
        public bool? CanShare { get; set; }

        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string RecordKey { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_users")]
        public SharedFolderUpdateUserStatus[] addUsers;

        [DataMember(Name = "update_users")]
        public SharedFolderUpdateUserStatus[] updateUsers;

        [DataMember(Name = "remove_users")]
        public SharedFolderUpdateUserStatus[] removeUsers;

        [DataMember(Name = "add_teams")]
        public SharedFolderUpdateTeamStatus[] addTeams;

        [DataMember(Name = "update_teams")]
        public SharedFolderUpdateTeamStatus[] updateTeams;

        [DataMember(Name = "remove_teams")]
        public SharedFolderUpdateTeamStatus[] removeTeams;

        [DataMember(Name = "add_records")]
        public SharedFolderUpdateRecordStatus[] addRecords;

        [DataMember(Name = "update_records")]
        public SharedFolderUpdateRecordStatus[] updateRecords;

        [DataMember(Name = "remove_records")]
        public SharedFolderUpdateRecordStatus[] removeRecords;
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateUserStatus
    {
        [DataMember(Name = "username")]
        public string Username { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateTeamStatus
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class SharedFolderUpdateRecordStatus
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class MoveObject
    {
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;

        [DataMember(Name = "uid", EmitDefaultValue = false)]
        public string uid;

        [DataMember(Name = "from_type", EmitDefaultValue = false)]
        public string fromType;

        [DataMember(Name = "from_uid", EmitDefaultValue = false)]
        public string fromUid;

        [DataMember(Name = "can_edit")]
        public bool canEdit { get; set; }

        [DataMember(Name = "can_reshare")]
        public bool canShare { get; set; }

        [DataMember(Name = "cascade")]
        public bool cascade { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class TransitionKey
    {
        [DataMember(Name = "uid", EmitDefaultValue = false)]
        public string uid;

        [DataMember(Name = "key", EmitDefaultValue = false)]
        public string key;
    }

    /// <exclude/>
    [DataContract]
    public class MoveCommand : AuthenticatedCommand
    {
        public MoveCommand() : base("move")
        {
        }

        [DataMember(Name = "to_type", EmitDefaultValue = false)]
        public string toType;

        [DataMember(Name = "to_uid", EmitDefaultValue = false)]
        public string toUid;

        [DataMember(Name = "link")]
        public bool isLink;

        [DataMember(Name = "move", EmitDefaultValue = false)]
        public MoveObject[] moveObjects;

        [DataMember(Name = "transition_keys", EmitDefaultValue = false)]
        public TransitionKey[] transitionKeys;

    }

    /// <exclude/>
    [DataContract]
    public class FolderCommand : AuthenticatedCommand
    {
        public FolderCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string FolderUid { get; set; }

        [DataMember(Name = "folder_type", EmitDefaultValue = false)]
        public string FolderType { get; set; }

        [DataMember(Name = "parent_uid", EmitDefaultValue = false)]
        public string ParentUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data { get; set; }

        [DataMember(Name = "manage_users", EmitDefaultValue = false)]
        public bool? ManageUsers { get; set; }

        [DataMember(Name = "manage_records", EmitDefaultValue = false)]
        public bool? ManageRecords { get; set; }

        [DataMember(Name = "can_edit", EmitDefaultValue = false)]
        public bool? CanEdit { get; set; }

        [DataMember(Name = "can_share", EmitDefaultValue = false)]
        public bool? CanShare { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class FolderAddCommand : FolderCommand
    {
        public FolderAddCommand() : base("folder_add")
        {
        }

        [DataMember(Name = "key", EmitDefaultValue = false)]
        public string Key { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class FolderUpdateCommand : FolderCommand
    {
        public FolderUpdateCommand() : base("folder_update")
        {
        }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class AddFolderResponse : KeeperApiResponse
    {
        [DataMember(Name = "revision")]
        public long revision;
    }

    /// <exclude/>
    [DataContract]
    public class PreDeleteObject
    {
        [DataMember(Name = "object_uid", EmitDefaultValue = false)]
        public string objectUid;

        [DataMember(Name = "object_type", EmitDefaultValue = false)]
        public string objectType;

        [DataMember(Name = "from_uid", EmitDefaultValue = false)]
        public string fromUid;

        [DataMember(Name = "from_type", EmitDefaultValue = false)]
        public string fromType;

        [DataMember(Name = "delete_resolution", EmitDefaultValue = false)]
        public string deleteResolution;
    }

    /// <exclude/>
    [DataContract]
    public class PreDeleteCommand : AuthenticatedCommand
    {
        public PreDeleteCommand() : base("pre_delete")
        {
        }

        [DataMember(Name = "objects", EmitDefaultValue = false)]
        public PreDeleteObject[] objects;
    }

    /// <exclude/>
    [DataContract]
    public class WouldDeleteObject
    {
        [DataMember(Name = "deletion_summary", EmitDefaultValue = false)]
        public string[] deletionSummary;
    }

    /// <exclude/>
    [DataContract]
    public class PreDeleteResponseObject
    {
        [DataMember(Name = "pre_delete_token", EmitDefaultValue = false)]
        public string preDeleteToken;

        [DataMember(Name = "would_delete", EmitDefaultValue = false)]
        public WouldDeleteObject wouldDelete;
    }

    /// <exclude/>
    [DataContract]
    public class PreDeleteResponse : KeeperApiResponse
    {
        [DataMember(Name = "pre_delete_response", EmitDefaultValue = false)]
        public PreDeleteResponseObject preDeleteResponse;
    }

    /// <exclude/>
    [DataContract]
    public class DeleteCommand : AuthenticatedCommand
    {
        public DeleteCommand() : base("delete")
        {
        }

        [DataMember(Name = "pre_delete_token", EmitDefaultValue = false)]
        public string preDeleteToken;
    }

    /// <exclude/>
    [DataContract]
    public class GetAvailableTeamsCommand : AuthenticatedCommand
    {
        public GetAvailableTeamsCommand() : base("get_available_teams")
        {
        }
    }

    /// <exclude/>
    [DataContract]
    public class AvailableTeam
    {
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string teamUid;
        [DataMember(Name = "team_name", EmitDefaultValue = false)]
        public string teamName;
    }

    /// <exclude/>
    [DataContract]
    public class GetAvailableTeamsResponse : KeeperApiResponse
    {
        [DataMember(Name = "teams", EmitDefaultValue = false)]
        public AvailableTeam[] teams;
    }

    /// <exclude/>
    [DataContract]
    public class GetShareAutoCompleteCommand : AuthenticatedCommand
    {
        public GetShareAutoCompleteCommand() : base("get_share_auto_complete")
        {
        }

        [DataMember(Name = "starts_with", EmitDefaultValue = false)]
        public string StartsWith { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class ShareUserInfo
    {
        [DataMember(Name = "email")]
        public string Email { get; set; }
    }

    /// <exclude/>
    [DataContract]
    public class GetShareAutoCompleteResponse : KeeperApiResponse
    {
        [DataMember(Name = "shares_from_users")]
        public ShareUserInfo[] SharesFromUsers;

        [DataMember(Name = "shares_with_users")]
        public ShareUserInfo[] SharesWithUsers;

        [DataMember(Name = "group_users	")]
        public ShareUserInfo[] GroupUsers;
    }

    /// <exclude/>
    [DataContract]
    public class PublicKeysCommand : AuthenticatedCommand
    {
        public PublicKeysCommand() : base("public_keys")
        {
        }

        [DataMember(Name = "key_owners", EmitDefaultValue = false)]
        public string[] keyOwners;
    }

    /// <exclude/>
    [DataContract]
    public class UserPublicKeysObject
    {
        [DataMember(Name = "key_owner", EmitDefaultValue = false)]
        public string keyOwner;
        [DataMember(Name = "public_key", EmitDefaultValue = false)]
        public string publicKey;
        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string resultCode;
        [DataMember(Name = "message", EmitDefaultValue = false)]
        public string message;
    }

    /// <exclude/>
    [DataContract]
    public class PublicKeysResponse : KeeperApiResponse
    {
        [DataMember(Name = "public_keys", EmitDefaultValue = false)]
        public UserPublicKeysObject[] publicKeys;
    }

    /// <exclude/>
    [DataContract]
    public class TeamKeyObject
    {
        [DataMember(Name = "team_uid")]
        public string teamUid;
        [DataMember(Name = "key")]
        public string key;
        [DataMember(Name = "type")]
        public int keyType;
        [DataMember(Name = "result_code")]
        public string resultCode;
        [DataMember(Name = "message")]
        public string message;
    }

    /// <exclude/>
    [DataContract]
    public class TeamGetKeysCommand : AuthenticatedCommand
    {
        public TeamGetKeysCommand() : base("team_get_keys")
        {
        }

        [DataMember(Name = "teams", EmitDefaultValue = false)]
        public string[] teams;
    }

    /// <exclude/>
    [DataContract]
    public class TeamGetKeysResponse : KeeperApiResponse
    {
        [DataMember(Name = "keys", EmitDefaultValue = false)]
        public TeamKeyObject[] keys;
    }

    [DataContract]
    internal class RequestDownloadCommand : AuthenticatedCommand, IRecordAccessPath
    {
        public RequestDownloadCommand() : base("request_download")
        {
        }

        [DataMember(Name = "file_ids")]
        public string[] FileIDs;

        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    [DataContract]
    internal class RequestUploadCommand : AuthenticatedCommand
    {
        public RequestUploadCommand() : base("request_upload")
        {
        }

        [DataMember(Name = "file_count")]
        public int FileCount = 0;

        [DataMember(Name = "thumbnail_count")]
        public int ThumbnailCount = 0;
    }

    [DataContract]
    internal class RequestDownload
    {
        [DataMember(Name = "success_status_code")]
        public int SuccessStatusCode;

        [DataMember(Name = "url")]
        public string Url;
    }

    [DataContract]
    [KnownType(typeof(RequestDownload))]
    internal class RequestDownloadResponse : KeeperApiResponse
    {

        [DataMember(Name = "downloads")]
        public RequestDownload[] Downloads;
    }

    [DataContract]
    internal class UploadParameters
    {
        [DataMember(Name = "url")]
        public string Url;

        [DataMember(Name = "max_size")]
        public long MaxSize;

        [DataMember(Name = "success_status_code")]
        public int SuccessStatusCode;

        [DataMember(Name = "file_id")]
        public string FileId;

        [DataMember(Name = "file_parameter")]
        public string FileParameter;

        [DataMember(Name = "parameters")]
        public IDictionary<string, object> Parameters;

    }

    [DataContract]
    internal class RequestUploadResponse : KeeperApiResponse
    {
        [DataMember(Name = "file_uploads")]
        public UploadParameters[] FileUploads;

        [DataMember(Name = "thumbnail_uploads")]
        public UploadParameters[] ThumbnailUploads;
    }


    [DataContract]
    internal class CancelShareCommand : AuthenticatedCommand
    {
        public CancelShareCommand() : base("cancel_share")
        {
        }

        [DataMember(Name = "from_email")]
        public string FromEmail;

        [DataMember(Name = "to_email")]
        public string ToEmail;
    }

    [DataContract]
    internal class RecordShareObject : IRecordAccessPath
    {
        [DataMember(Name = "to_username")]
        public string ToUsername;

        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string RecordKey;

        [DataMember(Name = "use_ecc_key", EmitDefaultValue = false)]
        public bool? useEccKey;

        [DataMember(Name = "editable", EmitDefaultValue = false)]
        public bool? Editable;

        [DataMember(Name = "shareable", EmitDefaultValue = false)]
        public bool? Shareable;

        [DataMember(Name = "transfer", EmitDefaultValue = false)]
        public bool? Transfer;

        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    [DataContract]
    internal class RecordShareUpdateCommand : AuthenticatedCommand
    {
        public RecordShareUpdateCommand() : base("record_share_update")
        {
            Pt = "Commander";
        }

        [DataMember(Name = "pt")]
        public string Pt;

        [DataMember(Name = "add_shares", EmitDefaultValue = false)]
        public RecordShareObject[] AddShares;

        [DataMember(Name = "update_shares", EmitDefaultValue = false)]
        public RecordShareObject[] UpdateShares;

        [DataMember(Name = "remove_shares", EmitDefaultValue = false)]
        public RecordShareObject[] RemoveShares;
    }

    [DataContract]
    internal class RecordShareStatus
    {
        [DataMember(Name = "username")]
        public string Username;
        [DataMember(Name = "record_uid")]
        public string RecordUid;
        [DataMember(Name = "status")]
        public string Status;
        [DataMember(Name = "message")]
        public string Message;
    }

    [DataContract]
    internal class RecordShareUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_statuses")]
        public RecordShareStatus[] AddStatuses;
        [DataMember(Name = "update_statuses")]
        public RecordShareStatus[] UpdateStatuses;
        [DataMember(Name = "remove_statuses")]
        public RecordShareStatus[] RemoveStatuses;
    }

    [DataContract]
    internal class GetRecordsCommand : AuthenticatedCommand
    {
        public GetRecordsCommand() : base("get_records")
        {
        }

        [DataMember(Name = "include", EmitDefaultValue = false)]
        public string[] Include;

        [DataMember(Name = "client_time")]
        public long ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        [DataMember(Name = "records", EmitDefaultValue = false)]
        public RecordAccessPath[] Records;
    }


    [DataContract]
    internal class RecordUserPermission
    {
        [DataMember(Name = "username")]
        public string Username;

        [DataMember(Name = "owner")]
        public bool Owner { get; set; }

        [DataMember(Name = "sharable")]
        public bool Sharable { get; set; }

        [DataMember(Name = "editable")]
        public bool Editable { get; set; }

        [DataMember(Name = "awaiting_approval")]
        public bool AwaitingApproval { get; set; }
    }

    [DataContract]
    internal class RecordSharedFolderPermission
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid;

        [DataMember(Name = "revision")]
        public long Revision;

        [DataMember(Name = "reshareable")]
        public bool Reshareable { get; set; }

        [DataMember(Name = "editable")]
        public bool Editable { get; set; }
    }

    [DataContract]
    internal class RecordDetail
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid;

        [DataMember(Name = "revision")]
        public long Revision;

        [DataMember(Name = "version")]
        public int Version;

        [DataMember(Name = "shared")]
        public bool Shared;

        [DataMember(Name = "data")]
        public string Data;

        [DataMember(Name = "extra")]
        public string Extra;

        [DataMember(Name = "non_shared_data")]
        public string NonSharedData;

        [DataMember(Name = "user_permissions")]
        public RecordUserPermission[] UserPermissions;

        [DataMember(Name = "shared_folder_permissions")]
        public RecordSharedFolderPermission[] SharedFolderPermissions;
    }

    [DataContract]
    internal class GetRecordsResponse : KeeperApiResponse
    {
        [DataMember(Name = "records", EmitDefaultValue = false)]
        public RecordDetail[] Records;
    }
}
