using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Commands
{
    [DataContract]
    public class RecordDataCustom
    {
        [DataMember(Name = "name")] public string Name = "";
        [DataMember(Name = "value")] public string Value = "";
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type;
    }

    [DataContract]
    public class RecordData
    {
        [DataMember(Name = "title")] public string Title = "";
        [DataMember(Name = "folder")] public string Folder = "";
        [DataMember(Name = "secret1")] public string Secret1 = "";
        [DataMember(Name = "secret2")] public string Secret2 = "";
        [DataMember(Name = "link")] public string Link = "";
        [DataMember(Name = "notes")] public string Notes = "";
        [DataMember(Name = "custom", EmitDefaultValue = false)]
        public RecordDataCustom[] Custom;
    }

    [DataContract]
    public class RecordExtraFileThumb
    {
        [DataMember(Name = "id")] public string Id = "";
        [DataMember(Name = "type")] public string Type = "";
        [DataMember(Name = "size")] public int? Size;
    }

    [DataContract]
    public class RecordExtraFile
    {
        [DataMember(Name = "id")] public string Id = "";
        [DataMember(Name = "name")] public string Name = "";
        [DataMember(Name = "key")] public string Key;
        [DataMember(Name = "size", EmitDefaultValue = false)]
        public long? Size;
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title;
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type;
        [DataMember(Name = "lastModified", EmitDefaultValue = false)]
        public long? LastModified;
        [DataMember(Name = "thumbs")] public RecordExtraFileThumb[] Thumbs;
    }

    [DataContract]
    public class RecordExtra : IExtensibleDataObject
    {
        [DataMember(Name = "files", EmitDefaultValue = false)]
        public RecordExtraFile[] Files;
        [DataMember(Name = "fields", EmitDefaultValue = false)]
        public Dictionary<string, object>[] Fields;
        public ExtensionDataObject ExtensionData { get; set; }
    }

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

    [DataContract]
    public class RecordAuditData
    {
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }
        [DataMember(Name = "record_type", EmitDefaultValue = false)]
        public string RecordType { get; set; }
        [DataMember(Name = "url", EmitDefaultValue = false)]
        public string Url { get; set; }
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

        [DataMember(Name = "status")]
        public string Status;

        [DataMember(Name = "message")]
        public string Message;
    }

    /// <exclude/>
    [DataContract]
    public class RecordUpdateResponse : KeeperApiResponse
    {
        [DataMember(Name = "add_records")]
        public RecordUpdateStatus[] AddRecords;

        [DataMember(Name = "update_records")]
        public RecordUpdateStatus[] UpdateRecords;

        [DataMember(Name = "remove_records")]
        public RecordUpdateStatus[] RemoveRecords;

        [DataMember(Name = "delete_records")]
        public RecordUpdateStatus[] DeleteRecords;

        [DataMember(Name = "revision")]
        public long Revision;
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
    public class UploadParameters
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
        public IDictionary<string, string> Parameters;

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
    public class GetDeletedRecordsCommand : AuthenticatedCommand
    {
        public GetDeletedRecordsCommand() : base("get_deleted_records")
        {
            ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        [DataMember(Name = "client_time")]
        public long ClientTime;
    }

    [DataContract]
    public class GetDeletedRecordsResponse : KeeperApiResponse
    {
        [DataMember(Name = "records")]
        public DeletedRecord[] Records;
        [DataMember(Name = "non_access_records")]
        public DeletedRecord[] NonAccessRecords;
        [DataMember(Name = "shared_folder_records")]
        public DeletedSharedFolderRecord[] SharedFolderRecords;
    }
}
