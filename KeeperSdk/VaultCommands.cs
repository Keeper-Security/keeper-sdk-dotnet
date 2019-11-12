using System;
using System.Runtime.Serialization;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class SharedFolderUpdateCommand : AuthorizedCommand, ISharedFolderAccessPath
    {
        public SharedFolderUpdateCommand() : base("shared_folder_update")
        {
            pt = KeeperEndpoint.DefaultDeviceName;
        }

        [DataMember(Name = "pt", EmitDefaultValue = false)]
        public string pt;

        [DataMember(Name = "operation")]
        public string Operation { get; set; }

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

        public string SharedFolderUid { get => shared_folder_uid; set => shared_folder_uid = value; }
        public string TeamUid { get => from_team_uid; set => from_team_uid = value; }
    }

    [DataContract]
    public class SharedFolderUpdateUser {
        [DataMember(Name = "username", EmitDefaultValue = false)]
        public string Username { get; set; }
        
        [DataMember(Name = "manage_users", EmitDefaultValue = false)]
        public bool? ManageUsers { get; set; }

        [DataMember(Name = "manage_records", EmitDefaultValue = false)]
        public bool? ManageRecords { get; set; }

        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)]
        public string SharedFolderKey { get; set; }
    }

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

    [DataContract]
    public class SharedFolderUpdateResponse : KeeperApiResponse {
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

    [DataContract]
    public class SharedFolderUpdateUserStatus {
        [DataMember(Name = "username")]
        public string Username { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    [DataContract]
    public class SharedFolderUpdateTeamStatus
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    [DataContract]
    public class SharedFolderUpdateRecordStatus
    {
        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }
    }
}
