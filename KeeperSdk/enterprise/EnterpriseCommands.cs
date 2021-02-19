using System.Collections.Generic;
using System.Runtime.Serialization;

namespace KeeperSecurity.Commands
{
    [DataContract]
    public class GetEnterpriseDataCommand : AuthenticatedCommand
    {
        public GetEnterpriseDataCommand() : base("get_enterprise_data") { }

        [DataMember(Name = "include", EmitDefaultValue = false)]
        public string[] include;
    }

    public interface IEncryptedData
    {
        string EncryptedData { get; set; }
    }

    public interface IDisplayName
    {
        string DisplayName { get; set; }
    }

    [DataContract]
    public class GetEnterpriseNode : IEncryptedData
    {
        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "parent_id")]
        public long? ParentId { get; set; }

        [DataMember(Name = "encrypted_data", EmitDefaultValue = false)]
        public string EncryptedData { get; set; }
    }

    [DataContract]
    public class GetEnterpriseRole : IEncryptedData
    {
        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "encrypted_data", EmitDefaultValue = false)]
        public string EncryptedData { get; set; }

        [DataMember(Name = "visible_below", EmitDefaultValue = false)]
        public bool? VisibleBelow { get; set; }

        [DataMember(Name = "new_user_inherit", EmitDefaultValue = false)]
        public bool? NewUserInherit { get; set; }
    }

    [DataContract]
    public class GetEnterpriseRoleUser
    {
        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class GetEnterpriseRoleKey
    {
        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }
        [DataMember(Name = "encrypted_key")]
        public string EncryptedKey { get; set; }
        [DataMember(Name = "key_type")]
        public string KeyType { get; set; }
    }

    [DataContract]
    public class GetEnterpriseRoleKey2
    {
        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }
        [DataMember(Name = "role_key")]
        public string RoleKey { get; set; }
    }

    [DataContract]
    public class GetEnterpriseQueuedTeam : IEncryptedData
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }
        [DataMember(Name = "name")]
        public string Name { get; set; }
        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }
        [DataMember(Name = "encrypted_data")]
        public string EncryptedData { get; set; }
    }

    [DataContract]
    public class GetEnterpriseQueuedTeamUser
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }
        [DataMember(Name = "users")]
        public ICollection<long> Users { get; set; }
    }

    [DataContract]
    public class GetEnterpriseTeam
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "restrict_sharing")]
        public bool RestrictSharing { get; set; }

        [DataMember(Name = "restrict_edit")]
        public bool RestrictEdit { get; set; }

        [DataMember(Name = "restrict_view")]
        public bool RestrictView { get; set; }

        [DataMember(Name = "encrypted_team_key")]
        public string EncryptedTeamKey { get; set; }
    }

    [DataContract]
    public class GetEnterpriseTeamUser
    {
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class GetEnterpriseUser : IEncryptedData
    {
        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "username")]
        public string Username { get; set; }

        [DataMember(Name = "key_type")]
        public string KeyType { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; }

        [DataMember(Name = "lock")]
        public int Lock { get; set; }

        [DataMember(Name = "account_share_expiration")]
        public decimal? AccountShareExpiration { get; set; }

        [DataMember(Name = "encrypted_data")]
        public string EncryptedData { get; set; }
    }

    [DataContract]
    public class GetDeviceForAdminApproval
    {
        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }

        [DataMember(Name = "encrypted_device_token")]
        public string EncryptedDeviceToken { get; set; }

        [DataMember(Name = "device_public_key")]
        public string DevicePublicKey { get; set; }

        [DataMember(Name = "device_name")]
        public string DeviceName { get; set; }

        [DataMember(Name = "client_version")]
        public string ClientVersion { get; set; }
    }

    [DataContract]
    public class GetEnterpriseKeys
    {
        [DataMember(Name = "rsa_public_key")]
        public string RsaPublicKey { get; set; }
        [DataMember(Name = "rsa_encrypted_private_key")]
        public string RsaEncryptedPrivateKey { get; set; }

        [DataMember(Name = "ecc_public_key")]
        public string EccPublicKey { get; set; }
        [DataMember(Name = "ecc_encrypted_private_key")]
        public string EccEncryptedPrivateKey { get; set; }
    }

    [DataContract]
    public class EnterpriseMspPool
    {
        [DataMember(Name = "product_id")]
        public string ProductId { get; set; }
        [DataMember(Name = "availableSeats")]
        public int AvailableSeats { get; set; }
        [DataMember(Name = "seats")]
        public int Seats { get; set; }
    }

    [DataContract]
    public class GetEnterpriseLicenses
    {
        [DataMember(Name = "enterprise_license_id")]
        public long EnterpriseLicenseId { get; set; }
        [DataMember(Name = "expiration")]
        public string Expiration { get; set; }
        [DataMember(Name = "file_plan")]
        public int FilePlan { get; set; }
        [DataMember(Name = "max_gb")]
        public int MaxGb { get; set; }

        [DataMember(Name = "lic_status")]
        public string LicStatus { get; set; }
        [DataMember(Name = "tier")]
        public int Tier { get; set; }
        [DataMember(Name = "paid")]
        public bool Paid { get; set; }
        [DataMember(Name = "number_of_seats")]
        public int NumberOfSeats { get; set; }
        [DataMember(Name = "seats_allocated")]
        public int SeatsAllocated { get; set; }
        [DataMember(Name = "seats_pending")]
        public int SeatsPending { get; set; }
        [DataMember(Name = "msp_pool")]
        public ICollection<EnterpriseMspPool> MspPool { get; set; }
    }

    [DataContract]
    public class EnterpriseManagedCompany
    {
        [DataMember(Name = "mc_enterprise_id")]
        public int McEnterpriseId { get; set; }
        [DataMember(Name = "mc_enterprise_name")]
        public string McEnterpriseName { get; set; }
        [DataMember(Name = "number_of_seats")]
        public int NumberOfSeats { get; set; }
        [DataMember(Name = "number_of_users")]
        public int NumberOfUsers { get; set; }
        [DataMember(Name = "product_id")]
        public string ProductId { get; set; }
        [DataMember(Name = "paused")]
        public bool Paused { get; set; }
        [DataMember(Name = "tree_key")]
        public string TreeKey { get; set; }
    }

    [DataContract]
    public class EnterpriseBridge
    {
        [DataMember(Name = "bridge_id")]
        public int BridgeId { get; set; }
        [DataMember(Name = "node_id")]
        public int NodeId { get; set; }
        [DataMember(Name = "wan_ip_enforcement")]
        public string WanIpEnforcement { get; set; }
        [DataMember(Name = "lan_ip_enforcement")]
        public string LanIpEnforcement { get; set; }
        [DataMember(Name = "status")]
        public string Status { get; set; }
    }

    [DataContract]
    public class GetEnterpriseDataResponse : KeeperApiResponse
    {
        [DataMember(Name = "enterprise_name")]
        public string EnterpriseName { get; set; }

        [DataMember(Name = "tree_key")]
        public string TreeKey { get; set; }

        [DataMember(Name = "key_type_id")]
        public int KeyTypeId { get; set; }

        [DataMember(Name = "nodes")]
        public ICollection<GetEnterpriseNode> Nodes { get; set; }

        [DataMember(Name = "roles")]
        public ICollection<GetEnterpriseRole> Roles { get; set; }

        [DataMember(Name = "role_users")]
        public ICollection<GetEnterpriseRoleUser> RoleUsers { get; set; }

        [DataMember(Name = "role_keys")]
        public ICollection<GetEnterpriseRoleKey> RoleKeys { get; set; }

        [DataMember(Name = "role_keys2")]
        public ICollection<GetEnterpriseRoleKey2> RoleKeys2 { get; set; }

        [DataMember(Name = "teams")]
        public ICollection<GetEnterpriseTeam> Teams { get; set; }

        [DataMember(Name = "team_users")]
        public ICollection<GetEnterpriseTeamUser> TeamUsers { get; set; }

        [DataMember(Name = "queued_teams")]
        public ICollection<GetEnterpriseQueuedTeam> QueuedTeams { get; set; }

        [DataMember(Name = "queued_team_users")]
        public ICollection<GetEnterpriseQueuedTeamUser> QueuedTeamUsers { get; set; }
        

        [DataMember(Name = "users")]
        public ICollection<GetEnterpriseUser> Users { get; set; }

        [DataMember(Name = "devices_request_for_admin_approval")]
        public ICollection<GetDeviceForAdminApproval> DeviceRequestForApproval { get; set; }

        [DataMember(Name = "keys")]
        public GetEnterpriseKeys Keys { get; set; }

        [DataMember(Name = "licenses")]
        public ICollection<GetEnterpriseLicenses> Licenses { get; set; }

        [DataMember(Name = "managed_companies")]
        public ICollection<EnterpriseManagedCompany> ManagedCompanies { get; set; }

        [DataMember(Name = "bridges")]
        public ICollection<EnterpriseBridge> Bridges { get; set; }
    }

    [DataContract]
    public class EncryptedData : IExtensibleDataObject
    {
        [DataMember(Name = "displayname", EmitDefaultValue = false)]
        public string DisplayName { get; set; }

        public ExtensionDataObject ExtensionData { get; set; }
    }


    [DataContract]
    public class PreAccountTransferCommand : AuthenticatedCommand
    {
        public PreAccountTransferCommand() : base("pre_account_transfer") { }

        [DataMember(Name = "target_username", EmitDefaultValue = false)]
        public string TargetUsername { get; set; }
    }

    [DataContract]
    public class PreAccountTransferDataResponse : KeeperApiResponse
    {
        [DataMember(Name = "username")]
        public string Username { get; set; }

        [DataMember(Name = "user_private_key")]
        public string UserPrivateKey { get; set; }

        [DataMember(Name = "role_key")]
        public string RoleKey { get; set; }

        [DataMember(Name = "role_key_id")]
        public long? RoleKeyId { get; set; }

        [DataMember(Name = "role_private_key")]
        public string RolePrivateKey { get; set; }

        [DataMember(Name = "transfer_key")]
        public string TransferKey { get; set; }
    }

    [DataContract]
    public class TeamEnterpriseUserCommand : AuthenticatedCommand
    {
        public TeamEnterpriseUserCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class TeamEnterpriseUserRemoveCommand : TeamEnterpriseUserCommand
    {
        public TeamEnterpriseUserRemoveCommand() : base("team_enterprise_user_remove")
        {
        }
    }

    [DataContract]
    public class TeamEnterpriseUserAddCommand : TeamEnterpriseUserCommand
    {
        public TeamEnterpriseUserAddCommand() : base("team_enterprise_user_add")
        {
        }
        [DataMember(Name = "user_type")]
        public int UserType { get; set; }

        [DataMember(Name = "team_key", EmitDefaultValue = false)]
        public string TeamKey { get; set; }
    }

    [DataContract]
    public class TeamDeleteCommand : AuthenticatedCommand
    {
        public TeamDeleteCommand() : base("team_delete")
        {
        }
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }
    }

    [DataContract]
    public class TeamCommand : AuthenticatedCommand
    {
        public TeamCommand(string command) : base(command)
        {
        }
        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "team_name")]
        public string TeamName { get; set; }

        [DataMember(Name = "restrict_share")]
        public bool RestrictShare { get; set; }

        [DataMember(Name = "restrict_edit")]
        public bool RestrictEdit { get; set; }

        [DataMember(Name = "restrict_view")]
        public bool RestrictView { get; set; }

        [DataMember(Name = "node_id", EmitDefaultValue = false)]
        public long? NodeId { get; set; }
    }

    [DataContract]
    public class TeamUpdateCommand : TeamCommand
    {
        public TeamUpdateCommand() : base("team_update")
        {
        }
    }


    [DataContract]
    public class TeamAddCommand : TeamCommand
    {
        public TeamAddCommand() : base("team_add")
        {
        }

        [DataMember(Name = "public_key", EmitDefaultValue = false)]
        public string PublicKey { get; set; }

        [DataMember(Name = "private_key", EmitDefaultValue = false)]
        public string PrivateKey { get; set; }

        [DataMember(Name = "team_key", EmitDefaultValue = false)]
        public string TeamKey { get; set; }

        [DataMember(Name = "manage_only", EmitDefaultValue = false)]
        public bool ManageOnly { get; set; }

        [DataMember(Name = "encrypted_team_key")]
        public string EncryptedTeamKey { get; set; }
    }

}
