﻿using System.Runtime.Serialization;

namespace KeeperSecurity.Commands
{
    public interface IDisplayName
    {
        string DisplayName { get; set; }
    }

    public interface IEncryptedData
    {
        string EncryptedData { get; }
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
    public class EnterpriseAllocateIdsCommand : AuthenticatedCommand
    {
        public EnterpriseAllocateIdsCommand() : base("enterprise_allocate_ids")
        {
            NumberRequested = 5;
        }

        [DataMember(Name = "number_requested")]
        public long NumberRequested { get; set; }
    }

    [DataContract]
    public class EnterpriseAllocateIdsResponse : KeeperApiResponse
    {
        [DataMember(Name = "number_allocated")]
        public int NumberAllocated { get; set; }
        [DataMember(Name = "base_id")]
        public long BaseId { get; set; }
    }


    [DataContract]
    public class NodeCommand : AuthenticatedCommand
    {
        public NodeCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "parent_id", EmitDefaultValue = false)]
        public long? ParentId { get; set; }

        [DataMember(Name = "encrypted_data")]
        public string EncryptedData { get; set; }
    }

    [DataContract]
    public class NodeAddCommand : NodeCommand
    {
        public NodeAddCommand() : base("node_add")
        {
        }
    }

    [DataContract]
    public class NodeUpdateCommand : NodeCommand
    {
        public NodeUpdateCommand() : base("node_update")
        {
        }
    }

    [DataContract]
    public class NodeDeleteCommand : AuthenticatedCommand
    {
        public NodeDeleteCommand() : base("node_delete")
        {
        }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

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

    [DataContract]
    public class TeamQueueUserCommand : AuthenticatedCommand
    {
        public TeamQueueUserCommand() : base("team_queue_user")
        {
        }

        [DataMember(Name = "team_uid")]
        public string TeamUid { get; set; }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class RoleCommand : AuthenticatedCommand
    {
        public RoleCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "encrypted_data")]
        public string EncryptedData { get; set; }

        [DataMember(Name = "visible_below")]
        public bool VisibleBelow { get; set; }

        [DataMember(Name = "new_user_inherit")]
        public bool NewUserInherit { get; set; }
    }

    [DataContract]
    public class RoleAddCommand : RoleCommand
    {
        public RoleAddCommand() : base("role_add")
        {
        }
    }

    [DataContract]
    public class RoleUpdateCommand : RoleCommand
    {
        public RoleUpdateCommand() : base("role_update")
        {
        }
    }

    [DataContract]
    public class RoleDeleteCommand : AuthenticatedCommand
    {
        public RoleDeleteCommand() : base("role_delete")
        {
        }

        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }
    }

    [DataContract]
    public class RoleEnforcementCommand : AuthenticatedCommand
    {
        public RoleEnforcementCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }

        [DataMember(Name = "enforcement")]
        public string Enforcement { get; set; }
    }

    [DataContract]
    public class RoleEnforcementAddCommand : RoleEnforcementCommand
    {
        public RoleEnforcementAddCommand() : base("role_enforcement_add")
        {
        }

        [DataMember(Name = "value")]
        public string Value { get; set; }
    }

    [DataContract]
    public class RoleEnforcementUpdateCommand : RoleEnforcementCommand
    {
        public RoleEnforcementUpdateCommand() : base("role_enforcement_update")
        {
        }

        [DataMember(Name = "value")]
        public string Value { get; set; }
    }

    [DataContract]
    public class RoleEnforcementRemoveCommand : RoleEnforcementCommand
    {
        public RoleEnforcementRemoveCommand() : base("role_enforcement_remove")
        {
        }
    }

    [DataContract]
    public class RoleUserCommand : AuthenticatedCommand
    {
        public RoleUserCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class RoleUserRemoveCommand : RoleUserCommand
    {
        public RoleUserRemoveCommand() : base("role_user_remove")
        {
        }
    }

    [DataContract]
    public class RoleUserAddCommand : RoleUserCommand
    {
        public RoleUserAddCommand() : base("role_user_add")
        {
        }
        [DataMember(Name = "tree_key", EmitDefaultValue = false)]
        public string TreeKey { get; set; }

        [DataMember(Name = "role_admin_key", EmitDefaultValue = false)]
        public string RoleAdminKey { get; set; }
    }

    [DataContract]
    public class EnterpriseUserCommand : AuthenticatedCommand
    {
        public EnterpriseUserCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class EnterpriseUserAddCommand : EnterpriseUserCommand
    {
        public EnterpriseUserAddCommand() : base("enterprise_user_add")
        {
        }

        [DataMember(Name = "enterprise_user_username")]
        public string EnterpriseUserUsername { get; set; }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }

        [DataMember(Name = "encrypted_data", EmitDefaultValue = false)]
        public string EncryptedData { get; set; }

        [DataMember(Name = "full_name", EmitDefaultValue = false)]
        public string FullName { get; set; }

        [DataMember(Name = "job_title", EmitDefaultValue = false)]
        public string JobTitle { get; set; }

        [DataMember(Name = "suppress_email_invite", EmitDefaultValue = false)]
        public bool? SuppressEmailInvite { get; set; }
    }

    [DataContract]
    public class EnterpriseUserAddResponse : KeeperApiResponse
    {
        [DataMember(Name = "verification_code")]
        public string VerificationCode { get; set; }
    }

    [DataContract]
    public class EnterpriseUserLockCommand : EnterpriseUserCommand
    {
        public EnterpriseUserLockCommand() : base("enterprise_user_lock")
        {
        }

        [DataMember(Name = "lock", EmitDefaultValue = false)]
        public string Lock { get; set; }  // one of: locked, disabled, unlocked

        [DataMember(Name = "delete_if_pending", EmitDefaultValue = false)]
        public bool? DeleteIfPending { get; set; }
    }

    [DataContract]
    public class MspAddon
    {
        [DataMember(Name = "seats")]
        public int Seats { get; set; }

        [DataMember(Name = "add_on")]
        public string AddOn { get; set; }
    }

    [DataContract]
    public class EnterpriseManagedCompanyByMspCommand : AuthenticatedCommand
    {
        public EnterpriseManagedCompanyByMspCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "enterprise_name")]
        public string EnterpriseName { get; set; }

        [DataMember(Name = "node_id", EmitDefaultValue = false)]
        public long? NodeId { get; set; }

        [DataMember(Name = "product_id")]
        public string ProductId { get; set; }

        [DataMember(Name = "seats")]
        public int Seats { get; set; }

        [DataMember(Name = "file_plan_type", EmitDefaultValue = false)]
        public string FilePlanType { get; set; }

        [DataMember(Name = "add_ons", EmitDefaultValue = false)]
        public MspAddon[] AddOns { get; set; }
    }

    [DataContract]
    public class EnterpriseRegistrationByMspCommand : EnterpriseManagedCompanyByMspCommand
    {
        public EnterpriseRegistrationByMspCommand() : base("enterprise_registration_by_msp")
        {
        }

        [DataMember(Name = "role_data")]
        public string RoleData { get; set; }

        [DataMember(Name = "root_node")]
        public string RootNode { get; set; }

        [DataMember(Name = "encrypted_tree_key")]
        public string EncryptedTreeKey { get; set; }
    }

    [DataContract]
    public class EnterpriseUpdateByMspCommand : EnterpriseManagedCompanyByMspCommand
    {
        public EnterpriseUpdateByMspCommand() : base("enterprise_update_by_msp")
        {
        }

        [DataMember(Name = "enterprise_id")]
        public int EnterpriseId { get; set; }

        [DataMember(Name = "notification", EmitDefaultValue = false)]
        public int Notification { get; set; }

        [DataMember(Name = "price", EmitDefaultValue = false)]
        public string Price { get; set; }
    }

    [DataContract]
    public class EnterpriseManagedCompanyByMspResponse : KeeperApiResponse
    {
        [DataMember(Name = "enterprise_id")]
        public int EnterpriseId { get; set; }
    }

    [DataContract]
    public class EnterpriseRemoveByMspCommand : AuthenticatedCommand
    {
        public EnterpriseRemoveByMspCommand() : base("enterprise_remove_by_msp")
        {
        }

        [DataMember(Name = "enterprise_id")]
        public int EnterpriseId { get; set; }
    }
}
