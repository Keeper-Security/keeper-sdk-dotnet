using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Runtime.Serialization;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Plugins.PEDM
{
    [DataContract]
    public class PolicyActions
    {
        [DataMember(Name = "OnSuccess")]
        public PolicyOnSuccess OnSuccess { get; set; }
        [DataMember(Name = "OnFailure")]
        public PolicyOnFailure OnFailure { get; set; }
    }
    
    [DataContract]
    public class PolicyOnSuccess
    {
        [DataMember(Name = "Controls")]
        public List<string> Controls { get; set; } = new List<string>();
    }
    
    [DataContract]
    public class PolicyOnFailure
    {
        [DataMember(Name = "Command")]
        public string Command { get; set; } = "";
    }
    
    [DataContract]
    public class PolicyRule
    {
        [DataMember(Name = "RuleName")]
        public string RuleName { get; set; } = "";
        [DataMember(Name = "ErrorMessage")]
        public string ErrorMessage { get; set; } = "";
        [DataMember(Name = "RuleExpressionType")]
        public string RuleExpressionType { get; set; } = "";
        [DataMember(Name = "Expression")]
        public string Expression { get; set; } = "";
    }
    
    [DataContract]
    public class DateRange
    {
        [DataMember(Name = "StartDate")]
        public long StartDate { get; set; }
        [DataMember(Name = "EndDate")]
        public long EndDate { get; set; }
    }
    
    [DataContract]
    public class TimeRange
    {
        [DataMember(Name = "StartTime")]
        public string StartTime { get; set; } = "";
        [DataMember(Name = "EndTime")]
        public string EndTime { get; set; } = "";
    }
    
    [DataContract]
    public class ApprovalLimitRange
    {
        [DataMember(Name = "validRange")]
        public string ValidRange { get; set; } = "";
        [DataMember(Name = "timeRange")]
        public TimeRange TimeRange { get; set; }
        [DataMember(Name = "limitToDays")]
        public List<int> LimitToDays { get; set; } = new List<int>();
    }
    
    [DataContract]
    public class Approvers
    {
        [DataMember(Name = "users")]
        public List<long> Users { get; set; } = new List<long>();
        [DataMember(Name = "teams")]
        public List<long> Teams { get; set; } = new List<long>();
        [DataMember(Name = "escalatedUsers")]
        public List<long> EscalatedUsers { get; set; } = new List<long>();
        [DataMember(Name = "escalatedTeams")]
        public List<long> EscalatedTeams { get; set; } = new List<long>();
    }
    
    [DataContract]
    public class PolicyPlainData
    {
        [DataMember(Name = "numberRequiredApprovers")]
        public int NumberRequiredApprovers { get; set; }
        
        [DataMember(Name = "isApprovalLimitOneTime")]
        public bool IsApprovalLimitOneTime { get; set; }
        
        [DataMember(Name = "oneTimeApprovalLimit")]
        public string OneTimeApprovalLimit { get; set; } = "";
        
        [DataMember(Name = "approvalLimitRange")]
        public ApprovalLimitRange ApprovalLimitRange { get; set; }
        
        [DataMember(Name = "approvers")]
        public Approvers Approvers { get; set; }
        
        [DataMember(Name = "disabled", EmitDefaultValue = false)]
        public bool? Disabled { get; set; }
    }
    
    [DataContract]
    public class PolicyInput
    {
        [DataMember(Name = "plainData")]
        public PolicyPlainData PlainData { get; set; }
        
        [DataMember(Name = "data")]
        public PolicyDataStructure Data { get; set; }
        
        [DataMember(Name = "policyUid", EmitDefaultValue = false)]
        public string PolicyUid { get; set; }
    }

    [DataContract]
    public class PolicyDataStructure
    {
        [DataMember(Name = "PolicyName")]
        public string PolicyName { get; set; } = "";
        
        [DataMember(Name = "PolicyType")]
        public string PolicyType { get; set; } = "";
        
        [DataMember(Name = "PolicyId")]
        public string PolicyId { get; set; } = "";
        
        [DataMember(Name = "Status")]
        public string Status { get; set; } = "";
        
        [DataMember(Name = "Actions")]
        public PolicyActions Actions { get; set; }
        [DataMember(Name = "NotificationMessage")]
        public string NotificationMessage { get; set; } = "";
        
        [DataMember(Name = "NotificationRequiresAcknowledge")]
        public bool NotificationRequiresAcknowledge { get; set; }
        
        [DataMember(Name = "RiskLevel")]
        public int RiskLevel { get; set; }
        
        [DataMember(Name = "Operator")]
        public string Operator { get; set; } = "";
        
        [DataMember(Name = "Rules")]
        public List<PolicyRule> Rules { get; set; } = new List<PolicyRule>();
        
        [DataMember(Name = "UserCheck")]
        public List<string> UserCheck { get; set; } = new List<string>();
        
        [DataMember(Name = "MachineCheck")]
        public List<string> MachineCheck { get; set; } = new List<string>();
        
        [DataMember(Name = "ApplicationCheck")]
        public List<string> ApplicationCheck { get; set; } = new List<string>();
        
        [DataMember(Name = "DayCheck")]
        public List<int> DayCheck { get; set; } = new List<int>();
        
        [DataMember(Name = "DateCheck")]
        public List<DateRange> DateCheck { get; set; } = new List<DateRange>();
        
        [DataMember(Name = "TimeCheck")]
        public List<TimeRange> TimeCheck { get; set; } = new List<TimeRange>();
        
        [DataMember(Name = "CertificationCheck")]
        public List<string> CertificationCheck { get; set; } = new List<string>();
        
        [DataMember(Name = "Extension")]
        public Dictionary<string, object> Extension { get; set; } = new Dictionary<string, object>();
        
        [DataMember(Name = "plainData", EmitDefaultValue = false)]
        public PolicyPlainData PlainData { get; set; }
    }
    public interface IPedmAdminSettings : IUid
    {
        string Key { get; set; }
        string Value { get; set; }
    }

    public interface IPedmStorageDeployment : IUid
    {
        string DeploymentUid { get; set; }
        byte[] EncryptedKey { get; set; }
        bool Disabled { get; set; }
        byte[] Data { get; set; }
        byte[] PublicKey { get; set; }
        long Created { get; set; }
        long LastUpdated { get; set; }
    }

    public interface IPedmStorageAgent : IUid
    {
        string AgentUid { get; set; }
        string MachineId { get; set; }
        string DeploymentUid { get; set; }
        byte[] PublicKey { get; set; }
        byte[] Data { get; set; }
        bool Disabled { get; set; }
        long Created { get; set; }
        long Modified { get; set; }
    }

    public interface IPedmStoragePolicy : IUid
    {
        string PolicyUid { get; set; }
        byte[] AdminData { get; set; }
        byte[] Data { get; set; }
        byte[] Key { get; set; }
        bool Disabled { get; set; }
        long Created { get; set; }
        long Updated { get; set; }
    }

    public interface IPedmStorageCollection : IUid
    {
        string CollectionUid { get; set; }
        int CollectionType { get; set; }
        byte[] Data { get; set; }
        long Created { get; set; }
    }

    public interface IPedmStorageCollectionLink : IUidLink
    {
        string CollectionUid { get; set; }
        string LinkUid { get; set; }
        int LinkType { get; set; }
    }

    public interface IPedmStorageApproval : IUid
    {
        string ApprovalUid { get; set; }
        int ApprovalType { get; set; }
        string AgentUid { get; set; }
        byte[] AccountInfo { get; set; }
        byte[] ApplicationInfo { get; set; }
        byte[] Justification { get; set; }
        int ExpireIn { get; set; }
        long Created { get; set; }
    }

    public interface IPedmStorageApprovalStatus : IUid
    {
        string ApprovalUid { get; set; }
        int ApprovalStatus { get; set; }
        int EnterpriseUserId { get; set; }
        long Modified { get; set; }
    }

    [SqlTable(Name = "pedm_admin_settings", PrimaryKey = new[] { "key" })]
    internal class PedmAdminSettingsData : IPedmAdminSettings, IEntityCopy<IPedmAdminSettings>
    {
        [SqlColumn(Name = "key")]
        public string Key { get; set; } = "";

        [SqlColumn(Name = "value")]
        public string Value { get; set; } = "";

        public string Uid => Key;

        public void CopyFields(IPedmAdminSettings source)
        {
            if (source == null) return;
            Key = source.Key;
            Value = source.Value;
        }
    }

    [SqlTable(Name = "pedm_storage_deployment", PrimaryKey = new[] { "deployment_uid" })]
    internal class PedmStorageDeploymentData : IPedmStorageDeployment, IEntityCopy<IPedmStorageDeployment>
    {
        [SqlColumn(Name = "deployment_uid")]
        public string DeploymentUid { get; set; } = "";

        [SqlColumn(Name = "encrypted_key")]
        public byte[] EncryptedKey { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "disabled")]
        public bool Disabled { get; set; } = false;

        [SqlColumn(Name = "data")]
        public byte[] Data { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "public_key")]
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "created")]
        public long Created { get; set; } = 0;

        [SqlColumn(Name = "last_updated")]
        public long LastUpdated { get; set; } = 0;

        public string Uid => DeploymentUid;

        public void CopyFields(IPedmStorageDeployment source)
        {
            if (source == null) return;
            DeploymentUid = source.DeploymentUid;
            EncryptedKey = source.EncryptedKey ?? Array.Empty<byte>();
            Disabled = source.Disabled;
            Data = source.Data ?? Array.Empty<byte>();
            PublicKey = source.PublicKey ?? Array.Empty<byte>();
            Created = source.Created;
            LastUpdated = source.LastUpdated;
        }
    }

    [SqlTable(Name = "pedm_storage_agent", PrimaryKey = new[] { "agent_uid" })]
    internal class PedmStorageAgentData : IPedmStorageAgent, IEntityCopy<IPedmStorageAgent>
    {
        [SqlColumn(Name = "agent_uid")]
        public string AgentUid { get; set; } = "";

        [SqlColumn(Name = "machine_id")]
        public string MachineId { get; set; } = "";

        [SqlColumn(Name = "deployment_uid")]
        public string DeploymentUid { get; set; } = "";

        [SqlColumn(Name = "public_key")]
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "data")]
        public byte[] Data { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "disabled")]
        public bool Disabled { get; set; } = false;

        [SqlColumn(Name = "created")]
        public long Created { get; set; } = 0;

        [SqlColumn(Name = "modified")]
        public long Modified { get; set; } = 0;

        public string Uid => AgentUid;

        public void CopyFields(IPedmStorageAgent source)
        {
            if (source == null) return;
            AgentUid = source.AgentUid;
            MachineId = source.MachineId;
            DeploymentUid = source.DeploymentUid;
            PublicKey = source.PublicKey ?? Array.Empty<byte>();
            Data = source.Data ?? Array.Empty<byte>();
            Disabled = source.Disabled;
            Created = source.Created;
            Modified = source.Modified;
        }
    }

    [SqlTable(Name = "pedm_storage_policy", PrimaryKey = new[] { "policy_uid" })]
    internal class PedmStoragePolicyData : IPedmStoragePolicy, IEntityCopy<IPedmStoragePolicy>
    {
        [SqlColumn(Name = "policy_uid")]
        public string PolicyUid { get; set; } = "";

        [SqlColumn(Name = "admin_data")]
        public byte[] AdminData { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "data")]
        public byte[] Data { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "key")]
        public byte[] Key { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "disabled")]
        public bool Disabled { get; set; } = false;

        [SqlColumn(Name = "created")]
        public long Created { get; set; } = 0;

        [SqlColumn(Name = "updated")]
        public long Updated { get; set; } = 0;

        public string Uid => PolicyUid;

        public void CopyFields(IPedmStoragePolicy source)
        {
            if (source == null) return;
            PolicyUid = source.PolicyUid;
            AdminData = source.AdminData ?? Array.Empty<byte>();
            Data = source.Data ?? Array.Empty<byte>();
            Key = source.Key ?? Array.Empty<byte>();
            Disabled = source.Disabled;
            Created = source.Created;
            Updated = source.Updated;
        }
    }

    [SqlTable(Name = "pedm_storage_collection", PrimaryKey = new[] { "collection_uid" })]
    internal class PedmStorageCollectionData : IPedmStorageCollection, IEntityCopy<IPedmStorageCollection>
    {
        [SqlColumn(Name = "collection_uid")]
        public string CollectionUid { get; set; } = "";

        [SqlColumn(Name = "collection_type")]
        public int CollectionType { get; set; } = 0;

        [SqlColumn(Name = "data")]
        public byte[] Data { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "created")]
        public long Created { get; set; } = 0;

        public string Uid => CollectionUid;

        public void CopyFields(IPedmStorageCollection source)
        {
            if (source == null) return;
            CollectionUid = source.CollectionUid;
            CollectionType = source.CollectionType;
            Data = source.Data ?? Array.Empty<byte>();
            Created = source.Created;
        }
    }

    [SqlTable(Name = "pedm_storage_collection_link", PrimaryKey = new[] { "collection_uid", "link_uid" }, Index1 = new[] { "link_uid" })]
    internal class PedmStorageCollectionLinkData : IPedmStorageCollectionLink, IEntityCopy<IPedmStorageCollectionLink>
    {
        [SqlColumn(Name = "collection_uid")]
        public string CollectionUid { get; set; } = "";

        [SqlColumn(Name = "link_uid")]
        public string LinkUid { get; set; } = "";

        [SqlColumn(Name = "link_type")]
        public int LinkType { get; set; } = 0;

        public string SubjectUid => CollectionUid;
        public string ObjectUid => LinkUid;

        public void CopyFields(IPedmStorageCollectionLink source)
        {
            if (source == null) return;
            CollectionUid = source.CollectionUid;
            LinkUid = source.LinkUid;
            LinkType = source.LinkType;
        }
    }

    [SqlTable(Name = "pedm_storage_approval", PrimaryKey = new[] { "approval_uid" })]
    internal class PedmStorageApprovalData : IPedmStorageApproval, IEntityCopy<IPedmStorageApproval>
    {
        [SqlColumn(Name = "approval_uid")]
        public string ApprovalUid { get; set; } = "";

        [SqlColumn(Name = "approval_type")]
        public int ApprovalType { get; set; } = 0;

        [SqlColumn(Name = "agent_uid")]
        public string AgentUid { get; set; } = "";

        [SqlColumn(Name = "account_info")]
        public byte[] AccountInfo { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "application_info")]
        public byte[] ApplicationInfo { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "justification")]
        public byte[] Justification { get; set; } = Array.Empty<byte>();

        [SqlColumn(Name = "expire_in")]
        public int ExpireIn { get; set; } = 0;

        [SqlColumn(Name = "created")]
        public long Created { get; set; } = 0;

        public string Uid => ApprovalUid;

        public void CopyFields(IPedmStorageApproval source)
        {
            if (source == null) return;
            ApprovalUid = source.ApprovalUid;
            ApprovalType = source.ApprovalType;
            AgentUid = source.AgentUid;
            AccountInfo = source.AccountInfo ?? Array.Empty<byte>();
            ApplicationInfo = source.ApplicationInfo ?? Array.Empty<byte>();
            Justification = source.Justification ?? Array.Empty<byte>();
            ExpireIn = source.ExpireIn;
            Created = source.Created;
        }
    }

    [SqlTable(Name = "pedm_storage_approval_status", PrimaryKey = new[] { "approval_uid" })]
    internal class PedmStorageApprovalStatusData : IPedmStorageApprovalStatus, IEntityCopy<IPedmStorageApprovalStatus>
    {
        [SqlColumn(Name = "approval_uid")]
        public string ApprovalUid { get; set; } = "";

        [SqlColumn(Name = "approval_status")]
        public int ApprovalStatus { get; set; } = 0;

        [SqlColumn(Name = "enterprise_user_id")]
        public int EnterpriseUserId { get; set; } = 0;

        [SqlColumn(Name = "modified")]
        public long Modified { get; set; } = 0;

        public string Uid => ApprovalUid;

        public void CopyFields(IPedmStorageApprovalStatus source)
        {
            if (source == null) return;
            ApprovalUid = source.ApprovalUid;
            ApprovalStatus = source.ApprovalStatus;
            EnterpriseUserId = source.EnterpriseUserId;
            Modified = source.Modified;
        }
    }

    public interface IPedmStorage
    {
        IEntityStorage<IPedmAdminSettings> Settings { get; }
        IEntityStorage<IPedmStorageDeployment> Deployments { get; }
        IEntityStorage<IPedmStorageAgent> Agents { get; }
        IEntityStorage<IPedmStoragePolicy> Policies { get; }
        IEntityStorage<IPedmStorageCollection> Collections { get; }
        ILinkStorage<IPedmStorageCollectionLink> CollectionLinks { get; }
        IEntityStorage<IPedmStorageApproval> Approvals { get; }
        IEntityStorage<IPedmStorageApprovalStatus> ApprovalStatus { get; }
        void Reset();
    }

    public class MemoryPedmStorage : IPedmStorage
    {
        private readonly InMemoryEntityStorage<IPedmAdminSettings> _settings = new();
        private readonly InMemoryEntityStorage<IPedmStorageDeployment> _deployments = new();
        private readonly InMemoryEntityStorage<IPedmStorageAgent> _agents = new();
        private readonly InMemoryEntityStorage<IPedmStoragePolicy> _policies = new();
        private readonly InMemoryEntityStorage<IPedmStorageCollection> _collections = new();
        private readonly InMemoryLinkStorage<IPedmStorageCollectionLink> _collectionLinks = new();
        private readonly InMemoryEntityStorage<IPedmStorageApproval> _approvals = new();
        private readonly InMemoryEntityStorage<IPedmStorageApprovalStatus> _approvalStatus = new();

        public IEntityStorage<IPedmAdminSettings> Settings => _settings;
        public IEntityStorage<IPedmStorageDeployment> Deployments => _deployments;
        public IEntityStorage<IPedmStorageAgent> Agents => _agents;
        public IEntityStorage<IPedmStoragePolicy> Policies => _policies;
        public IEntityStorage<IPedmStorageCollection> Collections => _collections;
        public ILinkStorage<IPedmStorageCollectionLink> CollectionLinks => _collectionLinks;
        public IEntityStorage<IPedmStorageApproval> Approvals => _approvals;
        public IEntityStorage<IPedmStorageApprovalStatus> ApprovalStatus => _approvalStatus;

        public void Reset()
        {
            _settings.Clear();
            _deployments.Clear();
            _agents.Clear();
            _policies.Clear();
            _collections.Clear();
            _collectionLinks.Clear();
            _approvals.Clear();
            _approvalStatus.Clear();
        }
    }

    public class SqlitePedmStorage : IPedmStorage
    {
        private readonly Func<IDbConnection> _getConnection;
        private readonly int _enterpriseId;
        private readonly string _ownerColumn = "enterprise_id";

        private readonly SqliteEntityStorage<IPedmAdminSettings, PedmAdminSettingsData> _settings;
        private readonly SqliteEntityStorage<IPedmStorageDeployment, PedmStorageDeploymentData> _deployments;
        private readonly SqliteEntityStorage<IPedmStorageAgent, PedmStorageAgentData> _agents;
        private readonly SqliteEntityStorage<IPedmStoragePolicy, PedmStoragePolicyData> _policies;
        private readonly SqliteEntityStorage<IPedmStorageCollection, PedmStorageCollectionData> _collections;
        private readonly SqliteLinkStorage<IPedmStorageCollectionLink, PedmStorageCollectionLinkData> _collectionLinks;
        private readonly SqliteEntityStorage<IPedmStorageApproval, PedmStorageApprovalData> _approvals;
        private readonly SqliteEntityStorage<IPedmStorageApprovalStatus, PedmStorageApprovalStatusData> _approvalStatus;

        public SqlitePedmStorage(Func<IDbConnection> getConnection, int enterpriseId)
        {
            _getConnection = getConnection;
            _enterpriseId = enterpriseId;

            var settingSchema = new TableSchema(typeof(PedmAdminSettingsData), _ownerColumn);
            var deploymentSchema = new TableSchema(typeof(PedmStorageDeploymentData), _ownerColumn);
            var agentSchema = new TableSchema(typeof(PedmStorageAgentData), _ownerColumn);
            var policySchema = new TableSchema(typeof(PedmStoragePolicyData), _ownerColumn);
            var collectionSchema = new TableSchema(typeof(PedmStorageCollectionData), _ownerColumn);
            var collectionLinkSchema = new TableSchema(typeof(PedmStorageCollectionLinkData), _ownerColumn);
            var approvalSchema = new TableSchema(typeof(PedmStorageApprovalData), _ownerColumn);
            var approvalStatusSchema = new TableSchema(typeof(PedmStorageApprovalStatusData), _ownerColumn);

            var connection = _getConnection();
            if (connection is DbConnection dbConnection)
            {
                DatabaseUtils.VerifyDatabase(
                    dbConnection,
                    settingSchema, deploymentSchema, agentSchema, policySchema,
                    collectionSchema, collectionLinkSchema, approvalSchema, approvalStatusSchema);
            }
            else
            {
                throw new InvalidOperationException("Connection must be a DbConnection");
            }

            _settings = new SqliteEntityStorage<IPedmAdminSettings, PedmAdminSettingsData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _deployments = new SqliteEntityStorage<IPedmStorageDeployment, PedmStorageDeploymentData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _agents = new SqliteEntityStorage<IPedmStorageAgent, PedmStorageAgentData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _policies = new SqliteEntityStorage<IPedmStoragePolicy, PedmStoragePolicyData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _collections = new SqliteEntityStorage<IPedmStorageCollection, PedmStorageCollectionData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _collectionLinks = new SqliteLinkStorage<IPedmStorageCollectionLink, PedmStorageCollectionLinkData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _approvals = new SqliteEntityStorage<IPedmStorageApproval, PedmStorageApprovalData>(
                _getConnection, _ownerColumn, _enterpriseId);
            _approvalStatus = new SqliteEntityStorage<IPedmStorageApprovalStatus, PedmStorageApprovalStatusData>(
                _getConnection, _ownerColumn, _enterpriseId);
        }

        public IEntityStorage<IPedmAdminSettings> Settings => _settings;
        public IEntityStorage<IPedmStorageDeployment> Deployments => _deployments;
        public IEntityStorage<IPedmStorageAgent> Agents => _agents;
        public IEntityStorage<IPedmStoragePolicy> Policies => _policies;
        public IEntityStorage<IPedmStorageCollection> Collections => _collections;
        public ILinkStorage<IPedmStorageCollectionLink> CollectionLinks => _collectionLinks;
        public IEntityStorage<IPedmStorageApproval> Approvals => _approvals;
        public IEntityStorage<IPedmStorageApprovalStatus> ApprovalStatus => _approvalStatus;

        public void Reset()
        {
            _settings.DeleteAll();
            _deployments.DeleteAll();
            _agents.DeleteAll();
            _policies.DeleteAll();
            _collections.DeleteAll();
            _collectionLinks.DeleteAll();
            _approvals.DeleteAll();
            _approvalStatus.DeleteAll();
        }
    }
}

