using KeeperSecurity.Storage;

namespace KeeperSecurity.Compliance
{
    /// <exclude />
    [SqlTable(Name = "compliance_metadata", PrimaryKey = new[] { "AccountUid" })]
    public class ComplianceMetadata : IEntityCopy<ComplianceMetadata>
    {
        [SqlColumn(Length = 64)] public string AccountUid { get; set; } = "_default_";
        [SqlColumn] public long PrelimDataLastUpdate { get; set; }
        [SqlColumn] public long ComplianceDataLastUpdate { get; set; }
        [SqlColumn] public long RecordsDated { get; set; }
        [SqlColumn] public long LastPwAudit { get; set; }
        [SqlColumn] public bool SharedRecordsOnly { get; set; }

        void IEntityCopy<ComplianceMetadata>.CopyFields(ComplianceMetadata source)
        {
            AccountUid = source.AccountUid;
            PrelimDataLastUpdate = source.PrelimDataLastUpdate;
            ComplianceDataLastUpdate = source.ComplianceDataLastUpdate;
            RecordsDated = source.RecordsDated;
            LastPwAudit = source.LastPwAudit;
            SharedRecordsOnly = source.SharedRecordsOnly;
        }
    }

    /// <exclude />
    public interface IComplianceUser : IUid
    {
        long UserUid { get; }
        byte[] Email { get; }
        int Status { get; }
        byte[] JobTitle { get; }
        byte[] FullName { get; }
        long NodeId { get; }
        long LastRefreshed { get; }
        long LastComplianceRefreshed { get; }
        long LastAgingRefreshed { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_user", PrimaryKey = new[] { "UserUid" })]
    public class ComplianceUser : IComplianceUser, IEntityCopy<IComplianceUser>
    {
        [SqlColumn] public long UserUid { get; set; }
        [SqlColumn] public byte[] Email { get; set; }
        [SqlColumn] public int Status { get; set; }
        [SqlColumn] public byte[] JobTitle { get; set; }
        [SqlColumn] public byte[] FullName { get; set; }
        [SqlColumn] public long NodeId { get; set; }
        [SqlColumn] public long LastRefreshed { get; set; }
        [SqlColumn] public long LastComplianceRefreshed { get; set; }
        [SqlColumn] public long LastAgingRefreshed { get; set; }

        string IUid.Uid => UserUid.ToString();

        void IEntityCopy<IComplianceUser>.CopyFields(IComplianceUser source)
        {
            UserUid = source.UserUid;
            Email = source.Email;
            Status = source.Status;
            JobTitle = source.JobTitle;
            FullName = source.FullName;
            NodeId = source.NodeId;
            LastRefreshed = source.LastRefreshed;
            LastComplianceRefreshed = source.LastComplianceRefreshed;
            LastAgingRefreshed = source.LastAgingRefreshed;
        }
    }

    /// <exclude />
    public interface IComplianceRecord : IUid
    {
        string RecordUid { get; }
        byte[] RecordUidBytes { get; }
        byte[] EncryptedData { get; }
        bool Shared { get; }
        bool InTrash { get; }
        bool HasAttachments { get; }
        long LastComplianceRefreshed { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_record", PrimaryKey = new[] { "RecordUid" })]
    public class ComplianceRecord : IComplianceRecord, IEntityCopy<IComplianceRecord>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public byte[] RecordUidBytes { get; set; }
        [SqlColumn] public byte[] EncryptedData { get; set; }
        [SqlColumn] public bool Shared { get; set; }
        [SqlColumn] public bool InTrash { get; set; }
        [SqlColumn] public bool HasAttachments { get; set; }
        [SqlColumn] public long LastComplianceRefreshed { get; set; }

        string IUid.Uid => RecordUid;

        void IEntityCopy<IComplianceRecord>.CopyFields(IComplianceRecord source)
        {
            RecordUid = source.RecordUid;
            RecordUidBytes = source.RecordUidBytes;
            EncryptedData = source.EncryptedData;
            Shared = source.Shared;
            InTrash = source.InTrash;
            HasAttachments = source.HasAttachments;
            LastComplianceRefreshed = source.LastComplianceRefreshed;
        }
    }

    /// <exclude />
    public interface IComplianceRecordAging : IUid
    {
        string RecordUid { get; }
        long Created { get; }
        long LastPwChange { get; }
        long LastModified { get; }
        long LastRotation { get; }
        long LastCached { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_record_aging", PrimaryKey = new[] { "RecordUid" })]
    public class ComplianceRecordAging : IComplianceRecordAging, IEntityCopy<IComplianceRecordAging>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public long Created { get; set; }
        [SqlColumn] public long LastPwChange { get; set; }
        [SqlColumn] public long LastModified { get; set; }
        [SqlColumn] public long LastRotation { get; set; }
        [SqlColumn] public long LastCached { get; set; }

        string IUid.Uid => RecordUid;

        void IEntityCopy<IComplianceRecordAging>.CopyFields(IComplianceRecordAging source)
        {
            RecordUid = source.RecordUid;
            Created = source.Created;
            LastPwChange = source.LastPwChange;
            LastModified = source.LastModified;
            LastRotation = source.LastRotation;
            LastCached = source.LastCached;
        }
    }

    /// <exclude />
    public interface IComplianceUserRecordLink : IUidLink
    {
        string RecordUid { get; }
        long UserUid { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_user_record_link", PrimaryKey = new[] { "RecordUid", "UserUid" },
        Index1 = new[] { "UserUid" })]
    public class ComplianceUserRecordLink : IComplianceUserRecordLink, IEntityCopy<IComplianceUserRecordLink>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public long UserUid { get; set; }

        string IUidLink.SubjectUid => RecordUid;
        string IUidLink.ObjectUid => UserUid.ToString();

        void IEntityCopy<IComplianceUserRecordLink>.CopyFields(IComplianceUserRecordLink source)
        {
            RecordUid = source.RecordUid;
            UserUid = source.UserUid;
        }
    }

    /// <exclude />
    public interface IComplianceTeam : IUid
    {
        string TeamUid { get; }
        string TeamName { get; }
        bool RestrictEdit { get; }
        bool RestrictShare { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_team", PrimaryKey = new[] { "TeamUid" })]
    public class ComplianceTeam : IComplianceTeam, IEntityCopy<IComplianceTeam>
    {
        [SqlColumn(Length = 32)] public string TeamUid { get; set; }
        [SqlColumn(Length = 256)] public string TeamName { get; set; }
        [SqlColumn] public bool RestrictEdit { get; set; }
        [SqlColumn] public bool RestrictShare { get; set; }

        string IUid.Uid => TeamUid;

        void IEntityCopy<IComplianceTeam>.CopyFields(IComplianceTeam source)
        {
            TeamUid = source.TeamUid;
            TeamName = source.TeamName;
            RestrictEdit = source.RestrictEdit;
            RestrictShare = source.RestrictShare;
        }
    }

    /// <exclude />
    public interface IComplianceTeamUserLink : IUidLink
    {
        string TeamUid { get; }
        long UserUid { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_team_user_link", PrimaryKey = new[] { "TeamUid", "UserUid" },
        Index1 = new[] { "UserUid" })]
    public class ComplianceTeamUserLink : IComplianceTeamUserLink, IEntityCopy<IComplianceTeamUserLink>
    {
        [SqlColumn(Length = 32)] public string TeamUid { get; set; }
        [SqlColumn] public long UserUid { get; set; }

        string IUidLink.SubjectUid => TeamUid;
        string IUidLink.ObjectUid => UserUid.ToString();

        void IEntityCopy<IComplianceTeamUserLink>.CopyFields(IComplianceTeamUserLink source)
        {
            TeamUid = source.TeamUid;
            UserUid = source.UserUid;
        }
    }

    /// <exclude />
    public interface IComplianceRole : IUid
    {
        long RoleId { get; }
        byte[] EncryptedData { get; }
        bool RestrictShareOutsideEnterprise { get; }
        bool RestrictShareAll { get; }
        bool RestrictShareOfAttachments { get; }
        bool RestrictMaskPasswordsWhileEditing { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_role", PrimaryKey = new[] { "RoleId" })]
    public class ComplianceRole : IComplianceRole, IEntityCopy<IComplianceRole>
    {
        [SqlColumn] public long RoleId { get; set; }
        [SqlColumn] public byte[] EncryptedData { get; set; }
        [SqlColumn] public bool RestrictShareOutsideEnterprise { get; set; }
        [SqlColumn] public bool RestrictShareAll { get; set; }
        [SqlColumn] public bool RestrictShareOfAttachments { get; set; }
        [SqlColumn] public bool RestrictMaskPasswordsWhileEditing { get; set; }

        string IUid.Uid => RoleId.ToString();

        void IEntityCopy<IComplianceRole>.CopyFields(IComplianceRole source)
        {
            RoleId = source.RoleId;
            EncryptedData = source.EncryptedData;
            RestrictShareOutsideEnterprise = source.RestrictShareOutsideEnterprise;
            RestrictShareAll = source.RestrictShareAll;
            RestrictShareOfAttachments = source.RestrictShareOfAttachments;
            RestrictMaskPasswordsWhileEditing = source.RestrictMaskPasswordsWhileEditing;
        }
    }

    /// <exclude />
    public interface IComplianceRecordPermissions : IUidLink
    {
        string RecordUid { get; }
        long UserUid { get; }
        int Permissions { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_record_permissions", PrimaryKey = new[] { "RecordUid", "UserUid" },
        Index1 = new[] { "UserUid" })]
    public class ComplianceRecordPermissions : IComplianceRecordPermissions, IEntityCopy<IComplianceRecordPermissions>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public long UserUid { get; set; }
        [SqlColumn] public int Permissions { get; set; }

        string IUidLink.SubjectUid => RecordUid;
        string IUidLink.ObjectUid => UserUid.ToString();

        void IEntityCopy<IComplianceRecordPermissions>.CopyFields(IComplianceRecordPermissions source)
        {
            RecordUid = source.RecordUid;
            UserUid = source.UserUid;
            Permissions = source.Permissions;
        }
    }

    /// <exclude />
    public interface IComplianceSfRecordLink : IUidLink
    {
        string FolderUid { get; }
        string RecordUid { get; }
        int Permissions { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_sf_record_link", PrimaryKey = new[] { "FolderUid", "RecordUid" },
        Index1 = new[] { "RecordUid" })]
    public class ComplianceSfRecordLink : IComplianceSfRecordLink, IEntityCopy<IComplianceSfRecordLink>
    {
        [SqlColumn(Length = 32)] public string FolderUid { get; set; }
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public int Permissions { get; set; }

        string IUidLink.SubjectUid => FolderUid;
        string IUidLink.ObjectUid => RecordUid;

        void IEntityCopy<IComplianceSfRecordLink>.CopyFields(IComplianceSfRecordLink source)
        {
            FolderUid = source.FolderUid;
            RecordUid = source.RecordUid;
            Permissions = source.Permissions;
        }
    }

    /// <exclude />
    public interface IComplianceSfUserLink : IUidLink
    {
        string FolderUid { get; }
        long UserUid { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_sf_user_link", PrimaryKey = new[] { "FolderUid", "UserUid" },
        Index1 = new[] { "UserUid" })]
    public class ComplianceSfUserLink : IComplianceSfUserLink, IEntityCopy<IComplianceSfUserLink>
    {
        [SqlColumn(Length = 32)] public string FolderUid { get; set; }
        [SqlColumn] public long UserUid { get; set; }

        string IUidLink.SubjectUid => FolderUid;
        string IUidLink.ObjectUid => UserUid.ToString();

        void IEntityCopy<IComplianceSfUserLink>.CopyFields(IComplianceSfUserLink source)
        {
            FolderUid = source.FolderUid;
            UserUid = source.UserUid;
        }
    }

    /// <exclude />
    public interface IComplianceSfTeamLink : IUidLink
    {
        string FolderUid { get; }
        string TeamUid { get; }
    }

    /// <exclude />
    [SqlTable(Name = "compliance_sf_team_link", PrimaryKey = new[] { "FolderUid", "TeamUid" },
        Index1 = new[] { "TeamUid" })]
    public class ComplianceSfTeamLink : IComplianceSfTeamLink, IEntityCopy<IComplianceSfTeamLink>
    {
        [SqlColumn(Length = 32)] public string FolderUid { get; set; }
        [SqlColumn(Length = 32)] public string TeamUid { get; set; }

        string IUidLink.SubjectUid => FolderUid;
        string IUidLink.ObjectUid => TeamUid;

        void IEntityCopy<IComplianceSfTeamLink>.CopyFields(IComplianceSfTeamLink source)
        {
            FolderUid = source.FolderUid;
            TeamUid = source.TeamUid;
        }
    }
}
