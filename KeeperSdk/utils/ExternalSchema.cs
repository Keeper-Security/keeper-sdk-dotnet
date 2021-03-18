using System;
using System.Runtime.Serialization;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Utils
{
    /// <exclude/>
    public interface IExternalLoader
    {
        bool VerifyDatabase();
        IConfigurationStorage GetConfigurationStorage(string configurationName, IConfigurationProtectionFactory protection);
        IKeeperStorage GetKeeperStorage(string username);
    }

    /// <exclude/>
    public interface IEntityCopy<in T>
    {
        void CopyFields(T source);
    }

    /// <exclude/>
    public interface IEntity : IUid
    {
        new string Uid { get; set; }
    }

    /// <exclude/>
    public interface IEntityLink : IUidLink
    {
        new string SubjectUid { get; set; }
        new string ObjectUid { get; set; }
    }

    /// <exclude/>
    public enum ColumnType
    {
        Integer,
        Long,
        Boolean,
        String,
        Decimal,
    }

    /// <exclude/>
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public sealed class SqlTableAttribute : Attribute
    {
        public string Name { get; set; }
        public string[] PrimaryKey { get; set; }
        public string[] Index1 { get; set; }
        public string[] Index2 { get; set; }
    }

    /// <exclude/>
    [AttributeUsage(AttributeTargets.Property)]
    public sealed class SqlColumnAttribute : Attribute
    {
        public SqlColumnAttribute()
        {
            CanBeNull = true;
        }

        public string Name { get; set; }
        public int Length { get; set; }
        public bool CanBeNull { get; set; }
    }

    /// <exclude/>
    [SqlTable(Name = "Records", PrimaryKey = new [] { "RecordUid" })]
    [DataContract]
    public class ExternalRecord : IEntity, IPasswordRecord, IEntityCopy<IPasswordRecord>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "revision", EmitDefaultValue = false)]
        public long Revision { get; set; }

        [SqlColumn]
        [DataMember(Name = "client_modified_time", EmitDefaultValue = false)]
        public long ClientModifiedTime { get; set; }

        [SqlColumn]
        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data { get; set; }

        [SqlColumn]
        [DataMember(Name = "extra", EmitDefaultValue = false)]
        public string Extra { get; set; }

        [SqlColumn]
        [DataMember(Name = "udata", EmitDefaultValue = false)]
        public string Udata { get; set; }

        [SqlColumn]
        [DataMember(Name = "shared")]
        public bool Shared { get; set; }

        [SqlColumn]
        [DataMember(Name = "owner")]
        public bool Owner { get; set; }

        public string Uid
        {
            get => RecordUid;
            set => RecordUid = value;
        }

        public void CopyFields(IPasswordRecord source)
        {
            RecordUid = source.RecordUid;
            Revision = source.Revision;
            ClientModifiedTime = source.ClientModifiedTime;
            Data = source.Data;
            Extra = source.Extra;
            Udata = source.Udata;
            Shared = source.Shared;
            Owner = source.Owner;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "RecordKeys", PrimaryKey = new[] { "RecordUid", "SharedFolderUid" }, Index1 = new [] { "SharedFolderUid" })]
    [DataContract]
    public class ExternalRecordMetadata : IEntityLink, IRecordMetadata, IEntityCopy<IRecordMetadata>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [SqlColumn(Length = 32)]
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "record_key", EmitDefaultValue = false)]
        public string RecordKey { get; set; }

        [SqlColumn]
        [DataMember(Name = "record_key_type")]
        public int RecordKeyType { get; set; }

        [SqlColumn]
        [DataMember(Name = "can_share")]
        public bool CanShare { get; set; }

        [SqlColumn]
        [DataMember(Name = "can_edit")]
        public bool CanEdit { get; set; }

        public string SubjectUid
        {
            get => RecordUid;
            set => RecordUid = value;
        }

        public string ObjectUid
        {
            get => SharedFolderUid;
            set => SharedFolderUid = value;
        }

        public void CopyFields(IRecordMetadata source)
        {
            RecordUid = source.RecordUid;
            SharedFolderUid = source.SharedFolderUid;
            RecordKeyType = source.RecordKeyType;
            RecordKey = source.RecordKey;
            CanShare = source.CanShare;
            CanEdit = source.CanEdit;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "NonSharedData", PrimaryKey = new[] { "RecordUid" })]
    [DataContract]
    public class ExternalNonSharedData : IEntity, INonSharedData, IEntityCopy<INonSharedData>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data { get; set; }

        public void CopyFields(INonSharedData source)
        {
            RecordUid = source.RecordUid;
            Data = source.Data;
        }
        public string Uid
        {
            get => RecordUid;
            set => RecordUid = value;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "SharedFolders", PrimaryKey = new[] { "SharedFolderUid" })]
    [DataContract]
    public class ExternalSharedFolder : IEntity, ISharedFolder, IEntityCopy<ISharedFolder>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [SqlColumn(Length = 256)]
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [SqlColumn]
        [DataMember(Name = "default_manage_records")]
        public bool DefaultManageRecords { get; set; }

        [SqlColumn]
        [DataMember(Name = "default_manage_users")]
        public bool DefaultManageUsers { get; set; }

        [SqlColumn]
        [DataMember(Name = "default_can_edit")]
        public bool DefaultCanEdit { get; set; }

        [SqlColumn]
        [DataMember(Name = "default_can_share")]
        public bool DefaultCanShare { get; set; }

        public string Uid
        {
            get => SharedFolderUid;
            set => SharedFolderUid = value;
        }

        public void CopyFields(ISharedFolder source)
        {
            SharedFolderUid = source.Uid;
            Revision = source.Revision;
            Name = source.Name;
            DefaultManageRecords = source.DefaultManageRecords;
            DefaultManageUsers = source.DefaultManageUsers;
            DefaultCanEdit = source.DefaultCanEdit;
            DefaultCanShare = source.DefaultCanShare;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "SharedFolderKeys", PrimaryKey = new[] {"SharedFolderUid", "TeamUid"}, Index1 = new[] {"TeamUid"})]
    [DataContract]
    public class ExternalSharedFolderKey : IEntityLink, ISharedFolderKey, IEntityCopy<ISharedFolderKey>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [SqlColumn(Length = 32)]
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "key_type")]
        public int KeyType { get; set; }

        [SqlColumn]
        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)]
        public string SharedFolderKey { get; set; }

        public string SubjectUid
        {
            get => SharedFolderUid;
            set => SharedFolderUid = value;
        }

        public string ObjectUid
        {
            get => TeamUid;
            set => TeamUid = value;
        }

        public void CopyFields(ISharedFolderKey source)
        {
            SharedFolderUid = source.SharedFolderUid;
            TeamUid = source.TeamUid;
            KeyType = source.KeyType;
            SharedFolderKey = source.SharedFolderKey;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "SharedFolderUsers", PrimaryKey = new[] { "SharedFolderUid", "UserId" }, Index1 = new[] { "UserId" })]
    [DataContract]
    public class ExternalSharedFolderPermission : IEntityLink, ISharedFolderPermission, IEntityCopy<ISharedFolderPermission>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [SqlColumn(Length = 64)]
        [DataMember(Name = "user_id", EmitDefaultValue = false)]
        public string UserId { get; set; }

        [SqlColumn]
        [DataMember(Name = "user_type")]
        public int UserType { get; set; }

        [SqlColumn]
        [DataMember(Name = "manage_records")]
        public bool ManageRecords { get; set; }

        [SqlColumn]
        [DataMember(Name = "manage_users")]
        public bool ManageUsers { get; set; }

        public string SubjectUid
        {
            get => SharedFolderUid;
            set => SharedFolderUid = value;
        }

        public string ObjectUid
        {
            get => UserId;
            set => UserId = value;
        }

        public void CopyFields(ISharedFolderPermission source)
        {
            SharedFolderUid = source.SharedFolderUid;
            UserId = source.UserId;
            UserType = source.UserType;
            ManageRecords = source.ManageRecords;
            ManageUsers = source.ManageUsers;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "Teams", PrimaryKey = new[] { "TeamUid" })]
    [DataContract]
    public class ExternalEnterpriseTeam : IEntity, IEnterpriseTeam, IEntityCopy<IEnterpriseTeam>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }

        [SqlColumn(Length = 256)]
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [SqlColumn]
        [DataMember(Name = "team_key", EmitDefaultValue = false)]
        public string TeamKey { get; set; }

        [SqlColumn]
        [DataMember(Name = "key_type")]
        public int KeyType { get; set; }

        [SqlColumn]
        [DataMember(Name = "team_private_key", EmitDefaultValue = false)]
        public string TeamPrivateKey { get; set; }

        [SqlColumn]
        [DataMember(Name = "restrict_edit")]
        public bool RestrictEdit { get; set; }

        [SqlColumn]
        [DataMember(Name = "restrict_share")]
        public bool RestrictShare { get; set; }

        [SqlColumn]
        [DataMember(Name = "restrict_view")]
        public bool RestrictView { get; set; }

        public string Uid
        {
            get => TeamUid;
            set => TeamUid = value;
        }

        public void CopyFields(IEnterpriseTeam source)
        {
            TeamUid = source.TeamUid;
            Name = source.Name;
            TeamKey = source.TeamKey;
            KeyType = source.KeyType;
            TeamPrivateKey = source.TeamPrivateKey;
            RestrictEdit = source.RestrictEdit;
            RestrictShare = source.RestrictShare;
            RestrictView = source.RestrictView;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "Folders", PrimaryKey = new[] { "FolderUid" })]
    [DataContract]
    public class ExternalFolder : IEntity, IFolder, IEntityCopy<IFolder>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string FolderUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [SqlColumn(Length = 32)]
        [DataMember(Name = "parent_uid", EmitDefaultValue = false)]
        public string ParentUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "folder_type", EmitDefaultValue = false)]
        public string FolderType { get; set; }

        [SqlColumn]
        [DataMember(Name = "folder_key", EmitDefaultValue = false)]
        public string FolderKey { get; set; }

        [SqlColumn(Length = 32)]
        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [SqlColumn]
        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data { get; set; }

        public string Uid
        {
            get => FolderUid;
            set => FolderUid = value;
        }

        public void CopyFields(IFolder source)
        {
            FolderUid = source.FolderUid;
            Revision = source.Revision;
            ParentUid = source.ParentUid;
            FolderType = source.FolderType;
            FolderKey = source.FolderKey;
            SharedFolderUid = source.SharedFolderUid;
            Data = source.Data;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "FolderRecords", PrimaryKey = new[] {"FolderUid", "RecordUid"}, Index1 = new[] {"RecordUid"})]
    [DataContract]
    public class ExternalFolderRecordLink : IEntityLink, IFolderRecordLink, IEntityCopy<IFolderRecordLink>
    {
        [SqlColumn(Length = 32)]
        [DataMember(Name = "folder_uid", EmitDefaultValue = false)]
        public string FolderUid { get; set; }

        [SqlColumn(Length = 32)]
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        public string SubjectUid
        {
            get => FolderUid;
            set => FolderUid = value;
        }

        public string ObjectUid
        {
            get => RecordUid;
            set => RecordUid = value;
        }

        public void CopyFields(IFolderRecordLink source)
        {
            FolderUid = source.FolderUid;
            RecordUid = source.RecordUid;
        }
    }
}