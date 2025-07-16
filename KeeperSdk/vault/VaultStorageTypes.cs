using KeeperSecurity.Storage;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <exclude />
    [SqlTable(Name = "VaultSettings")]
    public class VaultSettings : IVaultSettings, IEntityCopy<IVaultSettings>
    {
        [SqlColumn] public byte[] SyncDownToken { get; set; }

        void IEntityCopy<IVaultSettings>.CopyFields(IVaultSettings source)
        {
            SyncDownToken = source.SyncDownToken;
        }
    }

    /// <exclude />
    [SqlTable(Name = "Record", PrimaryKey = new[] { "RecordUid" })]
    public class StorageRecord : IStorageRecord, IEntityCopy<IStorageRecord>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public long Revision { get; set; }
        [SqlColumn] public int Version { get; set; }
        [SqlColumn] public long ClientModifiedTime { get; set; }
        [SqlColumn] public string Data { get; set; }
        [SqlColumn] public string Extra { get; set; }
        [SqlColumn] public string Udata { get; set; }
        [SqlColumn] public bool Shared { get; set; }

        string IUid.Uid => RecordUid;

        void IEntityCopy<IStorageRecord>.CopyFields(IStorageRecord source)
        {
            RecordUid = source.RecordUid;
            Revision = source.Revision;
            Version = source.Version;
            ClientModifiedTime = source.ClientModifiedTime;
            Data = source.Data;
            Extra = source.Extra;
            Udata = source.Udata;
            Shared = source.Shared;
        }
    }

    /// <exclude />
    [SqlTable(Name = "SharedFolder", PrimaryKey = new[] { "SharedFolderUid" })]
    public class StorageSharedFolder : IStorageSharedFolder, IEntityCopy<IStorageSharedFolder>
    {
        [SqlColumn(Length = 32)] public string SharedFolderUid { get; set; }
        [SqlColumn] public long Revision { get; set; }
        [SqlColumn(Length = 256)] public string Name { get; set; }
        [SqlColumn] public string Data { get; set; }
        [SqlColumn] public string OwnerAccountUid { get; set; }
        [SqlColumn] public bool DefaultManageRecords { get; set; }
        [SqlColumn] public bool DefaultManageUsers { get; set; }
        [SqlColumn] public bool DefaultCanEdit { get; set; }
        [SqlColumn] public bool DefaultCanShare { get; set; }

        string IUid.Uid => SharedFolderUid;

        void IEntityCopy<IStorageSharedFolder>.CopyFields(IStorageSharedFolder source)
        {
            SharedFolderUid = source.Uid;
            Revision = source.Revision;
            Name = source.Name;
            Data = source.Data;
            OwnerAccountUid = source.OwnerAccountUid;
            DefaultManageRecords = source.DefaultManageRecords;
            DefaultManageUsers = source.DefaultManageUsers;
            DefaultCanEdit = source.DefaultCanEdit;
            DefaultCanShare = source.DefaultCanShare;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "NonSharedData", PrimaryKey = new[] { "RecordUid" })]
    public class StorageNonSharedData : IStorageNonSharedData, IEntityCopy<IStorageNonSharedData>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public string Data { get; set; }

        void IEntityCopy<IStorageNonSharedData>.CopyFields(IStorageNonSharedData source)
        {
            RecordUid = source.RecordUid;
            Data = source.Data;
        }

        string IUid.Uid => RecordUid;
    }


    /// <exclude/>
    [SqlTable(Name = "RecordKey", PrimaryKey = new[] { "RecordUid", "SharedFolderUid" },
        Index1 = new[] { "SharedFolderUid" })]
    public class StorageRecordKey : IStorageRecordKey, IEntityCopy<IStorageRecordKey>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn(Length = 32)] public string SharedFolderUid { get; set; }
        [SqlColumn] public string RecordKey { get; set; }
        [SqlColumn] public int RecordKeyType { get; set; }
        [SqlColumn] public bool CanShare { get; set; }
        [SqlColumn] public bool CanEdit { get; set; }
        [SqlColumn] public long Expiration { get; set; }
        [SqlColumn] public bool Owner { get; set; }
        [SqlColumn] public string OwnerAccountUid { get; set; }

        void IEntityCopy<IStorageRecordKey>.CopyFields(IStorageRecordKey source)
        {
            RecordUid = source.RecordUid;
            SharedFolderUid = source.SharedFolderUid;
            RecordKey = source.RecordKey;
            RecordKeyType = source.RecordKeyType;
            CanShare = source.CanShare;
            CanEdit = source.CanEdit;
            Expiration = source.Expiration;
            Owner = source.Owner;
            OwnerAccountUid = source.OwnerAccountUid;
        }

        string IUidLink.SubjectUid => RecordUid;
        string IUidLink.ObjectUid => SharedFolderUid;
    }

    /// <exclude/>
    [SqlTable(Name = "SharedFolderKey", PrimaryKey = new[] { "SharedFolderUid", "TeamUid" },
        Index1 = new[] { "TeamUid" })]
    public class StorageSharedFolderKey : IStorageSharedFolderKey, IEntityCopy<IStorageSharedFolderKey>
    {
        [SqlColumn(Length = 32)] public string SharedFolderUid { get; set; }
        [SqlColumn(Length = 32)] public string TeamUid { get; set; }
        [SqlColumn] public int KeyType { get; set; }
        [SqlColumn] public string SharedFolderKey { get; set; }

        void IEntityCopy<IStorageSharedFolderKey>.CopyFields(IStorageSharedFolderKey source)
        {
            SharedFolderUid = source.SharedFolderUid;
            TeamUid = source.TeamUid;
            KeyType = source.KeyType;
            SharedFolderKey = source.SharedFolderKey;
        }

        string IUidLink.SubjectUid => SharedFolderUid;
        string IUidLink.ObjectUid => TeamUid;
    }


    /// <exclude/>
    [SqlTable(Name = "VaultTeam", PrimaryKey = new[] { "TeamUid" })]
    public class StorageTeam : IStorageTeam, IEntityCopy<IStorageTeam>
    {
        [SqlColumn(Length = 32)] public string TeamUid { get; set; }
        [SqlColumn(Length = 256)] public string Name { get; set; }
        [SqlColumn] public string TeamKey { get; set; }
        [SqlColumn] public int KeyType { get; set; }
        [SqlColumn] public string TeamRsaPrivateKey { get; set; }
        [SqlColumn] public string TeamEcPrivateKey { get; set; }
        [SqlColumn] public bool RestrictEdit { get; set; }
        [SqlColumn] public bool RestrictShare { get; set; }
        [SqlColumn] public bool RestrictView { get; set; }

        string IUid.Uid => TeamUid;

        void IEntityCopy<IStorageTeam>.CopyFields(IStorageTeam source)
        {
            TeamUid = source.TeamUid;
            Name = source.Name;
            TeamKey = source.TeamKey;
            KeyType = source.KeyType;
            TeamRsaPrivateKey = source.TeamRsaPrivateKey;
            TeamEcPrivateKey = source.TeamEcPrivateKey;
            RestrictEdit = source.RestrictEdit;
            RestrictShare = source.RestrictShare;
            RestrictView = source.RestrictView;
        }
    }

    /// <exclude/>
    [SqlTable(Name = "SharedFolderPermission", PrimaryKey = new[] { "SharedFolderUid", "UserId" },
        Index1 = new[] { "UserId" })]
    public class StorageSharedFolderPermission : ISharedFolderPermission, IEntityCopy<ISharedFolderPermission>
    {
        [SqlColumn(Length = 32)] public string SharedFolderUid { get; set; }
        [SqlColumn(Length = 64)] public string UserId { get; set; }
        [SqlColumn] public int UserType { get; set; }
        [SqlColumn] public bool ManageRecords { get; set; }
        [SqlColumn] public bool ManageUsers { get; set; }
        [SqlColumn] public long Expiration { get; set; }

        void IEntityCopy<ISharedFolderPermission>.CopyFields(ISharedFolderPermission source)
        {
            SharedFolderUid = source.SharedFolderUid;
            UserId = source.UserId;
            UserType = source.UserType;
            ManageRecords = source.ManageRecords;
            ManageUsers = source.ManageUsers;
            Expiration = source.Expiration;
        }

        string IUidLink.SubjectUid => SharedFolderUid;
        string IUidLink.ObjectUid => UserId;
    }

    /// <exclude/>
    [SqlTable(Name = "Folder", PrimaryKey = new[] { "FolderUid" })]
    public class StorageFolder : IStorageFolder, IEntityCopy<IStorageFolder>
    {
        [SqlColumn(Length = 32)] public string FolderUid { get; set; }
        [SqlColumn] public long Revision { get; set; }
        [SqlColumn(Length = 32)] public string ParentUid { get; set; }
        [SqlColumn] public string FolderType { get; set; }
        [SqlColumn] public string FolderKey { get; set; }
        [SqlColumn(Length = 32)] public string SharedFolderUid { get; set; }
        [SqlColumn] public string Data { get; set; }

        void IEntityCopy<IStorageFolder>.CopyFields(IStorageFolder source)
        {
            FolderUid = source.FolderUid;
            Revision = source.Revision;
            ParentUid = source.ParentUid;
            FolderType = source.FolderType;
            FolderKey = source.FolderKey;
            SharedFolderUid = source.SharedFolderUid;
            Data = source.Data;
        }

        string IUid.Uid => FolderUid;
    }

    /// <exclude/>
    [SqlTable(Name = "FolderRecord", PrimaryKey = new[] { "FolderUid", "RecordUid" }, Index1 = new[] { "RecordUid" })]
    public class StorageFolderRecord : IStorageFolderRecord, IEntityCopy<IStorageFolderRecord>
    {
        [SqlColumn(Length = 32)] public string FolderUid { get; set; }
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }

        void IEntityCopy<IStorageFolderRecord>.CopyFields(IStorageFolderRecord source)
        {
            FolderUid = source.FolderUid;
            RecordUid = source.RecordUid;
        }

        string IUidLink.SubjectUid => FolderUid;
        string IUidLink.ObjectUid => RecordUid;
    }

    /// <exclude/>
    [SqlTable(Name = "RecordType", PrimaryKey = new[] { "Name" })]
    public class StorageRecordType : IStorageRecordType, IEntityCopy<IStorageRecordType>
    {
        [SqlColumn] public string Name { get; set; }
        [SqlColumn] public int RecordTypeId { get; set; }
        [SqlColumn] public int Scope { get; set; }
        [SqlColumn] public string Content { get; set; }

        void IEntityCopy<IStorageRecordType>.CopyFields(IStorageRecordType source)
        {
            Name = source.Name;
            RecordTypeId = source.RecordTypeId;
            Scope = source.Scope;
            Content = source.Content;
        }

        string IUid.Uid => Name;
    }


    /// <exclude/>
    [SqlTable(Name = "UserEmail", PrimaryKey = new[] { "AccountUid", "Email" }, Index1 = new[] { "Email" })]
    public class StorageUserEmail : IStorageUserEmail, IEntityCopy<IStorageUserEmail>
    {
        [SqlColumn(Length = 32)] public string AccountUid { get; set; }

        [SqlColumn(Length = 64)] public string Email { get; set; }

        void IEntityCopy<IStorageUserEmail>.CopyFields(IStorageUserEmail source)
        {
            AccountUid = source.AccountUid;
            Email = source.Email;
        }

        string IUidLink.SubjectUid => AccountUid;
        string IUidLink.ObjectUid => Email;
    }

    /// <exclude />
    [SqlTable(Name = "BreachWatchRecord", PrimaryKey = new[] { "RecordUid" })]
    public class StorageBreachWatchRecord : IStorageBreachWatchRecord, IEntityCopy<IStorageBreachWatchRecord>
    {
        [SqlColumn(Length = 32)] public string RecordUid { get; set; }
        [SqlColumn] public long Revision { get; set; }
        [SqlColumn] public int Type { get; set; }
        [SqlColumn] public string Data { get; set; }

        string IUid.Uid => RecordUid;

        void IEntityCopy<IStorageBreachWatchRecord>.CopyFields(IStorageBreachWatchRecord source)
        {
            RecordUid = source.RecordUid;
            Revision = source.Revision;
            Type = source.Type;
            Data = source.Data;
        }
    }
}