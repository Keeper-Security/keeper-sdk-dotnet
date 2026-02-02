using System;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault;

/// <summary>
/// Change-tracking cache wrapper for IKeeperStorage.
/// Only caches modifications (adds/updates/deletes) - all unmodified data is read from source.
/// </summary>
public class SnapshotKeeperStorage : IKeeperStorage
{
    public SnapshotKeeperStorage(IKeeperStorage sourceStorage)
    {
        if (sourceStorage == null) throw new ArgumentNullException(nameof(sourceStorage));

        PersonalScopeUid = sourceStorage.PersonalScopeUid;

        VaultSettings = new SnapshotRecordStorage<IVaultSettings>(sourceStorage.VaultSettings);
        Records = new SnapshotEntityStorage<IStorageRecord>(sourceStorage.Records);
        SharedFolders = new SnapshotEntityStorage<IStorageSharedFolder>(sourceStorage.SharedFolders);
        Teams = new SnapshotEntityStorage<IStorageTeam>(sourceStorage.Teams);
        NonSharedData = new SnapshotEntityStorage<IStorageNonSharedData>(sourceStorage.NonSharedData);
        RecordKeys = new SnapshotLinkStorage<IStorageRecordKey>(sourceStorage.RecordKeys);
        SharedFolderKeys = new SnapshotLinkStorage<IStorageSharedFolderKey>(sourceStorage.SharedFolderKeys);
        SharedFolderPermissions = new SnapshotLinkStorage<ISharedFolderPermission>(sourceStorage.SharedFolderPermissions);
        Folders = new SnapshotEntityStorage<IStorageFolder>(sourceStorage.Folders);
        FolderRecords = new SnapshotLinkStorage<IStorageFolderRecord>(sourceStorage.FolderRecords);
        RecordTypes = new SnapshotEntityStorage<IStorageRecordType>(sourceStorage.RecordTypes);
        UserEmails = new SnapshotLinkStorage<IStorageUserEmail>(sourceStorage.UserEmails);
        BreachWatchRecords = new SnapshotEntityStorage<IStorageBreachWatchRecord>(sourceStorage.BreachWatchRecords);
    }

    public string PersonalScopeUid { get; }

    public IRecordStorage<IVaultSettings> VaultSettings { get; }
    public IEntityStorage<IStorageRecord> Records { get; }
    public IEntityStorage<IStorageSharedFolder> SharedFolders { get; }
    public IEntityStorage<IStorageTeam> Teams { get; }
    public IEntityStorage<IStorageNonSharedData> NonSharedData { get; }
    public ILinkStorage<IStorageRecordKey> RecordKeys { get; }
    public ILinkStorage<IStorageSharedFolderKey> SharedFolderKeys { get; }
    public ILinkStorage<ISharedFolderPermission> SharedFolderPermissions { get; }
    public IEntityStorage<IStorageFolder> Folders { get; }
    public ILinkStorage<IStorageFolderRecord> FolderRecords { get; }
    public IEntityStorage<IStorageRecordType> RecordTypes { get; }
    public ILinkStorage<IStorageUserEmail> UserEmails { get; }
    public IEntityStorage<IStorageBreachWatchRecord> BreachWatchRecords { get; }

    public void Clear()
    {
        // Clear() is called during full sync, which is not supported with cached storage
        // because it would require clearing MySQL data (read-only source)
        throw new NotSupportedException(
            "CachedKeeperStorage does not support full sync (Clear operation). " +
            "Full sync requires clearing the backing MySQL storage, which violates the read-only contract. " +
            "Use incremental sync only.");
    }
}
