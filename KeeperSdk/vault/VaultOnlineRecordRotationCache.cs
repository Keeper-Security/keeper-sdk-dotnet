using System;
using System.Collections.Generic;
using KeeperSecurity.Utils;
using VaultProto = Vault;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline
    {
        private readonly HashSet<string> _recordRotationCache = new(StringComparer.Ordinal);

        internal void ClearRecordRotationCache()
        {
            _recordRotationCache.Clear();
        }

        internal void RemoveFromRecordRotationCache(IEnumerable<string> recordUids)
        {
            if (recordUids == null)
                return;

            foreach (var recordUid in recordUids)
            {
                if (!string.IsNullOrEmpty(recordUid))
                    _recordRotationCache.Remove(recordUid);
            }
        }

        internal void UpdateRecordRotationCache(IEnumerable<VaultProto.RecordRotation> rotations)
        {
            if (rotations == null)
                return;

            foreach (var rotation in rotations)
            {
                var recordUid = rotation.RecordUid.ToByteArray().Base64UrlEncode();
                if (!string.IsNullOrEmpty(recordUid))
                    _recordRotationCache.Add(recordUid);
            }
        }

        internal bool HasRecordRotationConfigured(string recordUid)
        {
            return !string.IsNullOrEmpty(recordUid) && _recordRotationCache.Contains(recordUid);
        }
    }
}
