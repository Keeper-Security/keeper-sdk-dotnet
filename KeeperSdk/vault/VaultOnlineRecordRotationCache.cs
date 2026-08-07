using System;
using System.Collections.Generic;
using System.Threading;
using KeeperSecurity.Utils;
using VaultProto = Vault;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Record rotation metadata from <c>vault/sync_down</c> (Commander <c>record_rotation_cache</c> equivalent).
    /// </summary>
    public sealed class RecordRotationInfo
    {
        public string RecordUid { get; set; } = "";
        public long Revision { get; set; }
        public string ConfigurationUid { get; set; } = "";
        public string Schedule { get; set; } = "";
        public byte[] PasswordComplexity { get; set; } = Array.Empty<byte>();
        public bool Disabled { get; set; }
        public string ResourceUid { get; set; } = "";
        public long LastRotation { get; set; }
        public int LastRotationStatus { get; set; }
    }

    public partial class VaultOnline
    {
        private readonly Dictionary<string, RecordRotationInfo> _recordRotationCache =
            new(StringComparer.Ordinal);
        private int _recordRotationsCleared;

        /// <summary>
        /// Full record-rotation map populated by normal vault sync-down.
        /// </summary>
        public IReadOnlyDictionary<string, RecordRotationInfo> RecordRotationCache => _recordRotationCache;

        public bool TryGetRecordRotation(string recordUid, out RecordRotationInfo rotation)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                rotation = null;
                return false;
            }

            return _recordRotationCache.TryGetValue(recordUid, out rotation);
        }

        public RecordRotationInfo GetRecordRotation(string recordUid)
        {
            return TryGetRecordRotation(recordUid, out var rotation) ? rotation : null;
        }

        /// <summary>
        /// Checks whether the rotation cache was cleared and resets the flag.
        /// </summary>
        /// <remarks>
        /// Only the first caller sees true after a clear. Use it to trigger a full rotation refresh.
        /// </remarks>
        public bool ConsumeRotationsCleared()
        {
            return Interlocked.Exchange(ref _recordRotationsCleared, 0) != 0;
        }

        /// <summary>
        /// Clears the rotation cache and marks it for the next rotation refresh.
        /// </summary>
        internal void ClearRecordRotationCache()
        {
            _recordRotationCache.Clear();
            Interlocked.Exchange(ref _recordRotationsCleared, 1);
        }

        internal void RemoveFromRecordRotationCache(IEnumerable<string> recordUids)
        {
            if (recordUids == null)
            {
                return;
            }

            foreach (var recordUid in recordUids)
            {
                if (!string.IsNullOrEmpty(recordUid))
                {
                    _recordRotationCache.Remove(recordUid);
                }
            }
        }

        internal void UpdateRecordRotationCache(IEnumerable<VaultProto.RecordRotation> rotations)
        {
            if (rotations == null)
            {
                return;
            }

            foreach (var rotation in rotations)
            {
                var recordUid = rotation.RecordUid?.ToByteArray().Base64UrlEncode();
                if (string.IsNullOrEmpty(recordUid))
                {
                    continue;
                }

                _recordRotationCache[recordUid] = new RecordRotationInfo
                {
                    RecordUid = recordUid,
                    Revision = rotation.Revision,
                    ConfigurationUid = rotation.ConfigurationUid?.ToByteArray().Base64UrlEncode() ?? "",
                    Schedule = rotation.Schedule ?? "",
                    PasswordComplexity = rotation.PwdComplexity?.ToByteArray() ?? Array.Empty<byte>(),
                    Disabled = rotation.Disabled,
                    ResourceUid = rotation.ResourceUid?.ToByteArray().Base64UrlEncode() ?? "",
                    LastRotation = rotation.LastRotation,
                    LastRotationStatus = (int)rotation.LastRotationStatus,
                };
            }
        }

        internal bool HasRecordRotationConfigured(string recordUid)
        {
            return !string.IsNullOrEmpty(recordUid) && _recordRotationCache.ContainsKey(recordUid);
        }
    }
}
