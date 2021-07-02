using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace KeeperSecurity.Enterprise
{
    /// <exclude/>
    public abstract class EnterpriseDataPlugin
    {
        public IEnterpriseLoader Enterprise { get; internal set; }
        public abstract IEnumerable<IKeeperEnterpriseEntity> Entities { get; }
    }

    /// <summary>
    /// Represents Keeper Enterprise connection that incrementally loads requested enterprrise data.
    /// </summary>
    public class EnterpriseLoader : IEnterpriseLoader
    {
        /// <summary>
        /// Gets Keeper authentication.
        /// </summary>
        public IAuthentication Auth { get; }

        /// <summary>
        /// Gets enterprise data
        /// </summary>
        public string EnterpriseName { get; private set; }

        /// <summary>
        /// Gets Enterprise Tree encryption key.
        /// </summary>
        public byte[] TreeKey { get; private set; }


        /// <exclude/>
        public byte[] RsaPrivateKey { get; set; }

        /// <exclude/>
        public byte[] EcPrivateKey { get; set; }

        private byte[] _continuationToken;

        /// <summary>
        /// Initialises EnterpriseLoader instance.
        /// </summary>
        /// <param name="auth">Keeper Authentication</param>
        /// <param name="plugins">Enterprise data plugins</param>
        /// <param name="treeKey">Enterprise tree key. Optional.</param>
        /// <seealso cref="EnterpriseData"/>
        /// <seealso cref="RoleData"/>
        /// <seealso cref="DeviceApprovalData"/>
        /// <seealso cref="ManagedCompanyData"/>
        public EnterpriseLoader(IAuthentication auth, IEnumerable<EnterpriseDataPlugin> plugins, byte[] treeKey = null)
        {
            Auth = auth;
            TreeKey = treeKey;
            _continuationToken = new byte[0];

            foreach (var plugin in plugins)
            {
                plugin.Enterprise = this;
                foreach (var entity in plugin.Entities)
                {
                    RegisterEnterpriseEntity(entity);
                }
            }
        }

        private readonly ConcurrentDictionary<EnterpriseDataEntity, IList<IKeeperEnterpriseEntity>> _entities
            = new ConcurrentDictionary<EnterpriseDataEntity, IList<IKeeperEnterpriseEntity>>();

        private IEnterpriseLoader GetEnterprise()
        {
            return this;
        }
        private void RegisterEnterpriseEntity(IKeeperEnterpriseEntity entity)
        {
            if (!_entities.TryGetValue(entity.DataEntity, out var lst))
            {
                lst = new List<IKeeperEnterpriseEntity>();
                _entities.TryAdd(entity.DataEntity, lst);
            }
            if (!lst.Contains(entity))
            {
                if (entity is IGetEnterprise ge)
                {
                    ge.GetEnterprise = GetEnterprise;
                }
                lst.Add(entity);
            }
        }

        /// <summary>
        /// Retrieves Enterprise Data structure.
        /// </summary>
        /// <returns>Awaitable task.</returns>
        public async Task Load()
        {
            if (TreeKey == null)
            {
                var krq = new GetEnterpriseDataKeysRequest();
                var krs = await Auth.ExecuteAuthRest<GetEnterpriseDataKeysRequest, GetEnterpriseDataKeysResponse>("enterprise/get_enterprise_data_keys", krq);
                var encTreeKey = krs.TreeKey.TreeKey_.Base64UrlDecode();
                switch (krs.TreeKey.KeyTypeId)
                {
                    case BackupKeyType.EncryptedByDataKey:
                        TreeKey = CryptoUtils.DecryptAesV1(encTreeKey, Auth.AuthContext.DataKey);
                        break;
                    case BackupKeyType.EncryptedByPublicKey:
                        if (encTreeKey.Length > 60)
                        {
                            TreeKey = CryptoUtils.DecryptRsa(encTreeKey, Auth.AuthContext.PrivateKey);
                        }
                        break;
                    default:
                        throw new Exception("cannot decrypt tree key");
                }

                if (krs.EnterpriseKeys != null)
                {
                    if (!krs.EnterpriseKeys.RsaEncryptedPrivateKey.IsEmpty)
                    {
                        RsaPrivateKey = CryptoUtils.DecryptAesV2(krs.EnterpriseKeys.RsaEncryptedPrivateKey.ToByteArray(), TreeKey);
                    }
                    if (!krs.EnterpriseKeys.EccEncryptedPrivateKey.IsEmpty)
                    {
                        EcPrivateKey = CryptoUtils.DecryptAesV2(krs.EnterpriseKeys.EccEncryptedPrivateKey.ToByteArray(), TreeKey);
                    }
                }
            }

            var done = false;
            while (!done)
            {
                var rrq = new EnterpriseDataRequest
                {
                    ContinuationToken = Google.Protobuf.ByteString.CopyFrom(_continuationToken)
                };
                var rrs = await Auth.ExecuteAuthRest<EnterpriseDataRequest, EnterpriseDataResponse>("enterprise/get_enterprise_data_for_user", rrq);
                if (rrs.CacheStatus == CacheStatus.Clear)
                {
                    foreach (var entities in _entities.Values)
                    {
                        foreach (var entity in entities)
                        {
                            entity.Clear();
                        }
                    }
                }
                if (rrs.GeneralData != null)
                {
                }
                done = !rrs.HasMore;
                _continuationToken = rrs.ContinuationToken.ToByteArray();
                if (string.IsNullOrEmpty(EnterpriseName) && rrs.GeneralData != null)
                {
                    EnterpriseName = rrs.GeneralData.EnterpriseName;
                }

                foreach (var entityData in rrs.Data)
                {
                    if (_entities.TryGetValue(entityData.Entity, out var entities))
                    {
                        foreach (var entity in entities)
                        {
                            entity.ProcessKeeperEnterpriseData(entityData);
                        }
                    }
                }
            }
        }

        private readonly ConcurrentBag<long> _availableIds = new ConcurrentBag<long>();

        /// <summary>
        ///     Returns unique enterprise id.
        /// </summary>
        /// <returns>Enterprise ID. Awaitable task.</returns>
        public async Task<long> GetEnterpriseId()
        {
            if (_availableIds.TryTake(out var id))
            {
                return id;
            }

            var rs = await Auth.ExecuteAuthCommand<EnterpriseAllocateIdsCommand, EnterpriseAllocateIdsResponse>(new EnterpriseAllocateIdsCommand());
            if (rs.IsSuccess)
            {
                for (int i = 1; i < rs.NumberAllocated; i++)
                {
                    _availableIds.Add(rs.BaseId + i);
                }
                return rs.BaseId;
            }
            throw new Exception("Unable to allocate enterprise ID");
        }
    }
}
