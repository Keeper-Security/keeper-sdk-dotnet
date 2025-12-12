using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;
using Folder;

namespace KeeperSecurity.Plugins.PEDM
{
    public class RebuildTask
    {
        private readonly bool _fullRebuild;
        private HashSet<string> _agents;
        private HashSet<string> _policies;
        private HashSet<string> _collections;
        private HashSet<string> _approvals;

        public RebuildTask(bool fullRebuild = false)
        {
            _fullRebuild = fullRebuild;
        }

        public bool FullRebuild => _fullRebuild;

        public void AddAgents(IEnumerable<string> agents)
        {
            if (_fullRebuild) return;
            if (_agents == null)
            {
                _agents = new HashSet<string>();
            }
            foreach (var agent in agents)
            {
                _agents.Add(agent);
            }
        }

        public void AddPolicies(IEnumerable<string> policies)
        {
            if (_fullRebuild) return;
            if (_policies == null)
            {
                _policies = new HashSet<string>();
            }
            foreach (var policy in policies)
            {
                _policies.Add(policy);
            }
        }

        public void AddCollections(IEnumerable<string> collections)
        {
            if (_fullRebuild) return;
            if (_collections == null)
            {
                _collections = new HashSet<string>();
            }
            foreach (var collection in collections)
            {
                _collections.Add(collection);
            }
        }

        public void AddApprovals(IEnumerable<string> approvals)
        {
            if (_fullRebuild) return;
            if (_approvals == null)
            {
                _approvals = new HashSet<string>();
            }
            foreach (var approval in approvals)
            {
                _approvals.Add(approval);
            }
        }

        public IEnumerable<string> Agents => _agents;
        public IEnumerable<string> Policies => _policies;
        public IEnumerable<string> Collections => _collections;
        public IEnumerable<string> Approvals => _approvals;
    }

    public interface IPedmAdmin
    {
        Task SyncDown(bool reload = false);
        IEntityStorage<PedmDeployment> Deployments { get; }
        IEntityStorage<PedmAgent> Agents { get; }
    }

    public class PedmDeployment : IUid
    {
        public string DeploymentUid { get; set; }
        public bool Disabled { get; set; }
        public byte[] DeploymentKey { get; set; }
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public string Name { get; set; }
        public byte[] EncryptedData { get; set; }
        public byte[] AgentData { get; set; }
        public long Created { get; set; }
        public long Modified { get; set; }
        public string Uid => DeploymentUid;
    }

    public class PedmAgent : IUid
    {
        public string AgentUid { get; set; }
        public string MachineId { get; set; }
        public string DeploymentUid { get; set; }
        public byte[] PublicKey { get; set; }
        public bool Disabled { get; set; }
        public long Created { get; set; }
        public long Modified { get; set; }
        public string Uid => AgentUid;
    }

    public class PedmPolicy : IUid
    {
        public string PolicyUid { get; set; }
        public byte[] PolicyKey { get; set; }
        public byte[] PolicyData { get; set; }
        public PolicyDataStructure Data { get; set; }        
        public Dictionary<string, object> AdminData { get; set; }
        public bool Disabled { get; set; }
        public long Created { get; set; }
        public long Updated { get; set; }
        public string Uid => PolicyUid;
    }

    public class PedmCollection : IUid
    {
        public string CollectionUid { get; set; }
        public int CollectionType { get; set; }
        public byte[] CollectionData { get; set; }
        public long Created { get; set; }
        public string Uid => CollectionUid;
    }

    public class PedmApproval : IUid
    {
        public string ApprovalUid { get; set; }
        public int ApprovalType { get; set; }
        public string AgentUid { get; set; }
        public byte[] AccountInfo { get; set; }
        public byte[] ApplicationInfo { get; set; }
        public byte[] Justification { get; set; }
        public int ExpireIn { get; set; }
        public long Created { get; set; }
        public string Uid => ApprovalUid;
    }

    public class PedmDeploymentAgent : IUidLink
    {
        public string DeploymentUid { get; set; }
        public string AgentUid { get; set; }
        public string SubjectUid => DeploymentUid;
        public string ObjectUid => AgentUid;
    }

    public class CollectionLink
    {
        public string CollectionUid { get; set; }
        public string LinkUid { get; set; }
        public PEDMProto.CollectionLinkType LinkType { get; set; }
    }

    public class CollectionLinkDataResult
    {
        public CollectionLink CollectionLink { get; set; }
        public byte[] LinkData { get; set; }
    }

    public class ModifyStatus
    {
        public List<string> Add { get; set; } = new List<string>();
        public List<string> Update { get; set; } = new List<string>();
        public List<string> Remove { get; set; } = new List<string>();
        
        public List<EntityStatus> AddErrors { get; set; } = new List<EntityStatus>();
        public List<EntityStatus> UpdateErrors { get; set; } = new List<EntityStatus>();
        public List<EntityStatus> RemoveErrors { get; set; } = new List<EntityStatus>();

        public static ModifyStatus FromProto(PEDMProto.PedmStatusResponse response)
        {
            var status = new ModifyStatus();
            foreach (var item in response.AddStatus)
            {
                var entityUid = item.Key.Count > 0 ? item.Key[0].ToByteArray().Base64UrlEncode() : null;
                if (entityUid != null)
                {
                    if (item.Success)
                    {
                        status.Add.Add(entityUid);
                    }
                    else
                    {
                        status.AddErrors.Add(new EntityStatus
                        {
                            EntityUid = entityUid,
                            Success = item.Success,
                            Message = item.Message
                        });
                    }
                }
            }
            foreach (var item in response.UpdateStatus)
            {
                var entityUid = item.Key.Count > 0 ? item.Key[0].ToByteArray().Base64UrlEncode() : null;
                if (entityUid != null)
                {
                    if (item.Success)
                    {
                        status.Update.Add(entityUid);
                    }
                    else
                    {
                        status.UpdateErrors.Add(new EntityStatus
                        {
                            EntityUid = entityUid,
                            Success = item.Success,
                            Message = item.Message
                        });
                    }
                }
            }
            foreach (var item in response.RemoveStatus)
            {
                var entityUid = item.Key.Count > 0 ? item.Key[0].ToByteArray().Base64UrlEncode() : null;
                if (entityUid != null)
                {
                    if (item.Success)
                    {
                        status.Remove.Add(entityUid);
                    }
                    else
                    {
                        status.RemoveErrors.Add(new EntityStatus
                        {
                            EntityUid = entityUid,
                            Success = item.Success,
                            Message = item.Message
                        });
                    }
                }
            }
            return status;
        }

        public void Merge(ModifyStatus other)
        {
            Add.AddRange(other.Add);
            Update.AddRange(other.Update);
            Remove.AddRange(other.Remove);
            AddErrors.AddRange(other.AddErrors);
            UpdateErrors.AddRange(other.UpdateErrors);
            RemoveErrors.AddRange(other.RemoveErrors);
        }
    }

    public class DeploymentDataInput
    {
        public string DeploymentUid { get; set; }
        public string Name { get; set; }
        public bool? Disabled { get; set; }
        public string SpiffeCert { get; set; }
    }

    public class CollectionData
    {
        public string CollectionUid { get; set; }
        public int CollectionType { get; set; }
        public string CollectionDataJson { get; set; }
    }

    public class UpdateAgent
    {
        public string AgentUid { get; set; }
        public string DeploymentUid { get; set; }
        public bool? Disabled { get; set; }
    }

    public class PedmPlugin : IPedmAdmin
    {
        private readonly IEnterpriseLoader _loader;
        private readonly IPedmStorage _storage;
        private readonly IAuthentication _auth;
        private readonly int _enterpriseId;
        private readonly string _enterpriseUid;
        private readonly string _deviceUid;
        private bool _populateData = true;
        private byte[] _agentKey;
        private byte[] _allAgents;

        private readonly InMemoryEntityStorage<PedmDeployment> _deployments = new();
        private readonly InMemoryEntityStorage<PedmAgent> _agents = new();
        private readonly InMemoryLinkStorage<PedmDeploymentAgent> _deploymentAgents = new();
        private readonly InMemoryEntityStorage<PedmPolicy> _policies = new();
        private readonly InMemoryEntityStorage<PedmCollection> _collections = new();
        private readonly InMemoryEntityStorage<PedmApproval> _approvals = new();

        private bool _needSync = true;

        public PedmPlugin(IEnterpriseLoader loader)
        {
            if (!loader.Auth.AuthContext.IsEnterpriseAdmin)
            {
                throw new InvalidOperationException("Enterprise admin access is required");
            }

            _loader = loader;
            _auth = loader.Auth;
            _enterpriseId = 0;
            var enterpriseIdBytes = BitConverter.GetBytes(_enterpriseId);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(enterpriseIdBytes);
            }
            _enterpriseUid = enterpriseIdBytes.Base64UrlEncode();
            _deviceUid = CryptoUtils.GenerateUid();
            _storage = new MemoryPedmStorage();

            if (_auth.PushNotifications != null)
            {
                _auth.PushNotifications.RegisterCallback(OnPushMessage);
            }
        }

        private bool OnPushMessage(NotificationEvent evt)
        {
            if (evt?.Event == "pedm_sync")
            {
                _needSync = true;
            }
            return false;
        }

        public void Close()
        {
            if (_auth.PushNotifications != null)
            {
                _auth.PushNotifications.RemoveCallback(OnPushMessage);
            }
        }

        public IEntityStorage<PedmDeployment> Deployments => _deployments;
        public IEntityStorage<PedmAgent> Agents => _agents;
        public IEntityStorage<PedmPolicy> Policies => _policies;
        public IEntityStorage<PedmCollection> Collections => _collections;
        public IEntityStorage<PedmApproval> Approvals => _approvals;
        public ILinkStorage<PedmDeploymentAgent> DeploymentAgents => _deploymentAgents;

        public bool NeedSync => _needSync;

        public byte[] AgentKey
        {
            get
            {
                if (_agentKey == null)
                {
                    var enterpriseData = _loader as EnterpriseLoader;
                    if (enterpriseData?.TreeKey != null)
                    {
                    var treeKey = enterpriseData.TreeKey;
                    byte[] salt;
                    if (treeKey.Length >= 32)
                    {
                        var x1Bytes = new byte[16];
                        Array.Copy(treeKey, 0, x1Bytes, 0, 16);
                        
                        var x2Bytes = new byte[16];
                        Array.Copy(treeKey, 16, x2Bytes, 0, 16);
                        
                        salt = new byte[16];
                        for (int i = 0; i < 16; i++)
                        {
                            salt[i] = (byte)(x1Bytes[i] ^ x2Bytes[i]);
                        }
                    }
                    else
                    {
                        var x1 = BitConverter.ToUInt64(treeKey, 0);
                        var x2 = treeKey.Length >= 16 ? BitConverter.ToUInt64(treeKey, 8) : 0UL;
                        var saltValue = x1 ^ x2;
                        salt = BitConverter.GetBytes(saltValue);
                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(salt);
                        }
                        if (salt.Length < 16)
                        {
                            var paddedSalt = new byte[16];
                            Array.Copy(salt, 0, paddedSalt, 16 - salt.Length, salt.Length);
                            salt = paddedSalt;
                        }
                    }
                        var ecPrivateKey = enterpriseData.EcPrivateKey;
                        if (ecPrivateKey != null)
                        {
                            var ecPrivateKeyBase64 = ecPrivateKey.Base64UrlEncode();
                            _agentKey = CryptoUtils.DeriveKeyV1(ecPrivateKeyBase64, salt, 1_000_000);
                        }
                    }
                }
                return _agentKey;
            }
        }

        public byte[] AllAgents
        {
            get
            {
                if (_allAgents == null)
                {
                    _allAgents = new byte[16]; 
                }
                return _allAgents;
            }
        }

        public async Task SyncDown(bool reload = false)
        {
            if (reload)
            {
                _needSync = true;
            }

            if (!_needSync) return;

            await _auth.SyncPedmData(_storage, _loader.TreeKey, reload);
            _needSync = false;

            if (_populateData)
            {
                var task = new RebuildTask(true);
                BuildData(task);
            }
        }

        public void BuildData(RebuildTask task)
        {
            var treeKey = _loader.TreeKey;
            if (treeKey == null) return;

            var _ = AgentKey;

            _deployments.Clear();
            var deps = new List<PedmDeployment>();
            foreach (var dep in _storage.Deployments.GetAll())
            {
                try
                {
                    var pd = LoadDeployment(dep, treeKey);
                    if (pd != null)
                    {
                        deps.Add(pd);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Deployment \"{dep.DeploymentUid}\" decryption error: {e.Message}");
                }
            }
            _deployments.PutEntities(deps);

            if (task.FullRebuild)
            {
                _agents.Clear();
                _policies.Clear();
                _collections.Clear();
                _approvals.Clear();
            }
            else
            {
                if (task.Agents != null)
                {
                    var agentsToRemove = _agents.GetAll().Where(a => task.Agents.Contains(a.AgentUid)).ToList();
                    foreach (var agent in agentsToRemove)
                    {
                        _agents.DeleteUids(new[] { agent.AgentUid });
                    }
                }

                if (task.Policies != null)
                {
                    var policiesToRemove = _policies.GetAll().Where(p => task.Policies.Contains(p.PolicyUid)).ToList();
                    foreach (var policy in policiesToRemove)
                    {
                        _policies.DeleteUids(new[] { policy.PolicyUid });
                    }
                }

                if (task.Collections != null)
                {
                    var collectionsToRemove = _collections.GetAll().Where(c => task.Collections.Contains(c.CollectionUid)).ToList();
                    foreach (var collection in collectionsToRemove)
                    {
                        _collections.DeleteUids(new[] { collection.CollectionUid });
                    }
                }

                if (task.Approvals != null)
                {
                    var approvalsToRemove = _approvals.GetAll().Where(a => task.Approvals.Contains(a.ApprovalUid)).ToList();
                    foreach (var approval in approvalsToRemove)
                    {
                        _approvals.DeleteUids(new[] { approval.ApprovalUid });
                    }
                }
            }

            var agents = new List<PedmAgent>();
            var agentsToLoad = task.FullRebuild
                ? _storage.Agents.GetAll()
                : task.Agents != null
                    ? _storage.Agents.GetAll().Where(a => task.Agents.Contains(a.AgentUid))
                    : _storage.Agents.GetAll();

            foreach (var agent in agentsToLoad)
            {
                try
                {
                    var pa = LoadAgent(agent);
                    if (pa != null)
                    {
                        agents.Add(pa);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Agent \"{agent.AgentUid}\" load error: {e.Message}");
                }
            }
            _agents.PutEntities(agents);

            var policies = new List<PedmPolicy>();
            var policiesToLoad = task.FullRebuild
                ? _storage.Policies.GetAll()
                : task.Policies != null
                    ? _storage.Policies.GetAll().Where(p => task.Policies.Contains(p.PolicyUid))
                    : _storage.Policies.GetAll();

            foreach (var policy in policiesToLoad)
            {
                try
                {
                    var pp = LoadPolicy(policy);
                    if (pp != null)
                    {
                        policies.Add(pp);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Policy \"{policy.PolicyUid}\" load error: {e.Message}");
                }
            }
            _policies.PutEntities(policies);

            var collections = new List<PedmCollection>();
            var collectionsToLoad = task.FullRebuild
                ? _storage.Collections.GetAll()
                : task.Collections != null
                    ? _storage.Collections.GetAll().Where(c => task.Collections.Contains(c.CollectionUid))
                    : _storage.Collections.GetAll();

            foreach (var collection in collectionsToLoad)
            {
                try
                {
                    var pc = LoadCollection(collection);
                    if (pc != null)
                    {
                        collections.Add(pc);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Collection \"{collection.CollectionUid}\" load error: {e.Message}");
                }
            }
            _collections.PutEntities(collections);

            var approvals = new List<PedmApproval>();
            var approvalsToLoad = task.FullRebuild
                ? _storage.Approvals.GetAll()
                : task.Approvals != null
                    ? _storage.Approvals.GetAll().Where(a => task.Approvals.Contains(a.ApprovalUid))
                    : _storage.Approvals.GetAll();

            foreach (var approval in approvalsToLoad)
            {
                try
                {
                    var pa = LoadApproval(approval);
                    if (pa != null)
                    {
                        approvals.Add(pa);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Approval \"{approval.ApprovalUid}\" load error: {e.Message}");
                }
            }
            _approvals.PutEntities(approvals);

            _deploymentAgents.Clear();
            var deploymentAgentLinks = new List<PedmDeploymentAgent>();
            foreach (var agent in _agents.GetAll())
            {
                if (!string.IsNullOrEmpty(agent.DeploymentUid))
                {
                    deploymentAgentLinks.Add(new PedmDeploymentAgent
                    {
                        DeploymentUid = agent.DeploymentUid,
                        AgentUid = agent.AgentUid
                    });
                }
            }
            _deploymentAgents.PutLinks(deploymentAgentLinks);
        }

        private PedmDeployment LoadDeployment(IPedmStorageDeployment storageDeployment, byte[] treeKey)
        {
            var deploymentKey = CryptoUtils.DecryptAesV2(storageDeployment.EncryptedKey, treeKey);
            var decryptedData = CryptoUtils.DecryptAesV2(storageDeployment.Data, deploymentKey);
            
            var data = PEDMProto.DeploymentData.Parser.ParseFrom(decryptedData);
            var name = data.Name;
            var dPrivateKey = data.EcPrivateKey?.ToByteArray();

            return new PedmDeployment
            {
                DeploymentUid = storageDeployment.DeploymentUid,
                Name = name,
                DeploymentKey = deploymentKey,
                Disabled = storageDeployment.Disabled,
                Created = storageDeployment.Created,
                Modified = storageDeployment.LastUpdated,
                PublicKey = storageDeployment.PublicKey,
                PrivateKey = dPrivateKey
            };
        }

        private PedmAgent LoadAgent(IPedmStorageAgent storageAgent)
        {
            return new PedmAgent
            {
                AgentUid = storageAgent.AgentUid,
                MachineId = storageAgent.MachineId,
                DeploymentUid = storageAgent.DeploymentUid,
                PublicKey = storageAgent.PublicKey,
                Disabled = storageAgent.Disabled,
                Created = storageAgent.Created,
                Modified = storageAgent.Modified
            };
        }

        private PedmPolicy LoadPolicy(IPedmStoragePolicy storagePolicy)
        {
            byte[] policyKey = null;
            if (storagePolicy.Key != null && storagePolicy.Key.Length > 0 && AgentKey != null)
            {
                try
                {
                    policyKey = CryptoUtils.DecryptAesV2(storagePolicy.Key, AgentKey);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Policy \"{storagePolicy.PolicyUid}\" key decryption error: {ex.Message}");
                    return null;
                }
            }

            byte[] policyData = null;
            if (storagePolicy.Data != null && storagePolicy.Data.Length > 0)
            {
                if (policyKey != null && policyKey.Length > 0)
                {
                    try
                    {
                        policyData = CryptoUtils.DecryptAesV2(storagePolicy.Data, policyKey);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Policy \"{storagePolicy.PolicyUid}\" data decryption error: {ex.Message}");
                        return null;
                    }
                }
                else
                {
                    Debug.WriteLine($"Policy \"{storagePolicy.PolicyUid}\" has no policy key, skipping");
                    return null;
                }
            }

            PolicyDataStructure parsedData = null;
            if (policyData != null && policyData.Length > 0)
            {
                try
                {
                    parsedData = JsonUtils.ParseJson<PolicyDataStructure>(policyData);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Policy \"{storagePolicy.PolicyUid}\" data parsing error: {ex.Message}");
                }
            }
            
            Dictionary<string, object> parsedAdminData = null;
            if (storagePolicy.AdminData != null && storagePolicy.AdminData.Length > 0)
            {
                try
                {
                    parsedAdminData = JsonUtils.ParseJson<Dictionary<string, object>>(storagePolicy.AdminData);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Policy \"{storagePolicy.PolicyUid}\" admin data parsing error: {ex.Message}");
                }
            }

            var newPolicy = new PedmPolicy
            {
                PolicyUid = storagePolicy.PolicyUid,
                PolicyKey = policyKey,
                PolicyData = policyData,
                Data = parsedData,
                AdminData = parsedAdminData,
                Disabled = storagePolicy.Disabled,
                Created = storagePolicy.Created,
                Updated = storagePolicy.Updated
            };
            return newPolicy;
        }

        private PedmCollection LoadCollection(IPedmStorageCollection storageCollection)
        {
            byte[] collectionData = null;
            if (storageCollection.Data != null && storageCollection.Data.Length > 0 && AgentKey != null)
            {
                try
                {
                    collectionData = CryptoUtils.DecryptAesV2(storageCollection.Data, AgentKey);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Collection \"{storageCollection.CollectionUid}\" data decryption error: {ex.Message}");
                }
            }

            return new PedmCollection
            {
                CollectionUid = storageCollection.CollectionUid,
                CollectionType = storageCollection.CollectionType,
                CollectionData = collectionData,
                Created = storageCollection.Created
            };
        }

        private PedmApproval LoadApproval(IPedmStorageApproval storageApproval)
        {
            return new PedmApproval
            {
                ApprovalUid = storageApproval.ApprovalUid,
                ApprovalType = storageApproval.ApprovalType,
                AgentUid = storageApproval.AgentUid,
                AccountInfo = storageApproval.AccountInfo,
                ApplicationInfo = storageApproval.ApplicationInfo,
                Justification = storageApproval.Justification,
                ExpireIn = storageApproval.ExpireIn,
                Created = storageApproval.Created
            };
        }

        public async Task<ModifyStatus> ModifyDeployments(
            IEnumerable<DeploymentDataInput> addDeployments = null,
            IEnumerable<DeploymentDataInput> updateDeployments = null,
            IEnumerable<string> removeDeployments = null)
        {
            var treeKey = _loader.TreeKey;
            if (treeKey == null)
            {
                throw new InvalidOperationException("Tree key is required");
            }

            var mrq = new PEDMProto.ModifyDeploymentRequest();

            if (addDeployments != null)
            {
                foreach (var ad in addDeployments)
                {
                    var deploymentUid = CryptoUtils.GenerateUid();
                    var deploymentKey = CryptoUtils.GenerateEncryptionKey();
                    CryptoUtils.GenerateEcKey(out var ecPrivateKey, out var ecPublicKey);
                    var ecPrivateKeyBytes = CryptoUtils.UnloadEcPrivateKey(ecPrivateKey);
                    var ecPublicKeyBytes = CryptoUtils.UnloadEcPublicKey(ecPublicKey);

                    var deploymentData = new PEDMProto.DeploymentData
                    {
                        Name = ad.Name,
                        EcPrivateKey = ByteString.CopyFrom(ecPrivateKeyBytes)
                    };
                    var deploymentDataBytes = deploymentData.ToByteArray();
                    var encryptedData = CryptoUtils.EncryptAesV2(deploymentDataBytes, deploymentKey);
                    var encryptedKey = CryptoUtils.EncryptAesV2(deploymentKey, treeKey);

                    var aRq = new PEDMProto.DeploymentCreateRequest
                    {
                        DeploymentUid = ByteString.CopyFrom(deploymentUid.Base64UrlDecode()),
                        AesKey = ByteString.CopyFrom(encryptedKey),
                        EcPublicKey = ByteString.CopyFrom(ecPublicKeyBytes),
                        EncryptedData = ByteString.CopyFrom(encryptedData)
                    };

                    if (!string.IsNullOrEmpty(ad.SpiffeCert))
                    {
                        // SpiffeCert is base64url encoded, decode it to bytes
                        var spiffeCertBytes = ad.SpiffeCert.Base64UrlDecode();
                        aRq.SpiffeCertificate = ByteString.CopyFrom(spiffeCertBytes);
                    }

                    var agentDataDict = new Dictionary<string, object>
                    {
                        ["deployment_uid"] = deploymentUid,
                        ["deployment_key"] = deploymentKey.Base64UrlEncode(),
                        ["enterprise_uid"] = _enterpriseUid,
                        ["device_uid"] = _deviceUid
                    };
                    var agentDataJson = JsonUtils.DumpJson(agentDataDict, indent: false);
                    var agentDataBytes = Encoding.UTF8.GetString(agentDataJson);
                    var agentDataEncrypted = CryptoUtils.EncryptEc(Encoding.UTF8.GetBytes(agentDataBytes), ecPublicKey);
                    aRq.AgentData = ByteString.CopyFrom(agentDataEncrypted);

                    mrq.AddDeployment.Add(aRq);
                }
            }

            if (updateDeployments != null)
            {
                foreach (var ud in updateDeployments)
                {
                    var deploymentUid = ud.DeploymentUid;
                    if (string.IsNullOrEmpty(deploymentUid))
                    {
                        throw new ArgumentException("DeploymentUid is required for update");
                    }
                    var sDep = _storage.Deployments.GetEntity(deploymentUid);
                    if (sDep == null)
                    {
                        throw new Exception($"Update Deployment: \"{deploymentUid}\" not found");
                    }

                    var dep = LoadDeployment(sDep, treeKey);
                    if (dep == null)
                    {
                        throw new Exception($"Update Deployment: \"{deploymentUid}\" could not be loaded");
                    }

                    var uRq = new PEDMProto.DeploymentUpdateRequest
                    {
                        DeploymentUid = ByteString.CopyFrom(deploymentUid.Base64UrlDecode())
                    };

                    if (ud.Disabled.HasValue)
                    {
                        uRq.Disabled = ud.Disabled.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;
                    }
                    else
                    {
                        uRq.Disabled = SetBooleanValue.BooleanNoChange;
                    }

                    if (!string.IsNullOrEmpty(ud.Name))
                    {
                        var data = new PEDMProto.DeploymentData
                        {
                            Name = ud.Name,
                            EcPrivateKey = ByteString.CopyFrom(dep.PrivateKey ?? Array.Empty<byte>())
                        };
                        var dataBytes = data.ToByteArray();
                        uRq.EncryptedData = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(dataBytes, dep.DeploymentKey));
                    }

                    if (!string.IsNullOrEmpty(ud.SpiffeCert))
                    {
                        var spiffeCertBytes = ud.SpiffeCert.Base64UrlDecode();
                        uRq.SpiffeCertificate = ByteString.CopyFrom(spiffeCertBytes);
                    }

                    mrq.UpdateDeployment.Add(uRq);
                }
            }

            if (removeDeployments != null)
            {
                foreach (var deploymentUid in removeDeployments)
                {
                    var sDep = _storage.Deployments.GetEntity(deploymentUid);
                    if (sDep == null)
                    {
                        throw new Exception($"Delete Deployment: \"{deploymentUid}\" not found");
                    }
                    mrq.RemoveDeployment.Add(ByteString.CopyFrom(deploymentUid.Base64UrlDecode()));
                }
            }

            var statusRs = await _auth.ExecuteRouter<PEDMProto.ModifyDeploymentRequest, PEDMProto.PedmStatusResponse>(
                "pedm/modify_deployment",
                mrq,
                typeof(PEDMProto.PedmStatusResponse));

            if (statusRs == null)
            {
                throw new Exception("Empty response from modify_deployment");
            }

            _needSync = true;
            return ModifyStatus.FromProto(statusRs);
        }

        public async Task<ModifyStatus> ModifyCollections(
            IEnumerable<CollectionData> addCollections = null,
            IEnumerable<CollectionData> updateCollections = null,
            IEnumerable<string> removeCollections = null)
        {
            if (!(_auth.Endpoint is KeeperEndpoint keeperEndpoint))
            {
                throw new InvalidOperationException("Endpoint must be KeeperEndpoint");
            }

            var sessionToken = _auth.AuthContext.SessionToken;
            var agentKey = AgentKey;
            if (agentKey == null)
            {
                throw new InvalidOperationException("Agent key is required");
            }

            var status = new ModifyStatus();

            var toAdd = new List<PEDMProto.CollectionValue>();
            var toUpdate = new List<PEDMProto.CollectionValue>();
            var toRemove = new List<ByteString>();

            if (addCollections != null)
            {
                foreach (var coll in addCollections)
                {
                    var cv = new PEDMProto.CollectionValue
                    {
                        CollectionUid = ByteString.CopyFrom(coll.CollectionUid.Base64UrlDecode()),
                        CollectionType = coll.CollectionType,
                        EncryptedData = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(
                            Encoding.UTF8.GetBytes(coll.CollectionDataJson ?? "{}"), agentKey))
                    };
                    toAdd.Add(cv);
                }
            }

            if (updateCollections != null)
            {
                foreach (var coll in updateCollections)
                {
                    var cv = new PEDMProto.CollectionValue
                    {
                        CollectionUid = ByteString.CopyFrom(coll.CollectionUid.Base64UrlDecode()),
                        CollectionType = coll.CollectionType,
                        EncryptedData = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(
                            Encoding.UTF8.GetBytes(coll.CollectionDataJson ?? "{}"), agentKey))
                    };
                    toUpdate.Add(cv);
                }
            }

            if (removeCollections != null)
            {
                foreach (var collectionUid in removeCollections)
                {
                    toRemove.Add(ByteString.CopyFrom(collectionUid.Base64UrlDecode()));
                }
            }

            while (toAdd.Count > 0 || toUpdate.Count > 0 || toRemove.Count > 0)
            {
                var crq = new PEDMProto.CollectionRequest();

                if (toAdd.Count > 0)
                {
                    var addChunk = toAdd.Take(500).ToList();
                    toAdd = toAdd.Skip(500).ToList();
                    crq.AddCollection.AddRange(addChunk);
                }

                if (toUpdate.Count > 0)
                {
                    var updateChunk = toUpdate.Take(500).ToList();
                    toUpdate = toUpdate.Skip(500).ToList();
                    crq.UpdateCollection.AddRange(updateChunk);
                }

                if (toRemove.Count > 0)
                {
                    var removeChunk = toRemove.Take(500).ToList();
                    toRemove = toRemove.Skip(500).ToList();
                    crq.RemoveCollection.AddRange(removeChunk);
                }

                var response = await _auth.ExecuteRouter<PEDMProto.CollectionRequest, PEDMProto.PedmStatusResponse>(
                    "pedm/modify_collection",
                    crq,
                    typeof(PEDMProto.PedmStatusResponse));
                if (response == null)
                {
                    throw new Exception("Empty response from modify_collection");
                }
                status.Merge(ModifyStatus.FromProto(response));
            }

            _needSync = true;
            return status;
        }

        public async Task<IEnumerable<CollectionLinkDataResult>> GetCollectionLinks(IEnumerable<CollectionLink> links)
        {
            throw new NotImplementedException("GetCollectionLinks is not yet implemented");
        }

        public async Task<ModifyStatus> SetCollectionLinks(
            IEnumerable<CollectionLink> setLinks = null,
            IEnumerable<CollectionLink> unsetLinks = null)
        {
            var clrq = new PEDMProto.SetCollectionLinkRequest();

            if (setLinks != null)
            {
                foreach (var coll in setLinks)
                {
                    var cln = new PEDMProto.CollectionLinkData
                    {
                        CollectionUid = ByteString.CopyFrom(coll.CollectionUid.Base64UrlDecode()),
                        LinkUid = ByteString.CopyFrom(coll.LinkUid.Base64UrlDecode()),
                        LinkType = coll.LinkType
                    };
                    clrq.AddCollection.Add(cln);
                }
            }

            if (unsetLinks != null)
            {
                foreach (var coll in unsetLinks)
                {
                    var cl = new PEDMProto.CollectionLink
                    {
                        CollectionUid = ByteString.CopyFrom(coll.CollectionUid.Base64UrlDecode()),
                        LinkUid = ByteString.CopyFrom(coll.LinkUid.Base64UrlDecode()),
                        LinkType = coll.LinkType
                    };
                    clrq.RemoveCollection.Add(cl);
                }
            }

            var statusRs = await _auth.ExecuteRouter<PEDMProto.SetCollectionLinkRequest, PEDMProto.PedmStatusResponse>(
                "pedm/set_collection_links",
                clrq,
                typeof(PEDMProto.PedmStatusResponse));

            if (statusRs == null)
            {
                throw new Exception("Empty response from set_collection_links");
            }

            _needSync = true;
            return ModifyStatus.FromProto(statusRs);
        }

        public async Task<ModifyStatus> ModifyAgents(
            IEnumerable<UpdateAgent> updateAgents = null,
            IEnumerable<string> removeAgents = null)
        {
            var rq = new PEDMProto.ModifyAgentRequest();

            if (updateAgents != null)
            {
                foreach (var ua in updateAgents)
                {
                    var existingAgent = _agents.GetEntity(ua.AgentUid);
                    if (existingAgent == null)
                    {
                        throw new Exception($"Update: Agent {ua.AgentUid} not found");
                    }

                    var au = new PEDMProto.AgentUpdate
                    {
                        AgentUid = ByteString.CopyFrom(ua.AgentUid.Base64UrlDecode())
                    };

                    if (!string.IsNullOrEmpty(ua.DeploymentUid))
                    {
                        au.DeploymentUid = ByteString.CopyFrom(ua.DeploymentUid.Base64UrlDecode());
                    }

                    if (ua.Disabled.HasValue)
                    {
                        au.Disabled = ua.Disabled.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;
                    }

                    rq.UpdateAgent.Add(au);
                }
            }

            if (removeAgents != null)
            {
                foreach (var agentUid in removeAgents)
                {
                    rq.RemoveAgent.Add(ByteString.CopyFrom(agentUid.Base64UrlDecode()));
                }
            }

            var statusRs = await _auth.ExecuteRouter<PEDMProto.ModifyAgentRequest, PEDMProto.PedmStatusResponse>(
                "pedm/modify_agent",
                rq,
                typeof(PEDMProto.PedmStatusResponse));

            if (statusRs == null)
            {
                throw new Exception("Empty response from modify_agent");
            }

            _needSync = true;
            return ModifyStatus.FromProto(statusRs);
        }

        public async Task<ModifyStatus> ModifyApprovals(
            IEnumerable<byte[]> toApprove = null,
            IEnumerable<byte[]> toDeny = null,
            IEnumerable<byte[]> toRemove = null)
        {
            var rq = new PEDMProto.ApprovalActionRequest();

            if (toApprove != null)
            {
                foreach (var approvalUid in toApprove)
                {
                    rq.Approve.Add(ByteString.CopyFrom(approvalUid));
                }
            }

            if (toDeny != null)
            {
                foreach (var approvalUid in toDeny)
                {
                    rq.Deny.Add(ByteString.CopyFrom(approvalUid));
                }
            }

            if (toRemove != null)
            {
                foreach (var approvalUid in toRemove)
                {
                    rq.Remove.Add(ByteString.CopyFrom(approvalUid));
                }
            }

            var statusRs = await _auth.ExecuteRouter<PEDMProto.ApprovalActionRequest, PEDMProto.PedmStatusResponse>(
                "pedm/approval_action",
                rq,
                typeof(PEDMProto.PedmStatusResponse));

            if (statusRs == null)
            {
                throw new Exception("Empty response from approval_action");
            }

            _needSync = true;
            return ModifyStatus.FromProto(statusRs);
        }
    }
}

