using System;
using System.Collections.Generic;
using Google.Protobuf;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;

namespace KeeperSecurity.Plugins.PEDM
{
    public class PedmUpdatePolicy
    {
        public string PolicyUid { get; set; }
        public Dictionary<string, object> AdminData { get; set; }
        public bool? Disabled { get; set; }
        public Dictionary<string, object> Data { get; set; }
    }

    public class AddDeployment
    {
        public string Name { get; set; }
        public byte[] SpiffeCert { get; set; }
        public DeploymentAgentInformation AgentInfo { get; set; }
    }

    public class UpdateDeployment
    {
        public string DeploymentUid { get; set; }
        public string Name { get; set; }
        public bool? Disabled { get; set; }
        public byte[] SpiffeCert { get; set; }
    }

    public class CollectionLinkData
    {
        public CollectionLink CollectionLink { get; set; }
        public byte[] LinkData { get; set; }
    }

    public interface IPedmStatus
    {
        bool Success { get; }
        string Message { get; }
    }

    public class EntityStatus : IPedmStatus
    {
        public string EntityUid { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
    }

    public class LinkStatus : IPedmStatus
    {
        public string SubjectUid { get; set; }
        public string ObjectUid { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
    }

    public class DeploymentAgentInformation
    {
        public Dictionary<string, object> Data { get; set; }
    }

    public static class PedmStatusParser
    {
        public static IPedmStatus ParsePedmStatus(PEDMProto.PedmStatus status)
        {
            if (status.Key.Count == 1)
            {
                return new EntityStatus
                {
                    EntityUid = status.Key[0].ToByteArray().Base64UrlEncode(),
                    Success = status.Success,
                    Message = status.Message
                };
            }
            
            if (status.Key.Count == 2)
            {
                return new LinkStatus
                {
                    SubjectUid = status.Key[0].ToByteArray().Base64UrlEncode(),
                    ObjectUid = status.Key[1].ToByteArray().Base64UrlEncode(),
                    Success = status.Success,
                    Message = status.Message
                };
            }
            
            return null;
        }
    }
}
