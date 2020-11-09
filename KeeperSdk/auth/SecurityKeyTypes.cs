using System.Runtime.Serialization;

namespace KeeperSecurity.Authentication
{
    /// <exclude/>
    [DataContract]
    public class SecurityKeyAuthenticateRequest
    {
        [DataMember(Name = "version")]
        public string version;

        [DataMember(Name = "appId")]
        public string appId;

        [DataMember(Name = "challenge")]
        public string challenge;

        [DataMember(Name = "keyHandle")]
        public string keyHandle;
    }

    /// <exclude/>
    [DataContract]
    public class SecurityKeyRequest
    {
        [DataMember(Name = "authenticateRequests")]
        public SecurityKeyAuthenticateRequest[] authenticateRequests;
    }

    /// <exclude/>
    [DataContract]
    public class SecurityKeyClientData
    {
        public const string U2F_REGISTER = "navigator.id.finishEnrollment";
        public const string U2F_SIGN = "navigator.id.getAssertion";

        [DataMember(Name = "typ", Order = 1)]
        public string dataType;
        [DataMember(Name = "challenge", Order = 2)]
        public string challenge;
        [DataMember(Name = "origin", Order = 3)]
        public string origin;
    }

    /// <exclude/>
    public class SecurityKeySignature
    {
        [DataMember(Name = "clientData", Order = 1)]
        public string clientData;
        [DataMember(Name = "signatureData", Order = 2)]
        public string signatureData;
        [DataMember(Name = "keyHandle", Order = 3)]
        public string keyHandle;
    }

    /// <exclude/>
    public class U2FSignature
    {
        public byte[] clientData;
        public byte[] signatureData;
        public byte[] keyHandle;
    }
}
