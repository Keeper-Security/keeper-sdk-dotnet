using System.Runtime.Serialization;

namespace KeeperSecurity.Authentication
{
    /// <exclude/>
    [DataContract]
    public class WebAuthnExtension
    {
        [DataMember(Name = "appid")]
        public string appid;
        [DataMember(Name = "uvm")]
        public bool uvm;
        [DataMember(Name = "loc")]
        public string loc;
        [DataMember(Name = "txAuthSimple")]
        public string txAuthSimple;
    }

    /// <exclude/>
    [DataContract]
    public class AllowCredential
    {
        [DataMember(Name = "type")]
        public string type;
        [DataMember(Name = "id")]
        public string id;
    }

    /// <exclude/>
    [DataContract]
    public class PublicKeyCredentialRequestOptions
    {
        [DataMember(Name = "challenge")]
        public string challenge;
        [DataMember(Name = "rpId")]
        public string rpId;
        [DataMember(Name = "allowCredentials")]
        public AllowCredential[] allowCredentials;
        [DataMember(Name = "userVerification")]
        public string userVerification;
        [DataMember(Name = "extensions")]
        public WebAuthnExtension extensions;
    }


    /// <exclude/>
    [DataContract]
    public class KeeperWebAuthnRequest
    {
        [DataMember(Name = "publicKeyCredentialRequestOptions")]
        public PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
        [DataMember(Name = "username")]
        public string username;
    }

    /// <exclude/>
    [DataContract]
    public class SecurityKeyClientData
    {
        public const string MAKE_CREDENTIAL = "webauthn.create";
        public const string GET_ASSERTION = "webauthn.get";

        public const string U2F_REGISTER = "navigator.id.finishEnrollment";
        public const string U2F_SIGN = "navigator.id.getAssertion";

        [DataMember(Name = "type", Order = 1)]
        public string dataType;
        [DataMember(Name = "challenge", Order = 2)]
        public string challenge;
        [DataMember(Name = "origin", Order = 3)]
        public string origin;
    }

    [DataContract]
    public class SignatureResponse
    {
        [DataMember(Name = "authenticatorData", Order = 1)]
        public string authenticatorData;
        [DataMember(Name = "clientDataJSON", Order = 2)]
        public string clientDataJSON;
        [DataMember(Name = "signature", Order = 3)]
        public string signature;
    }

    [DataContract]
    public class ClientExtensionResults
    {
    }

    /// <exclude/>
    [DataContract]
    public class KeeperWebAuthnSignature
    {
        [DataMember(Name = "id", Order = 1)]
        public string id;
        [DataMember(Name = "rawId", Order = 2)]
        public string rawId;
        [DataMember(Name = "response", Order = 3)]
        public SignatureResponse response;
        [DataMember(Name = "type", Order = 4)]
        public string type;
        [DataMember(Name = "clientExtensionResults", Order = 5)]
        public ClientExtensionResults clientExtensionResults;
    }

    /// <exclude/>
    public class WebAuthnSignature
    {
        public byte[] clientData;
        public byte[] authenticatorData;
        public byte[] signatureData;
        public byte[] credentialId;
    }
}
