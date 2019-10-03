using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Threading.Tasks;
using KeeperSecurity.Sdk.UI;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace KeeperSecurity.Sdk
{
    public static class DataVault
    {
        public static string UserName = "unit.test@keepersecurity.com";

        public static string UserPassword = CryptoUtils.GetRandomBytes(8).Base64UrlEncode();
        public static int UserIterations = 1000;
        public static byte[] UserSalt = CryptoUtils.GetRandomBytes(16);
        public static byte[] UserDataKey = CryptoUtils.GetRandomBytes(32);
        public static byte[] UserClientKey = CryptoUtils.GetRandomBytes(32);

        public static string UserPrivateKey =
$@"-----BEGIN RSA PRIVATE KEY----- 
Proc-Type: 4,ENCRYPTED 
DEK-Info: AES-128-CBC,7359ABCB9854B5CB781E4910662C5EF1

u1i/Mj22bT6AegV38qTsz0mK/QFbGpveS9dq4GXkYVA5JjqowcVsl1HUq2mIhDmW
wYRhkqGWD6IJkt++mDIpv74VKYYuzxTVvt4V46LS/mXn9xqO8g8Cy1qxWznRBPZe
a6/qziQpSI1R4PltIcD1gQHPIJiHINOi4Zi1GT6FTRzZwQ+08rOFfRchvP/rG8hX
KgLywsk9p44exMNJBJhOVTs6UeC4zGdMxNN++Qa+3o+6G8FVgyR4KNGqcFVoYGe6
L5K5KoJz4LwhUy3NDL9TSftxqvXsbiFtUw4BSEYjdyDYQz/ytpFkyGJIzn7vutx+
XbEIMRi6RR2qObI9TdiA5w7sOthvCiGbpzqlH6b++pIRNYiUPe+Ec8SeEbkM8wZB
IFx6xCpDKZQPyCnHngwYIw/iCXqO5UyJjDCnDHOVpMi/BbMJsKp7U+qcrUmN9gUr
VMFRlUZpps5Im3wu3gebZ6Fu41JYK2LqcgEOnh0EbeeZIvH3+uv/QIHdJPYSbsMU
Ns2KJQc+n4PsZa7kZf/CGAq926Y302o9SV2pX1GAcwoHJWkfukZhpt3ikJSrnHVD
FAIZbA0xt4XdbDMVg5T6Er+q1IO1zrZeQ/NLsRR+/JLz3+DvtIKrVMTLtGbl/VV4
rROt9l6YnF2F8CMaMz68v+19vzo1zEob/WD/8Ye3YQq66meJ/+NjwyTmMrZxsO/l
FHeDgDs1r2Nc1uC2/n1UiiZyFTaBzkj/5QUnpBm33V/P63+pN6cw0qEvjNEwdIOC
d5Ohky1d1ayhSeVHkx1ZYcSTriicgWcWTOV+zckJ+VAqvSCZV4A+NMqZGVzPhMgC
h9GWvIXfMDhXIDzBsQz2W3zseJFSzL4av8b/AxTDapOeS9M8FzsbEDJC7YfiLVWK
6bFOLr2dg5Lm41iyWmp7NK2+IUFN15DgMIbHcpfD24F+cs73hjE3E56rsb8dBifG
Q1izqwFiopK+1z9C/EWBmmY3AcyqjXEQl3DWnL2IbYnhmm/SN040BGVZKJcUBUlk
b7RPQF+uZWlM8EWLTqCZQUfl3bogxOcFryyElBPDVRq4Z/x4di2FuUbmI/Mbs1g7
PiBWKIC8CHk3sLezXgMn1thkKsRI3xN+jZcGTZ6lhTVKUAbbW8mqRzBtyjPHbjUC
9PRSeJRDc10ZYnyWhLXa2lSgY12obXNuxLi8eKg6VuBnVzh4CvjOmJY3NlA5xsUi
YLl49YLLQqBU2IwrgqYm+7n2D8PmnhwPUPj2shNoIi9gtAhx8n0pyypgzd8iTtQZ
3IxO1zaNjJOal4er299DcoBsZ5cZ7EU6ltwtUCNqGyaVWwSqjAKtiPGpjT/eEAeL
KLzX+F5r+dUUsy5m8ds+6TUWDxLaqT8PcugnUxT8f3JokODv7JHSiogB1ETeczKS
RJfJH63edAQLxl+rayIqsTuUntmMNgE3olQWexCChX9b8xW6OzVgw8jU6WX0OGOB
5qkDxT9de8CpseIymuDX8AYIpPxIHJdigTBBfYp34hPAKuBpAwDPNS1FiOZYYZSB
84VHEOeXkUpBgAGQwphDZITltMDnssSGPbCX9EHM5+mNVkmQw+SDJbcgXm0jNVtC
-----END RSA PRIVATE KEY-----";

        public static string PrivateKeyPassword = "E,{-qhsm;<cq]3D(3H5K/";
        public static string UserPublicKey =
$@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----";

        public static string SessionToken = CryptoUtils.GetRandomBytes(64).Base64UrlEncode();
        public static byte[] DeviceId = CryptoUtils.GetRandomBytes(64);

        public static string TwoFactorOneTimeToken = "123456";
        public static string TwoFactorDeviceToken = CryptoUtils.GetRandomBytes(32).Base64UrlEncode();

        public static RsaPrivateCrtKeyParameters ImportedPrivateKey = LoadPrivateKey(UserPrivateKey, PrivateKeyPassword);
        public static byte[] DerPrivateKey = ExportPrivateKey(ImportedPrivateKey);
        public static byte[] EncryptedPrivateKey = CryptoUtils.EncryptAesV1(DerPrivateKey, UserDataKey);

        public static RsaKeyParameters ImportedPublicKey = LoadPublicKey(UserPublicKey);
        public static byte[] DerPublicKey = ExportPublicKey(ImportedPublicKey);
        public static string EncodedPublicKey = DerPublicKey.Base64UrlEncode();

        public static byte[] V2DerivedKey = CryptoUtils.DeriveKeyV2("data_key", UserPassword, UserSalt, UserIterations);
        public static string EncryptedDataKey = CryptoUtils.EncryptAesV2(UserDataKey, V2DerivedKey).Base64UrlEncode();

        public static string EncryptionParams = CryptoUtils.CreateEncryptionParams(UserPassword, UserSalt, UserIterations, UserDataKey).Base64UrlEncode();

        public static long Revision = 100;

        private static RsaKeyParameters LoadPublicKey(string publicKey)
        {
            PemReader pemReader = new PemReader(new StringReader(publicKey));
            RsaKeyParameters key = (RsaKeyParameters)pemReader.ReadObject();
            return key;
        }
        private static byte[] ExportPublicKey(RsaKeyParameters publicKey)
        {
            var publicKeyInfo = new RsaPublicKeyStructure(publicKey.Modulus, publicKey.Exponent);
            return publicKeyInfo.GetDerEncoded();
        }

        public class PasswordFinder : IPasswordFinder
        {
            private readonly char[] _password;
            public PasswordFinder(string password)
            {
                _password = password.ToCharArray();
            }
            public char[] GetPassword()
            {
                return _password;
            }
        }
        private static RsaPrivateCrtKeyParameters LoadPrivateKey(string privateKey, string password)
        {
            PemReader pemReader = new PemReader(new StringReader(privateKey), new PasswordFinder(password));
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            return (RsaPrivateCrtKeyParameters)keyPair.Private;
        }

        private static byte[] ExportPrivateKey(RsaPrivateCrtKeyParameters privateKey)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return privateKeyInfo.GetDerEncoded();
        }

        public static IConfigurationStorage GetConfigurationStorage()
        {
            var serverConf = new ServerConfiguration
            {
                Server = "test.keepersecurity.com",
                DeviceId = DeviceId,
                ServerKeyId = 1
            };
            var userConf = new UserConfiguration
            {
                Username = UserName,
                Password = UserPassword
            };
            var config = new Configuration
            {
                LastServer = serverConf.Server,
                LastLogin = userConf.Username
            };
            config.MergeUserConfiguration(userConf);
            config.MergeServerConfiguration(serverConf);

            return new InMemoryConfigurationStorage(config);
        }

    }

    public class VaultEnvironment
    {
        public string User { get; } = DataVault.UserName;
        public string Password { get; } = DataVault.UserPassword;
        public int Iterations { get; } = DataVault.UserIterations;
        public byte[] Salt { get; } = DataVault.UserSalt;
        public byte[] DataKey { get; } = DataVault.UserDataKey;
        public RsaKeyParameters PublicKey { get; } = DataVault.ImportedPublicKey;
        public string EncodedPublicKey { get; } = DataVault.EncodedPublicKey;
        public string SessionToken { get; } = DataVault.SessionToken;
        public byte[] DeviceId { get; } = DataVault.DeviceId;
        public string OneTimeToken { get; } = DataVault.TwoFactorOneTimeToken;
        public string DeviceToken { get; } = DataVault.TwoFactorDeviceToken;
        public byte[] PrivateKeyData { get; } = DataVault.DerPrivateKey;
        public string EncryptedPrivateKey { get; } = DataVault.EncryptedPrivateKey.Base64UrlEncode();
        public string EncryptedDataKey { get; } = DataVault.EncryptedDataKey;
        public string EncryptionParams { get; } = DataVault.EncryptionParams;
        public byte[] ClientKey { get; } = DataVault.UserClientKey;
        public long Revision { get; } = DataVault.Revision;
        public string TwoFactorOneTimeToken { get; } = DataVault.TwoFactorOneTimeToken;


        private readonly DataContractJsonSerializer _dataSerializer;
        private readonly DataContractJsonSerializer _extraSerializer;
        public VaultEnvironment() {
            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };
            _dataSerializer = new DataContractJsonSerializer(typeof(RecordData), settings);
            _extraSerializer = new DataContractJsonSerializer(typeof(RecordExtra), settings);

        }

        internal  SyncDownResponse GetSyncDownResponse()
        {
            var rs = new SyncDownResponse
            {
                result = "success",
                fullSync = true,
                revision = DataVault.Revision,

            };

            return rs;
        }

        private Tuple<SyncDownRecord, SyncDownRecordMetaData> GenerateRecord(PasswordRecord record, KeyType keyType)
        {
            var recordUid = CryptoUtils.GenerateUid();
            var recordKey = CryptoUtils.GenerateEncryptionKey();
            var sdr = new SyncDownRecord
            {
                RecordUid = recordUid,
                Version = 2,
                Revision = Revision,
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Shared = keyType == KeyType.DataKey
            };
            var data = record.ExtractRecordData();
            using (var ms = new MemoryStream())
            {
                _dataSerializer.WriteObject(ms, data);
                sdr.Data = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
            }

            if (record.Attachments.Count > 0) {
                var extra = record.ExtractRecordExtra();
                using (var ms = new MemoryStream())
                {
                    _extraSerializer.WriteObject(ms, extra);
                    sdr.Extra = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
                }
            }

            var sdrmd = new SyncDownRecordMetaData {
                RecordUid = recordUid,
                Owner = keyType == KeyType.DataKey,
                CanShare = keyType == KeyType.DataKey,
                CanEdit = keyType == KeyType.DataKey,
                RecordKeyType = (int)keyType
            };
            if (keyType == KeyType.DataKey)
            {
                sdrmd.RecordKey = CryptoUtils.EncryptAesV1(recordKey, DataKey).Base64UrlEncode();
            }
            else
            {
                sdrmd.RecordKey = CryptoUtils.EncryptRsa(recordKey, PublicKey).Base64UrlEncode();
            }
            return new Tuple<SyncDownRecord, SyncDownRecordMetaData>(sdr, sdrmd);
        }
    }
}
