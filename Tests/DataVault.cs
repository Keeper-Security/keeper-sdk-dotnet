﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Xunit;
using VaultProto = Vault;
using RecordsProto = Records;
using System.Security.Cryptography;

namespace Tests
{
    public class TestWebSocket : FanOut<NotificationEvent>
    {
    }

    public class AuthMockParameters
    {
        public bool StopAtDeviceApproval { get; set; }
        public bool StopAtTwoFactor { get; set; }
        public bool StopAtPassword { get; set; }

        public void ResetStops()
        {
            StopAtDeviceApproval = false;
            StopAtTwoFactor = false;
            StopAtPassword = false;
        }

        protected Task<byte[]> MockExecuteRest(string endpoint, ApiRequestPayload payload, IAuth auth)
        {
            if (auth.Endpoint.Server != DataVault.DefaultEnvironment)
            {
                return Task.FromException<byte[]>(new KeeperRegionRedirect(DataVault.DefaultEnvironment));
            }

            byte[] response = null;
            switch (endpoint)
            {
                case "authentication/register_device":
                {
                    var device = new Device()
                    {
                        EncryptedDeviceToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(64)),
                    };
                    response = device.ToByteArray();
                }
                break;
                case "authentication/start_login":
                {
                    var lrs = new LoginResponse
                    {
                        EncryptedLoginToken = ByteString.CopyFrom(DataVault.EncryptedLoginToken),

                    };
                    if (StopAtDeviceApproval)
                    {
                        lrs.LoginState = LoginState.DeviceApprovalRequired;
                    }
                    else if (StopAtTwoFactor)
                    {
                        lrs.LoginState = LoginState.Requires2Fa;
                        lrs.Channels.Add(new TwoFactorChannelInfo
                        {
                            ChannelType = TwoFactorChannelType.TwoFaCtTotp,
                            ChannelUid = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                            ChannelName = "Mock",
                        });
                    }
                    else if (StopAtPassword)
                    {
                        lrs.LoginState = LoginState.RequiresAuthHash;
                        lrs.Salt.Add(new Salt
                        {
                            Iterations = DataVault.UserIterations,
                            Salt_ = ByteString.CopyFrom(DataVault.UserSalt),
                            Name = "Mock",
                            Uid = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                        });
                    }
                    else
                    {
                        lrs.LoginState = LoginState.LoggedIn;
                        lrs.AccountUid = ByteString.CopyFrom(DataVault.AccountUid);
                        lrs.PrimaryUsername = DataVault.UserName;
                        lrs.CloneCode = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8));
                        lrs.EncryptedSessionToken = ByteString.CopyFrom(DataVault.SessionToken);
                        var configuration = auth.Storage.Get();
                        var device = configuration.Devices.List.FirstOrDefault();
                        Assert.NotNull(device);
                        var devicePrivateKey = CryptoUtils.LoadEcPrivateKey(device.DeviceKey);
                        var devicePublicKey = CryptoUtils.GetEcPublicKey(devicePrivateKey);
                        lrs.EncryptedDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(DataVault.UserDataKey, devicePublicKey));
                        lrs.EncryptedDataKeyType = EncryptedDataKeyType.ByDevicePublicKey;
                    }

                    response = lrs.ToByteArray();
                }
                break;

                case "authentication/validate_auth_hash":
                {
                    var request = ValidateAuthHashRequest.Parser.ParseFrom(payload.Payload);
                    var expectedPassword = CryptoUtils.DeriveV1KeyHash(DataVault.UserPassword, DataVault.UserSalt, DataVault.UserIterations);
                    if (request.AuthResponse.SequenceEqual(expectedPassword))
                    {
                        var lrs = new LoginResponse
                        {
                            LoginState = LoginState.LoggedIn,
                            EncryptedLoginToken = ByteString.CopyFrom(DataVault.EncryptedLoginToken),
                            AccountUid = ByteString.CopyFrom(DataVault.AccountUid),
                            PrimaryUsername = DataVault.UserName,
                            CloneCode = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                            EncryptedSessionToken = ByteString.CopyFrom(DataVault.SessionToken),
                            EncryptedDataKey = ByteString.CopyFrom(DataVault.EncryptionParams),
                            EncryptedDataKeyType = EncryptedDataKeyType.ByPassword,
                        };
                        response = lrs.ToByteArray();
                    }
                    else
                    {
                        return Task.FromException<byte[]>(new KeeperAuthFailed("unit test"));
                    }

                }
                break;

                case "authentication/request_device_verification":
                    StopAtDeviceApproval = false;
                    response = new byte[0];
                    break;

                case "authentication/2fa_send_push":
                    if (StopAtDeviceApproval)
                    {
                        StopAtDeviceApproval = false;
                    }

                    response = new byte[0];
                    break;

                case "authentication/2fa_validate":
                    var tfvr = TwoFactorValidateRequest.Parser.ParseFrom(payload.Payload);
                    if (tfvr.Value == DataVault.TwoFactorOneTimeToken)
                    {
                        StopAtTwoFactor = false;
                        var tfars = new TwoFactorValidateResponse
                        {
                            EncryptedLoginToken = tfvr.EncryptedLoginToken
                        };
                        response = tfars.ToByteArray();
                    }
                    else
                    {
                        return Task.FromException<byte[]>(new KeeperAuthFailed("unit test"));
                    }

                    break;

                case "vault/execute_v2_command":
                    break;

                case "authentication/validate_device_verification_code":
                    var vdvcr = ValidateDeviceVerificationCodeRequest.Parser.ParseFrom(payload.Payload);
                    if (vdvcr.VerificationCode == DataVault.DeviceVerificationEmailCode)
                    {
                        StopAtDeviceApproval = false;
                        response = new byte[0];
                    }
                    else
                    {
                        return Task.FromException<byte[]>(new KeeperAuthFailed("unit test test"));
                    }

                    break;
                case "login/account_summary":
                {
                    response = auth.ProcessAccountSummary().ToByteArray();
                }
                break;
            }

            if (response != null)
            {
                return Task.FromResult(response);
            }

            return Task.FromException<byte[]>(new KeeperCanceled("not_implemented", $"\"{endpoint}\" is not implemented"));
        }
    }

    public static class DataVault
    {
        internal const string TestClientVersion = "c15.0.0";

        public const string DefaultEnvironment = "env.company.com";

        public static byte[] AccountUid = CryptoUtils.GetRandomBytes(16);
        public const string UserName = "some_fake_user@company.com";

        public static string UserPassword = CryptoUtils.GetRandomBytes(8).Base64UrlEncode();
        public static int UserIterations = 1000;
        public static byte[] UserSalt = CryptoUtils.GetRandomBytes(16);
        public static byte[] UserDataKey = CryptoUtils.GetRandomBytes(32);
        public static byte[] UserClientKey = CryptoUtils.GetRandomBytes(32);

        public static string UserPrivateKey = @"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpHQCOYFejfvWl
ia9LU0zydeVsC/mpRs9i5XopXAqM3dPxZfkrocMaXf7KUBsjTa8jMq576ANuOjXB
QanaqEA1zVXGWUtJaeQmbBu4ZRMRangA2O6ygyE+8TCdrVc92WtIx2wqiSNs/3Fu
C4929fHmgFqoCuusYSD7fpWLuaID+D9RPgMpyvKCUPhfHQf23kdq/5+vPapwSzKH
0ULR83Kif+694R0/Zpz6RrHy87kR5V8HM53D5Y9oG1Q7WHutJnrEo6brHU5qE1NQ
XLsKCbTfwm4zAcKFMrb0f0Q6Wps467NgDUQ3MvzyEQul76SXhGak1L3gEkOyyKQU
VuOiIBV/AgMBAAECggEAEH0pbrhqEyDv5qIUG24V1JY2NmC8iQrEccoaLSoyRSXj
4mek8eIl2c5MZ4GEA98xMmdgp+gpXXgDgcJbQ1ygVh6dPGe8dX4DptNnqIUCZPJS
nRKJw5IRjceKi/U4ymkGkuQO4d7ZO2l0r9wkst6sJWNic3wNGpOl2Z+wCR2idGx5
fKFGHA7rIXBXL1MRz384W6oYw6zLn9Ui2zqkbSxoklRCU64tPEfC092WiqMjyXfI
yIN9e8kXb96lv89ikqQBBnL9RYzm7g/+mdtR0ibJijocGaer6o7TsntvfI5IDNaG
SUEPtwyHW5xI7IX367TeYs5/Hb5Jeri0i5QvPdEdkQKBgQDRGP6KkIoQ/BA5FWIM
VhiTW3HMVJUpVf1D6jOXqL3eRNfHwYXu+RcvpJoRsoMDYQBG5zOvWCPKaW+BEDBu
xftsPKVIXoSyY9n4Rxw17gaheZ9uAwUOoaveNVSbARjCS17oS8/YdrYYPAi5cWFx
dbGBttDEYYRxLmeJ6LWZXSO/6wKBgQDPC/0EhiR4ELr+R6MPZXA3MLUmX3u+DYi3
ZRFNlQY8W9xeHUR3+LWK1fAnvAGPIF3AskwhaNlwBgoRP010GmzaWgBNs4evDjMU
SqMqv9f7FJVThu6eKmhjjR+GXprXmeBRnj3c4l79i1cQEdNUeiuW0hi66C7TMqTq
4ptT9u3vvQKBgBHz/m7xSBl7Ov1bu6ZpggSs9lFf9cqtymgZZMKhx2OdL5XEJPbG
xlnd3Sil1h/lJTvxP/vPKouHj/5Z4H6yWwsJDfvvuZ8DecSafm6W+FTG94xfkACY
mwQiOhhw+Ko+BHEXiUoBr1LXXLxnYsF2JH6JrtUdtlxtapBpvaXkXFxvAoGALP86
/te0Z0+jhA3Hl1oBWE1CoVNRDk3cr5bMeuLvVwDT1LRho/0uXzz9k3UdlaCAH5fg
ScaCswDtATCTwa7Yh1/V/w0MaPQaD8fkzC6jXtLrXRrPExq+UxxhhI9c8YxknvhY
E4AzCsFUq45kMlDW1lFUxJIfUxEHnHChN09MCLUCgYBeolR8MCO0tHTAWguVXQZY
Y45sqQ9kUJsV2/T8JjZ2TScqdKxhEKiCIU+31eFkbmRrAS11+qI0EPJ41Uu7oVpm
dGSJ3+1Sowp8JguM0OrfU4PU/C/K6HoezU+Evb6e3q31vskzLMqNar84+5M8fRAS
sveiIVtNpnh8NemUf/pKfA==
-----END PRIVATE KEY-----";

        public static string UserPublicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----";

        public static byte[] SessionToken = CryptoUtils.GetRandomBytes(64);
        public static byte[] DeviceId = CryptoUtils.GetRandomBytes(64);

        public static byte[] EncryptedLoginToken = CryptoUtils.GetRandomBytes(64);

        public static string DeviceVerificationEmailCode = "1234567890";

        public static string TwoFactorOneTimeToken = "123456";
        public static string TwoFactorDeviceToken = CryptoUtils.GetRandomBytes(32).Base64UrlEncode();

        public static RsaPrivateKey ImportedPrivateKey = LoadPrivateKey(UserPrivateKey);
        public static byte[] DerPrivateKey = CryptoUtils.UnloadRsaPrivateKey(ImportedPrivateKey);
        public static byte[] EncryptedPrivateKey = CryptoUtils.EncryptAesV1(DerPrivateKey, UserDataKey);

        public static RsaPublicKey ImportedPublicKey = LoadPublicKey(UserPublicKey);
        public static byte[] DerPublicKey = CryptoUtils.UnloadRsaPublicKey(ImportedPublicKey);
        public static string EncodedPublicKey = DerPublicKey.Base64UrlEncode();

        public static byte[] V2DerivedKey = CryptoUtils.DeriveKeyV2("data_key", UserPassword, UserSalt, UserIterations);
        public static string EncryptedDataKey = CryptoUtils.EncryptAesV2(UserDataKey, V2DerivedKey).Base64UrlEncode();

        public static byte[] EncryptionParams = CryptoUtils.CreateEncryptionParams(UserPassword, UserSalt, UserIterations, UserDataKey);

        public static long Revision = 100;

        private static RsaPublicKey LoadPublicKey(string publicKey)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKey);
            return rsa;
        }

        /*
        private static byte[] ExportPublicKey(RsaPublicKey publicKey)
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
        private static byte[] ExportPrivateKey(AsymmetricKeyParameter privateKey)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return privateKeyInfo.ParsePrivateKey().GetDerEncoded();
        }

        */
        private static RsaPrivateKey LoadPrivateKey(string privateKey)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKey);
            return rsa;
        }

        public static IConfigurationStorage GetConfigurationStorage()
        {
            IKeeperConfiguration configuration = new KeeperConfiguration();
            var serverConf = new ServerConfiguration(DefaultEnvironment)
            {
                ServerKeyId = 2
            };
            configuration.Servers.Put(serverConf);

            var userConf = new UserConfiguration(UserName)
            {
                //Password = UserPassword
            };
            configuration.Users.Put(userConf);
            configuration.LastServer = DefaultEnvironment;
            configuration.LastLogin = UserName;
            return new InMemoryConfigurationStorage(configuration);
        }

        internal static AccountSummaryElements ProcessAccountSummary(this IAuth auth)
        {
            var configuration = auth.Storage.Get();
            var device = configuration.Devices.List.FirstOrDefault();
            return new AccountSummaryElements
            {
                ClientKey = ByteString.CopyFrom(
                    CryptoUtils.EncryptAesV1(
                        CryptoUtils.GetRandomBytes(16),
                        DataVault.UserDataKey)),
                IsEnterpriseAdmin = false,
                KeysInfo = new KeysInfo
                {
                    EncryptionParams = ByteString.CopyFrom(DataVault.EncryptionParams),
                    EncryptedPrivateKey = ByteString.CopyFrom(DataVault.EncryptedPrivateKey),
                },
                Devices =
                {
                    new DeviceInfo
                    {
                        ClientVersion = DataVault.TestClientVersion,
                        DeviceName = "Test Device",
                        DeviceStatus = DeviceStatus.DeviceOk,
                        EncryptedDeviceToken = ByteString.CopyFrom(device.DeviceToken.Base64UrlDecode()),
                        DevicePublicKey = ByteString.CopyFrom(device.DeviceKey),
                    }
                },
                Settings = new Settings
                {

                },
                License = new AccountSummary.License
                {

                }
            };
        }
    }

    public class VaultEnvironment
    {
        public string User { get; } = DataVault.UserName;
        public byte[] AccountUid { get; } = DataVault.AccountUid;
        public string Password { get; } = DataVault.UserPassword;
        public int Iterations { get; } = DataVault.UserIterations;
        public byte[] Salt { get; } = DataVault.UserSalt;
        public byte[] DataKey { get; } = DataVault.UserDataKey;
        public RsaPublicKey PublicKey { get; } = DataVault.ImportedPublicKey;
        public string EncodedPublicKey { get; } = DataVault.EncodedPublicKey;
        public byte[] SessionToken { get; } = DataVault.SessionToken;
        public byte[] DeviceId { get; } = DataVault.DeviceId;
        public string OneTimeToken { get; } = DataVault.TwoFactorOneTimeToken;
        public string DeviceToken { get; } = DataVault.TwoFactorDeviceToken;
        public byte[] PrivateKeyData { get; } = DataVault.DerPrivateKey;
        public RsaPrivateKey PrivateRsaKey { get; } = DataVault.ImportedPrivateKey;
        public string EncryptedPrivateKey { get; } = DataVault.EncryptedPrivateKey.Base64UrlEncode();
        public string EncryptedDataKey { get; } = DataVault.EncryptedDataKey;
        public byte[] EncryptionParams { get; } = DataVault.EncryptionParams;
        public byte[] ClientKey { get; } = DataVault.UserClientKey;
        public long Revision { get; } = DataVault.Revision;
        public string TwoFactorOneTimeToken { get; } = DataVault.TwoFactorOneTimeToken;

        public VaultEnvironment()
        {
            var settings = new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            };
        }

        private Tuple<VaultProto.Record, VaultProto.RecordMetaData> GenerateRecord(KeeperRecord record,
            bool owner,
            long revision)
        {
            var sdr = new VaultProto.Record
            {
                RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                Revision = revision,
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Shared = record.Shared || !owner
            };
            if (record is PasswordRecord password)
            {
                sdr.Version = 2;
                var data = password.ExtractRecordData();
                sdr.Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(data), record.RecordKey));
                if (password.Attachments.Count > 0)
                {
                    var extra = password.ExtractRecordExtra();
                    sdr.Extra = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(extra), password.RecordKey));
                }
            }
            else if (record is TypedRecord typed)
            {
                sdr.Version = 3;
                var data = typed.ExtractRecordV3Data();
                sdr.Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(data), record.RecordKey));
            }

            VaultProto.RecordMetaData sdrmd = new VaultProto.RecordMetaData
            {
                RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                Owner = owner,
                CanShare = owner,
                CanEdit = owner,
                RecordKeyType = owner ? RecordsProto.RecordKeyType.EncryptedByDataKey : RecordsProto.RecordKeyType.EncryptedByPublicKey,
                RecordKey = ByteString.CopyFrom(owner ? CryptoUtils.EncryptAesV1(record.RecordKey, DataKey) : CryptoUtils.EncryptRsa(record.RecordKey, PublicKey))
            };

            return Tuple.Create(sdr, sdrmd);
        }

        private Tuple<VaultProto.SharedFolder, VaultProto.SharedFolderUser[], VaultProto.SharedFolderTeam[], VaultProto.SharedFolderRecord[]>
            GenerateSharedFolder(SharedFolder sharedFolder, long revision, IEnumerable<KeeperRecord> records, IEnumerable<Team> teams, bool hasKey)
        {
            var sf = new VaultProto.SharedFolder
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                Revision = revision,
                Name = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                DefaultManageRecords = true,
                DefaultManageUsers = true,
                DefaultCanEdit = true,
                DefaultCanReshare = true,
                CacheStatus = VaultProto.CacheStatus.Clear,
            };
            if (hasKey)
            {
                sf.KeyType = RecordsProto.RecordKeyType.EncryptedByDataKey;
                sf.SharedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(sharedFolder.SharedFolderKey, DataKey));
            }

            var userProto = new[]
            {
                new VaultProto.SharedFolderUser
                {
                    SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                    Username = User,
                    AccountUid = ByteString.CopyFrom(AccountUid),
                    ManageRecords = true,
                    ManageUsers = true,
                }
            };

            foreach (var record in records) 
            {
                record.Shared = true;
            }

            VaultProto.SharedFolderRecord[] recordProto =
                records?.Select(x =>
                {
                    x.Shared = true;
                    return new VaultProto.SharedFolderRecord
                    {
                        SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                        RecordUid = ByteString.CopyFrom(x.Uid.Base64UrlDecode()),
                        RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(x.RecordKey, sharedFolder.SharedFolderKey)),
                        Owner = true,
                        CanShare = false,
                        CanEdit = false,
                        Expiration = (DateTimeOffset.UtcNow + TimeSpan.FromDays(1)).ToUnixTimeMilliseconds(),
                    };
                }).ToArray() ?? [];
                

            VaultProto.SharedFolderTeam[] teamProto = teams?.Select(x => new VaultProto.SharedFolderTeam
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                TeamUid = ByteString.CopyFrom(x.TeamUid.Base64UrlDecode()),
                Name = x.Name,
                ManageRecords = true,
                ManageUsers = true,
            }).ToArray() ?? [];


            return Tuple.Create(sf, userProto, teamProto, recordProto);
        }

        private VaultProto.Team GenerateTeam(KeeperSecurity.Vault.Team team, bool ownsKey, IEnumerable<KeeperSecurity.Vault.SharedFolder> sharedFolders)
        {
            var encryptedTeamKey = ownsKey
                ? CryptoUtils.EncryptAesV1(team.TeamKey, DataKey)
                : CryptoUtils.EncryptRsa(team.TeamKey, PublicKey);
            var t = new VaultProto.Team
            {
                TeamUid = ByteString.CopyFrom(team.TeamUid.Base64UrlDecode()),
                Name = team.Name,
                TeamKeyType = ownsKey ? RecordsProto.RecordKeyType.EncryptedByDataKey : RecordsProto.RecordKeyType.EncryptedByPublicKey,
                TeamKey = ByteString.CopyFrom(encryptedTeamKey),
                TeamPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(PrivateKeyData, team.TeamKey)),
                RestrictEdit = team.RestrictEdit,
                RestrictShare = team.RestrictShare,
                RestrictView = team.RestrictView
            };

            if (sharedFolders != null)
            {
                var useTeamRsaKey = false;
                t.SharedFolderKeys.AddRange(sharedFolders.Select(x =>
                {
                    var key = new VaultProto.SharedFolderKey
                    {
                        SharedFolderUid = ByteString.CopyFrom(x.Uid.Base64UrlDecode()),
                        KeyType = useTeamRsaKey ? RecordsProto.RecordKeyType.EncryptedByPublicKey : RecordsProto.RecordKeyType.EncryptedByDataKey,
                        SharedFolderKey_ = ByteString.CopyFrom(useTeamRsaKey
                            ? CryptoUtils.EncryptRsa(x.SharedFolderKey, PublicKey)
                            : CryptoUtils.EncryptAesV1(x.SharedFolderKey, team.TeamKey)),
                    };
                    useTeamRsaKey = !useTeamRsaKey;
                    return key;
                }));
            }

            return t;
        }

        private VaultProto.UserFolder GenerateUserFolder(FolderNode folder, long revision)
        {
            var folderKey = CryptoUtils.GenerateEncryptionKey();
            var data = new FolderData { name = folder.Name };
            using (var stream = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(stream, Encoding.UTF8))
                {
                    var settings = new DataContractJsonSerializerSettings { UseSimpleDictionaryFormat = true };
                    var serializer = new DataContractJsonSerializer(typeof(FolderData), settings);
                    serializer.WriteObject(writer, data);
                }

                return new VaultProto.UserFolder
                {
                    FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                    KeyType = RecordsProto.RecordKeyType.EncryptedByDataKey,
                    Revision = revision,
                    UserFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(folderKey, DataKey)),
                    Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(stream.ToArray(), folderKey))
                };
            }
        }

        public static string SharedFolder1Uid = CryptoUtils.GenerateUid();
        public static string SharedFolder2Uid = CryptoUtils.GenerateUid();
        public VaultProto.SyncDownResponse GetSyncDownResponse()
        {
            var record1 = new PasswordRecord
            {
                Uid = CryptoUtils.GenerateUid(),
                RecordKey = CryptoUtils.GenerateEncryptionKey(),
                Title = "Record 1",
                Login = "some_fake_user1@company.com",
                Password = "password1",
                Link = "https://google.com",
                Notes = "note1"
            };
            record1.Custom.Add(new CustomField { Name = "name1", Value = "value1" });
            record1.Attachments.Add(new AttachmentFile
            {
                Id = "ABCDEFGH",
                Name = "Attachment 1",
                Key = CryptoUtils.GenerateEncryptionKey().Base64UrlEncode(),
                Size = 1000
            });

            var record2 = new PasswordRecord
            {
                Uid = CryptoUtils.GenerateUid(),
                RecordKey = CryptoUtils.GenerateEncryptionKey(),
                Title = "Record 2",
                Login = "some_fake_user2@company.com",
                Password = "password2",
                Link = "https://google.com",
                Notes = "note2"
            };
            var record3 = new PasswordRecord
            {
                Uid = CryptoUtils.GenerateUid(),
                RecordKey = CryptoUtils.GenerateEncryptionKey(),
                Title = "Record 3",
                Login = "some_fake_user3@company.com",
                Password = "password3",
                Link = "https://google.com",
            };

            var loginType = new TypedRecordFacade<LoginRecordType>();
            loginType.Fields.Login = "some_fake_user4@company.com";
            loginType.Fields.Password = "password4";
            loginType.Fields.Url = "https://google.com";
            var record4 = loginType.TypedRecord;
            record4.Uid = CryptoUtils.GenerateUid();
            record4.RecordKey = CryptoUtils.GenerateEncryptionKey();
            record4.Title = "Record 4";
            record4.Notes = "Note 4";

            var sharedFolder1 = new KeeperSecurity.Vault.SharedFolder
            {
                Uid = SharedFolder1Uid,
                SharedFolderKey = CryptoUtils.GenerateEncryptionKey(),
                DefaultManageRecords = false,
                DefaultManageUsers = false,
                DefaultCanEdit = false,
                DefaultCanShare = false,
                Name = "Shared Folder 1",
            };

            var sharedFolder2 = new KeeperSecurity.Vault.SharedFolder
            {
                Uid = SharedFolder2Uid,
                SharedFolderKey = CryptoUtils.GenerateEncryptionKey(),
                DefaultManageRecords = true,
                DefaultManageUsers = true,
                DefaultCanEdit = false,
                DefaultCanShare = false,
                Name = "Shared Folder 2",
            };

            var team1 = new KeeperSecurity.Vault.Team
            {
                TeamUid = CryptoUtils.GenerateUid(),
                TeamKey = CryptoUtils.GenerateEncryptionKey(),
                Name = "Team 1",
                RestrictEdit = true,
                RestrictShare = true,
                RestrictView = false,
            };

            var userFolder1 = new FolderNode
            {
                FolderUid = CryptoUtils.GenerateUid(),
                Name = "User Folder 1",
                FolderType = FolderType.UserFolder,
            };

            var (sf1, sfu1, sft1, sfr1) = GenerateSharedFolder(sharedFolder1, 12, new[] { record1 }, [team1], true);
            var (sf2, sfu2, sft2, sfr2) = GenerateSharedFolder(sharedFolder2, 12, new[] { record3 }, [team1], false);
            var t1 = GenerateTeam(team1, true, [sharedFolder1, sharedFolder2]);
            var uf1 = GenerateUserFolder(userFolder1, 14);
            var (r1, md1) = GenerateRecord(record1, true, 10);
            var (r2, md2) = GenerateRecord(record2, false, 11);
            var (r3, _) = GenerateRecord(record3, true, 12);
            var (r4, md4) = GenerateRecord(record4, true, 12);

            var sdr = new VaultProto.SyncDownResponse
            {
                HasMore = false,
                CacheStatus = VaultProto.CacheStatus.Clear,
                ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
            };
            sdr.Records.AddRange([r1, r2, r3, r4]);
            sdr.RecordMetaData.AddRange([md1, md2, md4]);
            sdr.SharedFolders.AddRange([sf1, sf2]);
            sdr.SharedFolderUsers.AddRange(sfu1);
            sdr.SharedFolderUsers.AddRange(sfu2);
            sdr.SharedFolderTeams.AddRange(sft1);
            sdr.SharedFolderTeams.AddRange(sft2);
            sdr.SharedFolderRecords.AddRange(sfr1);
            sdr.SharedFolderRecords.AddRange(sfr2);
            sdr.Teams.Add(t1);
            sdr.UserFolders.Add(uf1);
            sdr.UserFolderSharedFolders.Add(new VaultProto.UserFolderSharedFolder
            {
                SharedFolderUid = sf1.SharedFolderUid,
                Revision = sf1.Revision
            });
            sdr.UserFolderSharedFolders.Add(new VaultProto.UserFolderSharedFolder
            {
                SharedFolderUid = sf2.SharedFolderUid,
                Revision = sf2.Revision
            });
            sdr.UserFolderRecords.Add(new VaultProto.UserFolderRecord
            {
                RecordUid = r1.RecordUid,
            });
            sdr.UserFolderRecords.Add(new VaultProto.UserFolderRecord
            {
                RecordUid = r2.RecordUid,
                FolderUid = uf1.FolderUid,
            });
            sdr.UserFolderRecords.Add(new VaultProto.UserFolderRecord
            {
                RecordUid = r4.RecordUid,
            });

            return sdr;
        }
    }
}
