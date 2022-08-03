using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Xunit;

namespace Tests
{
    [DataContract]
    public class JsonList
    {
        [DataMember(Name = "servers")]
        public readonly IList<string> Servers = new List<string>(); 
    }

    public class CryptoTest
    {
        private const string FieldPattern = "^(\\w+)(\\.[^\\[]+)?(\\[*.\\])?\\s*=\\s*(.*)$";
        [Fact]
        public void TestPattern()
        {
            var rx = new Regex(FieldPattern);
            var m = rx.Match("text.fdfsd fff = sfsd dsf f sf sdf");
            Assert.True(m.Success);
        }

        private PasswordGenerationOptions RestoreRules(string password)
        {
            var options = new PasswordGenerationOptions();
            if (!string.IsNullOrEmpty(password))
            {
                options.Length = password.Length;
                foreach (var ch in password)
                {
                    if (char.IsDigit(ch))
                    {
                        options.Digit += 1;
                    }
                    else if (char.IsLetter(ch))
                    {
                        if (char.IsLower(ch))
                        {
                            options.Lower += 1;
                        }
                        else
                        {
                            options.Upper += 1;
                        }
                    }
                    else
                    {
                        options.Special += 1;
                    }
                }
            }
            return options;
        }

        [Fact]
        public void TestGeneratePassword() 
        {
            var password = CryptoUtils.GeneratePassword();
            var rules = RestoreRules(password);
            Assert.Equal(20, rules.Length);
            Assert.True(rules.Upper >= 4);
            Assert.True(rules.Lower >= 4);
            Assert.True(rules.Digit >= 2);
            Assert.True(rules.Special == 0);
            var options = new PasswordGenerationOptions();
            options.Length = 32;
            options.Upper = 10;
            options.Lower = 10;
            options.Digit = 10;
            options.Special = 2;
            password = CryptoUtils.GeneratePassword(options);
            rules = RestoreRules(password);
            Assert.Equal(options.Length, rules.Length);
            Assert.True(rules.Upper >= options.Upper);
            Assert.True(rules.Lower >= options.Lower);
            Assert.True(rules.Digit >= options.Digit);
            Assert.True(rules.Special >= options.Special);

            options.Length = 120;
            options.Upper = 99;
            options.Lower = 99;
            options.Digit = 99;
            options.Special = 99;
            password = CryptoUtils.GeneratePassword(options);
            rules = RestoreRules(password);
            Assert.Equal(options.Length, rules.Length);
            var counts = (new int[] { rules.Lower, rules.Upper, rules.Digit, rules.Special }).OrderBy(x => x).ToArray();
            Assert.True(counts.Last() - counts.First() < 4);

            options.Length = 1;
            options.Upper = 0;
            options.Lower = 99;
            options.Digit = 99;
            options.Special = 0;
            password = CryptoUtils.GeneratePassword(options);
            rules = RestoreRules(password);
            Assert.Equal(options.Length, rules.Length);
            Assert.True(rules.Lower + rules.Digit == 1);

            options.Length = 10;
            options.Upper = 5;
            options.Lower = 5;
            options.Digit = -1;
            options.Special = -1;
            password = CryptoUtils.GeneratePassword(options);
            rules = RestoreRules(password);
            Assert.Equal(options.Length, rules.Length);
            Assert.True(rules.Lower == 5);
            Assert.True(rules.Upper == 5);

            options.Length = 5000;
            options.Upper = 0;
            options.Lower = 20;
            options.Digit = -1;
            options.Special = -1;
            password = CryptoUtils.GeneratePassword(options);
            rules = RestoreRules(password);
            Assert.Equal(options.Length, rules.Length);
            Assert.True(rules.Lower >= 20);
        }

        [Fact]
        public async Task TestEncryptTransform()
        {
            var key = CryptoUtils.GenerateEncryptionKey();
            var encryptTransformV2 = new EncryptAesV2Transform(key);
            var decryptTransformV2 = new DecryptAesV2Transform(key);
            var data = new byte[999];
            for (var i = 0; i < data.Length; i++)
            {
                data[i] = (byte) (i & 0xff);
            }

            byte[] outputData;
            using (var output = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(new MemoryStream(data), encryptTransformV2, CryptoStreamMode.Read))
                {
                    await cryptoStream.CopyToAsync(output);
                }

                outputData = output.ToArray();
            }
            Assert.Equal(outputData.Length, data.Length + 12 + 16);

            byte[] dataBack;
            using (var back = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(new MemoryStream(outputData), decryptTransformV2, CryptoStreamMode.Read))
                {
                    await cryptoStream.CopyToAsync(back);
                }

                dataBack = back.ToArray();
            }
            Assert.Equal(dataBack.Length, data.Length);
            for (int i = 0; i < data.Length; i++) {
                Assert.Equal(data[i], dataBack[i]);
            }
        }

        [Fact]
        public void TestECDHAgreement()
        {

            var privKey = "HIIeyuuRkVGvhtax8mlX7fangaC6DKa2R8VAg5AAtBY";
            var pubKey ="BBbdHwhMWW6gTtUU1Qy6ICgFOMOMTJK5agJhPSWcsXBzh3WNprrZMTDzDcLmj3yfmJFVVeEdiccdPdBe1C1r6Ng";

            var privateKey = CryptoUtils.LoadPrivateEcKey(privKey.Base64UrlDecode());
            var publicKey = CryptoUtils.LoadPublicEcKey(pubKey.Base64UrlDecode());

            var aggr = AgreementUtilities.GetBasicAgreement("ECDHC");
            aggr.Init(privateKey);

            var expectedSecret = new BigInteger(1, "LWyhYOlzZqzFxnYxtw815CIdLtfaB2oDh9hAybvfX-M".Base64UrlDecode());
            var secret = aggr.CalculateAgreement(publicKey);
            Assert.Equal(expectedSecret, secret);

            var recordUid = "1xRhhNDGkK-Mj4NLh6LNZg".Base64UrlDecode();

            var expectedKey = "TPKrsCKfsnmktwahlihr22EqRA1c_BcZn8FA3M_1HDc".Base64UrlDecode();
            var key = SHA256.Create().ComputeHash(secret.ToByteArrayUnsigned().Concat(recordUid).ToArray());
            Assert.Equal(expectedKey, key);
        }

        [Fact]
        public void TestDecryptAesV1()
        {
            var data = "KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP".Base64UrlDecode();
            var key = "pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y".Base64UrlDecode();
            data = CryptoUtils.DecryptAesV1(data, key);
            Assert.Equal(data, "6lf4FGVyhDRnRhJ91TrahjIW8lTqGA".Base64UrlDecode());
        }

        [Fact]
        public void TestEncryptAesV1()
        {
            var iv = "KvsOJmE4JNK1HwKSpkBeRw".Base64UrlDecode();
            var block = "6lf4FGVyhDRnRhJ91TrahjIW8lTqGA".Base64UrlDecode();
            var key = "pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y".Base64UrlDecode();
            var enc = CryptoUtils.EncryptAesV1(block, key, iv);
            var encoded = enc.Base64UrlEncode();
            Assert.Equal("KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP", encoded);
        }

        [Fact]
        public void TestEncryptAesV2()
        {
            var key = "c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik".Base64UrlDecode();
            var data = ("nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxuy" +
                        "dFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilCbMhIzE").Base64UrlDecode();
            var nonce = "Nt9_Y37C_43eRCRQ".Base64UrlDecode();
            var encData = CryptoUtils.EncryptAesV2(data, key, nonce);
            var expectedData = ("Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB" +
                                "CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8To" +
                                "zb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw").Base64UrlDecode();
            Assert.Equal(encData, expectedData);

            var decData = CryptoUtils.DecryptAesV2(encData, key);
            Assert.Equal(decData, data);
        }

        [Fact]
        public void TestKeyDerivationV1()
        {
            var password = "q2rXmNBFeLwAEX55hVVTfg";
            var salt = "Ozv5_XSBgw-XSrDosp8Y1A".Base64UrlDecode();
            var expectedKey = "nu911pKhOIeX_lToXa4uIUuMPg1pj_3ZGpGmd7OjvRs".Base64UrlDecode();

            var key = CryptoUtils.DeriveV1KeyHash(password, salt, 1000);
            Assert.Equal(expectedKey, key);
        }

        [Fact]
        public void TestKeyDerivationV2()
        {
            var password = "q2rXmNBFeLwAEX55hVVTfg";
            var domain = "1oZZl0fKjU4";
            var salt = "Ozv5_XSBgw-XSrDosp8Y1A".Base64UrlDecode();
            var expectedKey = "rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g".Base64UrlDecode();

            var key = CryptoUtils.DeriveKeyV2(domain, password, salt, 1000);
            Assert.Equal(expectedKey, key);
        }

        [Fact]
        public void TestLocalRsa()
        {
            var data = CryptoUtils.GetRandomBytes(100);
            var publicKey = CryptoUtils.LoadPublicKey(TestPublicKey.Base64UrlDecode());
            var encData = CryptoUtils.EncryptRsa(data, publicKey);
            var privateKey = CryptoUtils.LoadPrivateKey(TestPrivateKey.Base64UrlDecode());
            var unencData = CryptoUtils.DecryptRsa(encData, privateKey);

            Assert.Equal(data, unencData);
        }

        private const string TestPublicKey = @"MIIBCgKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HD
Gl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANjusoMh
PvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4DKcry
glD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOdw-WP
aBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1ENzL8
8hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQAB";

        private const string TestPrivateKey = @"MIIEogIBAAKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5
K6HDGl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANju
soMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4D
KcryglD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOd
w-WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1E
NzL88hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQABAoIBABB9KW64ahMg7-ai
FBtuFdSWNjZgvIkKxHHKGi0qMkUl4-JnpPHiJdnOTGeBhAPfMTJnYKfoKV14A4HC
W0NcoFYenTxnvHV-A6bTZ6iFAmTyUp0SicOSEY3Hiov1OMppBpLkDuHe2TtpdK_c
JLLerCVjYnN8DRqTpdmfsAkdonRseXyhRhwO6yFwVy9TEc9_OFuqGMOsy5_VIts6
pG0saJJUQlOuLTxHwtPdloqjI8l3yMiDfXvJF2_epb_PYpKkAQZy_UWM5u4P_pnb
UdImyYo6HBmnq-qO07J7b3yOSAzWhklBD7cMh1ucSOyF9-u03mLOfx2-SXq4tIuU
Lz3RHZECgYEA0Rj-ipCKEPwQORViDFYYk1txzFSVKVX9Q-ozl6i93kTXx8GF7vkX
L6SaEbKDA2EARuczr1gjymlvgRAwbsX7bDylSF6EsmPZ-EccNe4GoXmfbgMFDqGr
3jVUmwEYwkte6EvP2Ha2GDwIuXFhcXWxgbbQxGGEcS5niei1mV0jv-sCgYEAzwv9
BIYkeBC6_kejD2VwNzC1Jl97vg2It2URTZUGPFvcXh1Ed_i1itXwJ7wBjyBdwLJM
IWjZcAYKET9NdBps2loATbOHrw4zFEqjKr_X-xSVU4bunipoY40fhl6a15ngUZ49
3OJe_YtXEBHTVHorltIYuugu0zKk6uKbU_bt770CgYAR8_5u8UgZezr9W7umaYIE
rPZRX_XKrcpoGWTCocdjnS-VxCT2xsZZ3d0opdYf5SU78T_7zyqLh4_-WeB-slsL
CQ3777mfA3nEmn5ulvhUxveMX5AAmJsEIjoYcPiqPgRxF4lKAa9S11y8Z2LBdiR-
ia7VHbZcbWqQab2l5FxcbwKBgCz_Ov7XtGdPo4QNx5daAVhNQqFTUQ5N3K-WzHri
71cA09S0YaP9Ll88_ZN1HZWggB-X4EnGgrMA7QEwk8Gu2Idf1f8NDGj0Gg_H5Mwu
o17S610azxMavlMcYYSPXPGMZJ74WBOAMwrBVKuOZDJQ1tZRVMSSH1MRB5xwoTdP
TAi1AoGAXqJUfDAjtLR0wFoLlV0GWGOObKkPZFCbFdv0_CY2dk0nKnSsYRCogiFP
t9XhZG5kawEtdfqiNBDyeNVLu6FaZnRkid_tUqMKfCYLjNDq31OD1Pwvyuh6Hs1P
hL2-nt6t9b7JMyzKjWq_OPuTPH0QErL3oiFbTaZ4fDXplH_6Snw";
    }
}