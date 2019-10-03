using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Xunit;

namespace KeeperSecurity.Sdk
{
    public class CryptoTest
    {
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
        public void TestAesGcmEncryption()
        {
            var key = "c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik".Base64UrlDecode();
            var nonce = "Nt9_Y37C_43eRCRQ".Base64UrlDecode();
            var data = ("nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxu" +
                "ydFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilC" +
                "bMhIzE").Base64UrlDecode();

            var expectedResult = ("Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB" +
                "CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8To" +
                "zb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw").Base64UrlDecode();

            var result = CryptoUtils.EncryptAesV2(data, key, nonce);
            Assert.Equal(expectedResult, result);

            var originalData = CryptoUtils.DecryptAesV2(expectedResult, key);
            Assert.Equal(originalData, data);
        }

        class PasswordFinder : IPasswordFinder
        {
            public char[] GetPassword()
            {
                return PivateKeyPassword.ToCharArray();
            }
        }

        [Fact]
        public void TestLocalRsa()
        {
            AsymmetricCipherKeyPair keyPair;
            using (var ms = new StringReader(PrivateKey))
            {
                keyPair = new PemReader(ms, new PasswordFinder()).ReadObject() as AsymmetricCipherKeyPair;
            }

            RsaPrivateCrtKeyParameters privateKey = keyPair.Private as RsaPrivateCrtKeyParameters;

            RsaKeyParameters publicKey = null;
            using (var ms = new StringReader(PublicKey))
            {
                publicKey = new PemReader(ms).ReadObject() as RsaKeyParameters;
            }

            var data = CryptoUtils.GetRandomBytes(100);
            var encData = CryptoUtils.EncryptRsa(data, publicKey);
            var unencData = CryptoUtils.DecryptRsa(encData, privateKey);

            Assert.Equal(data, unencData);
        }

        [Fact]
        public void TestOtherRsa()
        {
            RsaPrivateCrtKeyParameters privateKey = null;
            using (var ms = new StringReader(PrivateKey))
            {
                var keyPair = new PemReader(ms, new PasswordFinder()).ReadObject() as AsymmetricCipherKeyPair;
                privateKey = keyPair.Private as RsaPrivateCrtKeyParameters;
            }

            string dataString = "fDxt4nJLZPrRSMozaD1Vkt1QNS5bdAoEGmXv1mbE3DWo5HWJ13RBPuRQr7gqiZ542BLN_R8n8lmJrZ5RIVnvgB93y7SSuD9BxpP55RZ6twAl0vXBeVpPn9CTAgTHy8kM_U4h_g";
            string pythonEncrypted = @"KuUMs5JNMfhDlhPJ0izU10w3QgemQvJ7jhIPlcI-XYOmqfDlLW7bTK4uMUmyKTsVucnQoEpQlJTruZL
dKu1s8aBHLeNLQxGTbDFgmKFpsS-Iz3DZwcPu55CPgg1DzJDn-GVZWGGRXD5BYZZCbJ3NAfFRG4C6c9
PGLubDoGKOpjGUFQlO3a-FzBiUE6cy8xA5TAsF-1MhvjdwCaB_Ie-zyuJTeIg-mQcSueDu2WbWxrwY5
geMNO7C56NsBniDTrNlnAwXbM5uIyRO8kW8efwBCFhJegQIRozbfmKEXaqC5QdFHV_0uQCga6_u9LiJ
Ag0CMu0wA6jYL4mxnnLpwBo7bg";

            var data = CryptoUtils.Base64UrlDecode(dataString);
            var unencData = CryptoUtils.DecryptRsa(CryptoUtils.Base64UrlDecode(pythonEncrypted), privateKey);

            Assert.Equal(data, unencData);
        }

        const string PivateKeyPassword = "E,{-qhsm;<cq]3D(3H5K/";

        const string PrivateKey = 
@"-----BEGIN RSA PRIVATE KEY-----
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

        const string PublicKey = 
@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----";

    }
}