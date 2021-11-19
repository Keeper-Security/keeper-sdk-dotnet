using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace KeeperSecurity.Utils
{
    /// <summary>
    ///     Provides a set of encryption methods.
    /// </summary>
    public static class CryptoUtils
    {
        private const string CorruptedEncryptionParametersMessage = "Corrupted encryption parameters";

        private const int AesGcmNonceLength = 12;

        private static readonly SecureRandom RngCsp = new SecureRandom();

        internal static readonly ECDomainParameters EcParameters;

        static CryptoUtils()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            EcParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N);
        }

        /// <summary>
        ///     Generates secure random bytes.
        /// </summary>
        /// <param name="length">Length in bytes.</param>
        /// <returns>An array of random bytes.</returns>
        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            RngCsp.NextBytes(bytes);
            return bytes;
        }

        /// <summary>
        ///     Generate AES encryption key. Random 32 bytes.
        /// </summary>
        /// <returns>AES encryption key. 32 random bytes.</returns>
        public static byte[] GenerateEncryptionKey()
        {
            return GetRandomBytes(32);
        }

        /// <summary>
        ///     Generates UID. Random 16 bytes encoded to Base64 URL encoded.
        /// </summary>
        /// <returns>UID. 16 random bytes Base64 URL encoded.</returns>
        public static string GenerateUid()
        {
            return GetRandomBytes(16).Base64UrlEncode();
        }

        /// <summary>
        ///     Encodes byte array to string using Base64 URL encoding.
        /// </summary>
        /// <param name="data">Byte array.</param>
        /// <returns>Base64 URL encoded string.</returns>
        public static string Base64UrlEncode(this byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace("+", "-").Replace("/", "_");
        }

        /// <summary>
        ///     Decodes Base64 URL encoded string to byte array.
        /// </summary>
        /// <param name="text">Base64 URL encoded string.</param>
        /// <returns>Byte array.</returns>
        public static byte[] Base64UrlDecode(this string text)
        {
            if (text == null) return null;
            var base64 = text
                .Replace("-", "+")
                .Replace("_", "/")
                .Replace("=", "")
                .Replace("\r", "")
                .Replace("\n", "");
            base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            try
            {
                return Convert.FromBase64String(base64);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
                return new byte[] { };
            }
        }

        /// <summary>
        ///     Loads RSA public key.
        /// </summary>
        /// <param name="key">RSA public key DER encoded.</param>
        /// <returns>RSA Public Key</returns>
        public static RsaKeyParameters LoadPublicKey(byte[] key)
        {
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var publicKeyInfo = new SubjectPublicKeyInfo(algorithm, publicKeyStructure);

            return PublicKeyFactory.CreateKey(publicKeyInfo) as RsaKeyParameters;
        }

        /// <summary>
        ///     Loads RSA private key.
        /// </summary>
        /// <param name="key">RSA private key DER encoded.</param>
        /// <returns>RSA Private Key</returns>
        public static RsaPrivateCrtKeyParameters LoadPrivateKey(byte[] key)
        {
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var privateKeyInfo = new PrivateKeyInfo(algorithm, privateKeyStructure);

            return PrivateKeyFactory.CreateKey(privateKeyInfo) as RsaPrivateCrtKeyParameters;
        }

        /// <summary>
        ///     Encrypts data with AES CBC algorithm.
        /// </summary>
        /// <param name="data">plain data</param>
        /// <param name="key">AES encryption key.</param>
        /// <param name="iv">AES IV. Optional.</param>
        /// <returns>encrypted data</returns>
        /// <remarks>[IV: 16bytes][ENCRYPTED PADDED DATA]</remarks>
        public static byte[] EncryptAesV1(byte[] data, byte[] key, byte[] iv = null)
        {
            iv = iv ?? GetRandomBytes(16);
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);

            return iv.Concat(cipherText.Take(len)).ToArray();
        }

        /// <summary>
        ///     Decrypts data with AES CBC.
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="key">AES encryption key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptAesV1(byte[] data, byte[] key)
        {
            var iv = data.Take(16).ToArray();
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            cipher.Init(false, parameters);

            var decryptedData = new byte[cipher.GetOutputSize(data.Length - 16)];
            var len = cipher.ProcessBytes(data, 16, data.Length - 16, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);

            return decryptedData.Take(len).ToArray();
        }

        /// <exclude/>
        public static byte[] EncryptAesV2(byte[] data, byte[] key, byte[] nonce)
        {
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);

            return nonce.Concat(cipherText.Take(len)).ToArray();
        }

        /// <summary>
        ///     Encrypts data with AES GCM.
        /// </summary>
        /// <param name="data">Plain data.</param>
        /// <param name="key">AES encryption key.</param>
        /// <param name="nonceLength">Nonce length in bytes. Optional. Default 12</param>
        /// <returns>Encrypted data.</returns>
        /// <remarks>[NONCE: 12bytes][ENCRYPTED DATA][TAG: 16bytes]></remarks>
        public static byte[] EncryptAesV2(byte[] data, byte[] key, int nonceLength = AesGcmNonceLength)
        {
            return EncryptAesV2(data, key, GetRandomBytes(nonceLength));
        }

        /// <summary>
        ///     Decrypts with AES GCM.
        /// </summary>
        /// <param name="data">encrypted data</param>
        /// <param name="key">AES encryption key.</param>
        /// <param name="nonceLength">Nonce length. Optional. Default: 12 bytes.</param>
        /// <returns>Plain data.</returns>
        /// <exception cref="Exception">Cannot be decrypted.</exception>
        public static byte[] DecryptAesV2(byte[] data, byte[] key, int nonceLength = AesGcmNonceLength)
        {
            var nonce = data.Take(nonceLength).ToArray();
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, parameters);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - nonceLength)];

            var len = cipher.ProcessBytes(data, nonceLength, data.Length - nonceLength, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);

            return decryptedData.Take(len).ToArray();
        }

        /// <summary>
        ///     Encrypts data with RSA public key.
        /// </summary>
        /// <param name="data">Plain data</param>
        /// <param name="publicKey">RSA public key.</param>
        /// <returns>Encrypted data.</returns>
        /// <remarks>Uses PKCS1 padding.</remarks>
        public static byte[] EncryptRsa(byte[] data, RsaKeyParameters publicKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, publicKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        ///     Decrypts data with RSA private key
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="privateKey">RSA private key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptRsa(byte[] data, RsaPrivateCrtKeyParameters privateKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        ///     Derives encryption key from password.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="iterations">Iterations.</param>
        /// <returns>Encryption key.</returns>
        public static byte[] DeriveKeyV1(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            return ((KeyParameter) pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();
        }

        /// <summary>
        ///     Derives encryption key from password and gets HSA256 hash
        /// </summary>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="iterations">Iterations.</param>
        /// <returns></returns>
        public static byte[] DeriveV1KeyHash(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            var key = ((KeyParameter) pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();

            return SHA256.Create().ComputeHash(key);
        }

        /// <exclude />
        public static byte[] CreateAuthVerifier(string password, byte[] salt, int iterations)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian) Array.Reverse(iterationsBytes);

            var key = DeriveKeyV1(password, salt, iterations);
            return new[] {versionBytes.Take(1), iterationsBytes.Skip(1), salt, key}.SelectMany(x => x).ToArray();
        }

        /// <exclude />
        public static byte[] CreateEncryptionParams(string password, byte[] salt, int iterations, byte[] dataKey)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian) Array.Reverse(iterationsBytes);

            var key = DeriveKeyV1(password, salt, iterations);
            var iv = GetRandomBytes(16);
            var parameters = new ParametersWithIV(new KeyParameter(key), iv);

            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(true, parameters);
            var outBuffer = new byte[dataKey.Length * 2];
            var len = 0;
            while (len < outBuffer.Length)
            {
                var offset = len % dataKey.Length;
                len += cipher.ProcessBlock(dataKey, offset, outBuffer, len);
            }

            return new[] {versionBytes.Take(1), iterationsBytes.Skip(1), salt, iv, outBuffer}.SelectMany(x => x)
                .ToArray();
        }

        /// <exclude />
        public static byte[] DecryptEncryptionParams(string password, byte[] encryptionParams)
        {
            if (encryptionParams[0] != 1) throw new Exception(CorruptedEncryptionParametersMessage);

            if (encryptionParams.Length != 1 + 3 + 16 + 16 + 64) throw new Exception(CorruptedEncryptionParametersMessage);

            var iterations = (encryptionParams[1] << 16) + (encryptionParams[2] << 8) + encryptionParams[3];

            var salt = new byte[16];
            Array.Copy(encryptionParams, 4, salt, 0, 16);
            var key = DeriveKeyV1(password, salt, iterations);

            Array.Copy(encryptionParams, 20, salt, 0, 16);
            var parameters = new ParametersWithIV(new KeyParameter(key), salt);

            var cipher = new CbcBlockCipher(new AesEngine());
            cipher.Init(false, parameters);
            var len = 0;
            var outBuffer = new byte[64];
            while (len < 64) len += cipher.ProcessBlock(encryptionParams, len + 36, outBuffer, len);

            if (!outBuffer.Take(32).SequenceEqual(outBuffer.Skip(32))) throw new Exception(CorruptedEncryptionParametersMessage);

            return outBuffer.Take(32).Take(32).ToArray();
        }

        /// <summary>
        ///     Generates RSA key pair.
        /// </summary>
        /// <param name="privateKey"><c>out</c> Private key.</param>
        /// <param name="publicKey"><c>out</c> Public Key</param>
        public static void GenerateRsaKey(out byte[] privateKey, out byte[] publicKey)
        {
            var r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(RngCsp, 2048));
            var keys = r.GenerateKeyPair();

            var privateParams = (RsaPrivateCrtKeyParameters) keys.Private;
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateParams);
            privateKey = privateKeyInfo.ParsePrivateKey().GetDerEncoded();

            var publicParams = (RsaKeyParameters) keys.Public;
            var publicKeyInfo = new RsaPublicKeyStructure(publicParams.Modulus, publicParams.Exponent);
            publicKey = publicKeyInfo.GetDerEncoded();
        }

        /// <summary>
        ///     Derives encryption key from password.
        /// </summary>
        /// <param name="domain">Domain.</param>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="iterations">Iterations.</param>
        /// <returns>Encryption key.</returns>
        public static byte[] DeriveKeyV2(string domain, string password, byte[] salt, int iterations)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(domain + password);

            var pdb = new Pkcs5S2ParametersGenerator(new Sha512Digest());
            pdb.Init(passwordBytes, salt, iterations);
            var key = ((KeyParameter) pdb.GenerateDerivedMacParameters(64 * 8)).GetKey();

            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(domain));
        }

        /// <summary>
        /// Creates Auth hash for authorization with Biometrics
        /// </summary>
        /// <param name="biometricKey">Biometric key</param>
        /// <returns>Auth hash</returns>
        public static byte[] CreateBioAuthHash(byte[] biometricKey)
        {
            var hmac = new HMACSHA256(biometricKey);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes("biometric_auth"));
        }

        /// <summary>
        ///     Generate EC key pair.
        /// </summary>
        /// <param name="privateKey"><c>out</c> Private Key</param>
        /// <param name="publicKey"><c>out</c> Public Key.</param>
        public static void GenerateEcKey(out ECPrivateKeyParameters privateKey, out ECPublicKeyParameters publicKey)
        {
            var keyGeneratorParams = new ECKeyGenerationParameters(EcParameters, RngCsp);
            var keyGenerator = new ECKeyPairGenerator("ECDH");
            keyGenerator.Init(keyGeneratorParams);
            var keyPair = keyGenerator.GenerateKeyPair();
            privateKey = keyPair.Private as ECPrivateKeyParameters;
            publicKey = keyPair.Public as ECPublicKeyParameters;
        }

        /// <summary>
        ///     Serializes EC private key.
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>byte array representing EC private key.</returns>
        /// <remarks>32 bytes</remarks>
        public static byte[] UnloadEcPrivateKey(ECPrivateKeyParameters key)
        {
            var privateKey = key.D.ToByteArrayUnsigned();
            var len = privateKey.Length;
            if (len >= 32) return privateKey;
            var pk = new byte[32];
            Array.Clear(pk, 0, pk.Length);
            Array.Copy(privateKey, 0, pk, 32 - len, len);
            return pk;
        }

        /// <summary>
        ///     Serializes EC public key.
        /// </summary>
        /// <param name="key">Public key.</param>
        /// <returns>byte array representing EC public key.</returns>
        /// <remarks>Uncompressed. 65 bytes.</remarks>
        public static byte[] UnloadEcPublicKey(ECPublicKeyParameters key)
        {
            return key.Q.GetEncoded();
        }

        /// <summary>
        ///     Loads EC private key.
        /// </summary>
        /// <param name="key">private key bytes</param>
        /// <returns>EC private key.</returns>
        /// <exception cref="Exception">invalid key bytes</exception>
        public static ECPrivateKeyParameters LoadPrivateEcKey(byte[] key)
        {
            return new ECPrivateKeyParameters(new BigInteger(1, key), EcParameters);
        }

        /// <summary>
        ///     LoadV2 EC public key.
        /// </summary>
        /// <param name="key">public key bytes.</param>
        /// <returns>EC public key</returns>
        /// <exception cref="Exception">invalid key bytes</exception>
        public static ECPublicKeyParameters LoadPublicEcKey(byte[] key)
        {
            var point = new X9ECPoint(EcParameters.Curve, new DerOctetString(key)).Point;
            return new ECPublicKeyParameters(point, EcParameters);
        }

        /// <exclude />
        public static ECPublicKeyParameters GetPublicEcKey(ECPrivateKeyParameters privateKey)
        {
            return new ECPublicKeyParameters(privateKey.Parameters.G.Multiply(privateKey.D), privateKey.Parameters);
        }

        /// <summary>
        ///     Encrypts data with EC cryptography.
        /// </summary>
        /// <param name="data">Plain text</param>
        /// <param name="publicKey">Public key.</param>
        /// <returns>Encrypted data</returns>
        /// <remarks>[EPHEMERAL PUBLIC KEY][AES GCM ENCRYPTED DATA]</remarks>
        public static byte[] EncryptEc(byte[] data, ECPublicKeyParameters publicKey)
        {
            GenerateEcKey(out var ePrivateKey, out var ePublicKey);
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(ePrivateKey);
            var key = agreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
            key = SHA256.Create().ComputeHash(key);
            var encryptedData = EncryptAesV2(data, key);
            return UnloadEcPublicKey(ePublicKey).Concat(encryptedData).ToArray();
        }

        /// <summary>
        ///     Decrypts data wit EC cryptography.
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="privateKey">Private key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptEc(byte[] data, ECPrivateKeyParameters privateKey)
        {
            var ePublicKey = LoadPublicEcKey(data.Take(65).ToArray());
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(privateKey);
            var key = agreement.CalculateAgreement(ePublicKey).ToByteArrayUnsigned();
            key = SHA256.Create().ComputeHash(key);
            return DecryptAesV2(data.Skip(65).ToArray(), key);
        }

        internal static byte[] Base32ToBytes(string base32)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new List<byte>();
            var bytes = base32.ToCharArray();
            for (var bitIndex = 0; bitIndex < base32.Length * 5; bitIndex += 8)
            {
                var dualByte = alphabet.IndexOf(bytes[bitIndex / 5]) << 10;
                if (bitIndex / 5 + 1 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 1]) << 5;
                if (bitIndex / 5 + 2 < bytes.Length)
                    dualByte |= alphabet.IndexOf(bytes[bitIndex / 5 + 2]);

                dualByte = 0xff & (dualByte >> (15 - bitIndex % 5 - 8));
                output.Add((byte) dualByte);
            }

            return output.ToArray();
        }

        /// <summary>
        /// Gets TOTP code for URL
        /// </summary>
        /// <param name="url">TOTP URL</param>
        /// <returns>
        /// A tuple containing three values:
        /// <list type="number">
        /// <item><description>TOTP code</description></item>
        /// <item><description>Seconds passed</description></item>
        /// <item><description>TOTP Period in seconds</description></item>
        /// </list>
        /// </returns>
        public static Tuple<string, int, int> GetTotpCode(string url)
        {
            var uri = new Uri(url);
            if (uri.Scheme != "otpauth") return null;

            string secret = null;
            var algorithm = "SHA1";
            var digits = 6;
            var period = 30;
            var coll = HttpUtility.ParseQueryString(uri.Query);
            foreach (var key in coll.AllKeys)
                switch (key)
                {
                    case "secret":
                        secret = coll[key];
                        break;
                    case "algorithm":
                        algorithm = coll[key];
                        break;
                    case "digits":
                        int.TryParse(coll[key], out digits);
                        break;
                    case "period":
                        int.TryParse(coll[key], out period);
                        break;
                }

            if (string.IsNullOrEmpty(secret)) return null;

            var tmBase = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
            var tm = tmBase / period;
            var msg = BitConverter.GetBytes(tm);
            if (BitConverter.IsLittleEndian) Array.Reverse(msg);

            var secretBytes = Base32ToBytes(secret.ToUpperInvariant());

            HMAC hmac = null;
            switch (algorithm)
            {
                case "SHA1":
                    hmac = new HMACSHA1(secretBytes);
                    break;
                case "SHA256":
                    hmac = new HMACSHA256(secretBytes);
                    break;
                case "MD5":
                    hmac = new HMACMD5(secretBytes);
                    break;
            }

            if (hmac == null) return null;

            var digest = hmac.ComputeHash(msg);
            var offset = digest[digest.Length - 1] & 0x0f;
            var codeBytes = new byte[4];
            Array.Copy(digest, offset, codeBytes, 0, codeBytes.Length);
            codeBytes[0] &= 0x7f;
            if (BitConverter.IsLittleEndian) Array.Reverse(codeBytes);

            var codeInt = BitConverter.ToInt32(codeBytes, 0);
            codeInt %= Enumerable.Repeat(10, digits).Aggregate(1, (a, b) => a * b);
            var codeStr = codeInt.ToString();
            while (codeStr.Length < digits) codeStr = "0" + codeStr;

            return Tuple.Create(codeStr, (int) (tmBase % period), period);
        }
    }

    /// <exclude />
    public class EncryptTransform : ICryptoTransform
    {
        private readonly IBufferedCipher _cypher;
        private byte[] _tail;

        public EncryptTransform(IBufferedCipher cypher, byte[] key, int ivSize = 0)
        {
            _cypher = cypher;

            var iv = CryptoUtils.GetRandomBytes(ivSize > 0 ? ivSize : _cypher.GetBlockSize());
            _cypher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            _tail = iv;
            EncryptedBytes = 0;
        }

        public long EncryptedBytes { get; private set; }
        public int InputBlockSize => _cypher.GetBlockSize();

        public int OutputBlockSize => _cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer,
            int inputOffset,
            int inputCount,
            byte[] outputBuffer,
            int outputOffset)
        {
            EncryptedBytes += inputCount;
            var encrypted = _cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            if (_tail.Length > 0)
            {
                if (_tail.Length <= outputBuffer.Length - (outputOffset + encrypted))
                {
                    Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + _tail.Length, encrypted);
                    Array.Copy(_tail, 0, outputBuffer, outputOffset, _tail.Length);
                    encrypted += _tail.Length;
                    _tail = new byte[0];
                }
                else
                {
                    if (_tail.Length <= encrypted)
                    {
                        var newTail = new byte[_tail.Length];
                        Array.Copy(outputBuffer, outputOffset + encrypted - _tail.Length, newTail, 0, _tail.Length);
                        Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + _tail.Length, encrypted - newTail.Length);
                        Array.Copy(_tail, 0, outputBuffer, outputOffset, _tail.Length);
                        _tail = newTail;
                    }
                    else
                    {
                        var newTail = new byte[_tail.Length + encrypted];
                        Array.Copy(_tail, 0, newTail, 0, _tail.Length);
                        Array.Copy(outputBuffer, outputOffset, newTail, _tail.Length, encrypted);
                        _tail = newTail;
                        encrypted = 0;
                    }
                }
            }

            return encrypted;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            EncryptedBytes += inputCount;
            var final = _cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            var result = new byte[_tail.Length + final.Length];
            Array.Copy(_tail, 0, result, 0, _tail.Length);
            Array.Copy(final, 0, result, _tail.Length, final.Length);
            return result;
        }
    }

    /// <exclude />
    public class DecryptTransform : ICryptoTransform
    {
        private readonly IBufferedCipher _cypher;
        public readonly byte[] Key;
        private bool _initialized;

        public DecryptTransform(IBufferedCipher cypher, byte[] key, int ivSize)
        {
            _cypher = cypher;
            Key = key;
            _ivSize = ivSize > 0 ? ivSize : _cypher.GetBlockSize();
            _initialized = false;
            DecryptedBytes = 0;
        }

        public long DecryptedBytes { get; private set; }
        public int InputBlockSize => _cypher.GetBlockSize();

        public int OutputBlockSize => _cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        protected readonly int _ivSize;

        public void Dispose()
        {
        }

        private void EnsureInitialized(byte[] inputBuffer, ref int inputOffset, ref int inputCount)
        {
            if (!_initialized)
            {
                var iv = new byte[_ivSize];
                Array.Copy(inputBuffer, inputOffset, iv, 0, iv.Length);
                inputOffset += iv.Length;
                inputCount -= iv.Length;
                _cypher.Init(false, new ParametersWithIV(new KeyParameter(Key), iv));
                _initialized = true;
            }
        }

        public int TransformBlock(byte[] inputBuffer,
            int inputOffset,
            int inputCount,
            byte[] outputBuffer,
            int outputOffset)
        {
            EnsureInitialized(inputBuffer, ref inputOffset, ref inputCount);

            var res = _cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            DecryptedBytes += res;
            return res;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            EnsureInitialized(inputBuffer, ref inputOffset, ref inputCount);

            var res = _cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            DecryptedBytes += res.LongLength;
            return res;
        }
    }

    /// <exclude />
    public class EncryptAesV1Transform : EncryptTransform
    {
        public EncryptAesV1Transform(byte[] key) : base(
            new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
            key, 0)
        {
        }
    }

    /// <exclude />
    public class DecryptAesV1Transform : DecryptTransform
    {
        public DecryptAesV1Transform(byte[] key) : base(
            new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()),
            key, 0)
        {
        }
    }


    /// <exclude />
    public class EncryptAesV2Transform : EncryptTransform
    {
        public EncryptAesV2Transform(byte[] key) : base(
            new BufferedAeadBlockCipher(new GcmBlockCipher(new AesEngine())), key, 12)
        {
        }
    }

    /// <exclude />
    public class DecryptAesV2Transform : DecryptTransform
    {
        public DecryptAesV2Transform(byte[] key) : base(
            new BufferedAeadBlockCipher(new GcmBlockCipher(new AesEngine())), key, 12)
        {
        }
    }
}
