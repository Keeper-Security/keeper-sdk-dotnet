using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Buffers;


#if !HAS_BOUNCYCASTLE
using System.Formats.Asn1;
#else
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
#endif

namespace KeeperSecurity.Utils
{
    /// <summary>
    ///     Provides a set of encryption methods.
    /// </summary>
    public static class CryptoUtils
    {
        private const string CorruptedEncryptionParametersMessage = "Corrupted encryption parameters";
        private const int AesGcmNonceSize = 12;
        private const int AesGcmTagSize = 16;

#if !HAS_BOUNCYCASTLE
        private static readonly RandomNumberGenerator SecureRandom = RandomNumberGenerator.Create();
#else
        private static readonly SecureRandom SecureRandom = new();
        internal static readonly ECDomainParameters EcParameters;
        static CryptoUtils()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            EcParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N);
        }
#endif

        /// <summary>
        ///     Generates secure random bytes.
        /// </summary>
        /// <param name="length">Length in bytes.</param>
        /// <returns>An array of random bytes.</returns>
        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
#if !HAS_BOUNCYCASTLE
            SecureRandom.GetBytes(bytes);
#else
            SecureRandom.NextBytes(bytes);
#endif
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
            var uid = GetRandomBytes(16);
            if ((uid[0] & 0xf8) == 0xf8)
            {
                uid[0] = (byte) (uid[0] & 0x7f);
            }

            return uid.Base64UrlEncode();
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
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        ///     Unloads RSA public key.
        /// </summary>
        /// <param name="publicKey">RSA public key</param>
        /// <returns>RSA Public Key DER encoded</returns>
        public static byte[] UnloadRsaPublicKey(RsaPublicKey publicKey)
        {
#if !HAS_BOUNCYCASTLE
            var parameters = publicKey.ExportParameters(false);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteInteger(parameters.Modulus);
            writer.WriteInteger(parameters.Exponent);
            writer.PopSequence();
            return writer.Encode();
#else
            var publicKeyInfo = new RsaPublicKeyStructure(publicKey.Modulus, publicKey.Exponent);
            return publicKeyInfo.GetDerEncoded();
#endif 
        }

        /// <summary>
        ///     Loads RSA public key.
        /// </summary>
        /// <param name="key">RSA public key DER encoded</param>
        /// <returns>RSA Public Key</returns>
        public static RsaPublicKey LoadRsaPublicKey(byte[] key)
        {
#if !HAS_BOUNCYCASTLE
            var reader = new AsnReader(key, AsnEncodingRules.DER);
            reader = reader.ReadSequence();
            var modulus = reader.ReadIntegerBytes().ToUnsignedBigInteger(256).ToArray();
            var exponent = reader.ReadIntegerBytes().ToArray();
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent
            });
            return rsa;
#else
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var publicKeyInfo = new SubjectPublicKeyInfo(algorithm, publicKeyStructure);

            return PublicKeyFactory.CreateKey(publicKeyInfo) as RsaKeyParameters;
#endif 
        }

        /// <summary>
        ///     Unloads RSA private key.
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <returns>RSA Private Key DER encoded</returns>
        public static byte[] UnloadRsaPrivateKey(RsaPrivateKey privateKey)
        {
#if !HAS_BOUNCYCASTLE
            var data = privateKey.ExportPkcs8PrivateKey();
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            reader = reader.ReadSequence();
            _ = reader.ReadInteger();
            _ = reader.ReadSequence();
            var pk = reader.ReadOctetString();
            return pk;
#else
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return privateKeyInfo.ParsePrivateKey().GetDerEncoded();
#endif
        }

        private static ReadOnlyMemory<byte> ToUnsignedBigInteger(this ReadOnlyMemory<byte> bigInteger, int expectedLength)
        {
            var l = bigInteger.Length;

            if (l == expectedLength) 
            {
                return bigInteger;
            }
            if (l == expectedLength + 1 && bigInteger.Span[0] == 0) { 
                return bigInteger.Slice(1, expectedLength);
            }
            if (l < expectedLength) 
            {
                return Enumerable.Repeat<byte>(0, expectedLength - l).Concat(bigInteger.ToArray()).ToArray();
            }

            return bigInteger;
        }

        /// <summary>
        ///     Loads RSA private key.
        /// </summary>
        /// <param name="key">RSA private key DER encoded.</param>
        /// <returns>RSA Private Key</returns>
        public static RsaPrivateKey LoadRsaPrivateKey(byte[] key)
        {
#if !HAS_BOUNCYCASTLE
            var reader = new AsnReader(key, AsnEncodingRules.DER);
            reader = reader.ReadSequence();
            _ = reader.ReadInteger();
            var modulus = reader.ReadIntegerBytes().ToUnsignedBigInteger(256).ToArray();
            var publicExponent = reader.ReadIntegerBytes().ToArray();
            var privateExponent = reader.ReadIntegerBytes().ToUnsignedBigInteger(256).ToArray();

            var prime1 = reader.ReadIntegerBytes().ToUnsignedBigInteger(128).ToArray();
            var prime2 = reader.ReadIntegerBytes().ToUnsignedBigInteger(128).ToArray();
            var exponent1 = reader.ReadIntegerBytes().ToUnsignedBigInteger(128).ToArray();
            var exponent2 = reader.ReadIntegerBytes().ToUnsignedBigInteger(128).ToArray();
            var coefficient = reader.ReadIntegerBytes().ToUnsignedBigInteger(128).ToArray();

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = modulus,
                Exponent = publicExponent,
                D = privateExponent,
                P = prime1,
                Q = prime2,
                DP = exponent1,
                DQ = exponent2,
                InverseQ = coefficient,
            });
            return rsa;
#else
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var privateKeyInfo = new PrivateKeyInfo(algorithm, privateKeyStructure);
            return PrivateKeyFactory.CreateKey(privateKeyInfo) as RsaPrivateCrtKeyParameters;
#endif 
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
            using var aes = Aes.Create();

            aes.BlockSize = 16 * 8;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            iv = iv ?? GetRandomBytes(16);
            using var encryptor = aes.CreateEncryptor(key, iv);
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
            }
            return iv.Concat(ms.ToArray()).ToArray();
        }

        /// <summary>
        ///     Decrypts data with AES CBC.
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="key">AES encryption key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptAesV1(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.BlockSize = 16 * 8;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var iv = data.Take(16).ToArray();
            using var encryptor = aes.CreateDecryptor(key, iv);
            using var ms1 = new MemoryStream();
            using (var ms = new MemoryStream(data, 16, data.Length - 16))
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read))
            {
                cs.CopyTo(ms1);
            }
            return ms1.ToArray();
        }

        /// <exclude/>
        public static byte[] EncryptAesV2(byte[] data, byte[] key, byte[] nonce)
        {
#if !HAS_BOUNCYCASTLE
            using var aes = new AesGcm(key, AesGcmTagSize);

            var encryptedData = new byte[AesGcmNonceSize + data.Length + AesGcmTagSize];
            var nonceSpan = new Span<byte>(encryptedData, 0, AesGcmNonceSize);
            if (nonce == null)
            {
                SecureRandom.GetBytes(nonceSpan);
            }
            else
            {
                Array.Copy(nonce, encryptedData, AesGcmNonceSize);
            }
            var encrypted = new Span<byte>(encryptedData, AesGcmNonceSize, data.Length);
            var tag = new Span<byte>(encryptedData, AesGcmNonceSize + data.Length, AesGcmTagSize);
            var plain = new ReadOnlySpan<byte>(data, 0, data.Length);

            aes.Encrypt(nonceSpan, plain, encrypted, tag);
            return encryptedData;
#else
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            len += cipher.DoFinal(cipherText, len);

            return nonce.Concat(cipherText.Take(len)).ToArray();
#endif
        }

        /// <summary>
        ///     Encrypts data with AES GCM.
        /// </summary>
        /// <param name="data">Plain data.</param>
        /// <param name="key">AES encryption key.</param>
        /// <param name="nonceLength">Nonce length in bytes. Optional. Default 12</param>
        /// <returns>Encrypted data.</returns>
        /// <remarks>[NONCE: 12bytes][ENCRYPTED DATA][TAG: 16bytes]></remarks>
        public static byte[] EncryptAesV2(byte[] data, byte[] key, int nonceLength = AesGcmNonceSize)
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
        public static byte[] DecryptAesV2(byte[] data, byte[] key, int nonceLength = AesGcmNonceSize)
        {
#if !HAS_BOUNCYCASTLE
            using var aes = new AesGcm(key, AesGcmTagSize);
            var buffer = new byte[data.Length - (AesGcmNonceSize + AesGcmTagSize)];
            var nonce = data.Take(AesGcmNonceSize).ToArray();
            var encrypted = data.Skip(AesGcmNonceSize).Take(buffer.Length).ToArray();
            var tag = data.Skip(AesGcmNonceSize + buffer.Length).Take(AesGcmTagSize).ToArray();
            aes.Decrypt(nonce, encrypted, tag, buffer);
            return buffer;
#else
            var nonce = data.Take(nonceLength).ToArray();
            var parameters = new AeadParameters(new KeyParameter(key), 16 * 8, nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, parameters);
            var decryptedData = new byte[cipher.GetOutputSize(data.Length - nonceLength)];

            var len = cipher.ProcessBytes(data, nonceLength, data.Length - nonceLength, decryptedData, 0);
            len += cipher.DoFinal(decryptedData, len);

            return decryptedData.Take(len).ToArray();
#endif
        }

        /// <summary>
        ///     Encrypts data with RSA public key.
        /// </summary>
        /// <param name="data">Plain data</param>
        /// <param name="publicKey">RSA public key.</param>
        /// <returns>Encrypted data.</returns>
        /// <remarks>Uses PKCS1 padding.</remarks>
        public static byte[] EncryptRsa(byte[] data, RsaPublicKey publicKey)
        {
#if !HAS_BOUNCYCASTLE
            return publicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
#else
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, publicKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
#endif
        }

        /// <summary>
        ///     Decrypts data with RSA private key
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="privateKey">RSA private key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptRsa(byte[] data, RsaPrivateKey privateKey)
        {
#if !HAS_BOUNCYCASTLE
            return privateKey.Decrypt(data, RSAEncryptionPadding.Pkcs1);
#else
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
#endif
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
#if !HAS_BOUNCYCASTLE
            using var pdb = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pdb.GetBytes(256 / 8);
#else
                var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
                pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
                return ((KeyParameter) pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();
#endif
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
            var key = DeriveKeyV1(password, salt, iterations);
            using var sha = SHA256.Create();
            return sha.ComputeHash(key, 0, key.Length);
        }

        /// <exclude />
        public static byte[] CreateAuthVerifier(string password, byte[] salt, int iterations)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian) Array.Reverse(iterationsBytes);

            var key = DeriveKeyV1(password, salt, iterations);
            return new[] { versionBytes.Take(1), iterationsBytes.Skip(1), salt, key }.SelectMany(x => x).ToArray();
        }

        /// <exclude />
        public static byte[] CreateEncryptionParams(string password, byte[] salt, int iterations, byte[] dataKey)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian) Array.Reverse(iterationsBytes);

            var key = DeriveKeyV1(password, salt, iterations);
            var iv = GetRandomBytes(16);

            using var aes = Aes.Create();
            aes.BlockSize = 16 * 8;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var encryptor = aes.CreateEncryptor(key, iv);
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            cs.Write(dataKey, 0, dataKey.Length);
            cs.Write(dataKey, 0, dataKey.Length);

            var outBuffer = ms.ToArray();
            return new[] { versionBytes.Take(1), iterationsBytes.Skip(1), salt, iv, outBuffer }.SelectMany(x => x)
                .ToArray();
        }

        /// <exclude />
        public static byte[] DecryptEncryptionParams(string password, byte[] encryptionParams)
        {
            if (encryptionParams[0] != 1) throw new Exception(CorruptedEncryptionParametersMessage);

            if (encryptionParams.Length != 1 + 3 + 16 + 16 + 64)
                throw new Exception(CorruptedEncryptionParametersMessage);

            var iterations = (encryptionParams[1] << 16) + (encryptionParams[2] << 8) + encryptionParams[3];

            var salt = new byte[16];
            Array.Copy(encryptionParams, 4, salt, 0, 16);
            var key = DeriveKeyV1(password, salt, iterations);

            Array.Copy(encryptionParams, 20, salt, 0, 16);

            using var aes = Aes.Create();
            aes.BlockSize = 16 * 8;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            using var decryptor = aes.CreateDecryptor(key, salt);

            using var ms1 = new MemoryStream();
            using (var ms = new MemoryStream(encryptionParams, 36, 64))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                cs.CopyTo(ms1);
            }
            var outBuffer = ms1.ToArray();
            if (!outBuffer.Take(32).SequenceEqual(outBuffer.Skip(32)))
                throw new Exception(CorruptedEncryptionParametersMessage);

            return outBuffer.Take(32).Take(32).ToArray();
        }

        /// <summary>
        ///     Generates RSA key pair.
        /// </summary>
        /// <param name="privateKey"><c>out</c>Rsa Private key.</param>
        /// <param name="publicKey"><c>out</c>Rsa Public Key</param>
        public static void GenerateRsaKey(out RsaPrivateKey privateKey, out RsaPublicKey publicKey)
        {
#if !HAS_BOUNCYCASTLE
            var rsa = RSA.Create();
            var rsaPublicKey = RSA.Create();
            rsaPublicKey.ImportParameters(rsa.ExportParameters(false));
            privateKey = rsa;
            publicKey = rsaPublicKey;
#else
            var r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(SecureRandom, 2048));
            var keyPair = r.GenerateKeyPair();

            privateKey = (RsaPrivateCrtKeyParameters) keyPair.Private;
            publicKey = (RsaKeyParameters) keyPair.Public;
#endif
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
#if !HAS_BOUNCYCASTLE
            using var pdb = new Rfc2898DeriveBytes(domain + password, salt, iterations, HashAlgorithmName.SHA512);
            var key = pdb.GetBytes(512 / 8);
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(domain));
#else
            var passwordBytes = Encoding.UTF8.GetBytes(domain + password);
            var pdb = new Pkcs5S2ParametersGenerator(new Sha512Digest());
            pdb.Init(passwordBytes, salt, iterations);
            var key = ((KeyParameter) pdb.GenerateDerivedMacParameters(64 * 8)).GetKey();
            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(domain));
#endif
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
        public static void GenerateEcKey(out EcPrivateKey privateKey, out EcPublicKey publicKey)
        {
#if !HAS_BOUNCYCASTLE
            privateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            publicKey = privateKey.PublicKey;
#else
            var keyGeneratorParams = new ECKeyGenerationParameters(EcParameters, SecureRandom);
            var keyGenerator = new ECKeyPairGenerator("ECDH");
            keyGenerator.Init(keyGeneratorParams);
            var keyPair = keyGenerator.GenerateKeyPair();
            privateKey = keyPair.Private as ECPrivateKeyParameters;
            publicKey = keyPair.Public as ECPublicKeyParameters;
#endif
        }

        /// <summary>
        ///     Serializes EC private key.
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>byte array representing EC private key.</returns>
        /// <remarks>32 bytes</remarks>
        public static byte[] UnloadEcPrivateKey(EcPrivateKey key)
        {
#if !HAS_BOUNCYCASTLE
            var parameters = key.ExportParameters(true);
            return parameters.D;
#else
            var privateKey = key.D.ToByteArrayUnsigned();
            var len = privateKey.Length;
            if (len >= 32) return privateKey;
            var pk = new byte[32];
            Array.Clear(pk, 0, pk.Length);
            Array.Copy(privateKey, 0, pk, 32 - len, len);
            return pk;
#endif
        }

        /// <summary>
        ///     Serializes EC public key.
        /// </summary>
        /// <param name="publicKey">Public key.</param>
        /// <returns>byte array representing EC public key.</returns>
        /// <remarks>Uncompressed. 65 bytes.</remarks>
        public static byte[] UnloadEcPublicKey(EcPublicKey publicKey)
        {
#if !HAS_BOUNCYCASTLE
            var key = new byte[65];
            key[0] = 0x04;
            var parameters = publicKey.ExportParameters();
            Array.Copy(parameters.Q.X!, 0, key, 1, 32);
            Array.Copy(parameters.Q.Y!, 0, key, 33, 32);
            return key;
#else
            return publicKey.Q.GetEncoded();
#endif
        }

        /// <summary>
        ///     Loads EC private key.
        /// </summary>
        /// <param name="privateKey">private key bytes</param>
        /// <returns>EC private key.</returns>
        /// <exception cref="Exception">invalid key bytes</exception>
        public static EcPrivateKey LoadEcPrivateKey(byte[] privateKey)
        {
#if !HAS_BOUNCYCASTLE
            if (privateKey.Length < 32)
            {
                throw new ArgumentException("Invalid EC private key data");
            }
            var ecKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecKey.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKey
            });
            return ecKey;
#else
            return new ECPrivateKeyParameters(new BigInteger(1, privateKey), EcParameters);
#endif
        }

        /// <summary>
        ///     LoadV2 EC public key.
        /// </summary>
        /// <param name="publicKey">public key bytes.</param>
        /// <returns>EC public key</returns>
        /// <exception cref="Exception">invalid key bytes</exception>
        public static EcPublicKey LoadEcPublicKey(byte[] publicKey)
        {
#if !HAS_BOUNCYCASTLE
            if (publicKey.Length < 65)
            {
                throw new ArgumentException("Invalid EC public key data");
            }
            if (publicKey[0] != 0x04)
            {
                throw new ArgumentException("Invalid EC public key data");
            }

            var x = new ReadOnlySpan<byte>(publicKey, 1, 32);
            var y = new ReadOnlySpan<byte>(publicKey, 33, 32);
            var pk = EcPrivateKey.Create(ECCurve.NamedCurves.nistP256);
            pk.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = x.ToArray(),
                    Y = y.ToArray()
                }
            });
            return pk.PublicKey;
#else
            var point = new X9ECPoint(EcParameters.Curve, new DerOctetString(publicKey)).Point;
            return new ECPublicKeyParameters(point, EcParameters);
#endif
        }

        /// <exclude />
        public static EcPublicKey GetEcPublicKey(EcPrivateKey privateKey)
        {
#if !HAS_BOUNCYCASTLE
            return privateKey.PublicKey;
#else
            return new ECPublicKeyParameters(privateKey.Parameters.G.Multiply(privateKey.D), privateKey.Parameters);
#endif
        }

        /// <summary>
        ///     Encrypts data with EC cryptography.
        /// </summary>
        /// <param name="data">Plain text</param>
        /// <param name="publicKey">Public key.</param>
        /// <returns>Encrypted data</returns>
        /// <remarks>[EPHEMERAL PUBLIC KEY][AES GCM ENCRYPTED DATA]</remarks>
        public static byte[] EncryptEc(byte[] data, EcPublicKey publicKey)
        {
            GenerateEcKey(out var ePrivateKey, out var ePublicKey);
#if !HAS_BOUNCYCASTLE
            var encryptionKey = ePrivateKey.DeriveKeyMaterial(publicKey);
            var pk = UnloadEcPublicKey(ePublicKey);
            var encryptedData = EncryptAesV2(data, encryptionKey);
            var result = new byte[pk.Length + encryptedData.Length];
            Array.Copy(pk, result, pk.Length);
            Array.Copy(encryptedData, 0, result, pk.Length, encryptedData.Length);
            return result;
#else
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(ePrivateKey);
            var key = agreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
            key = SHA256.Create().ComputeHash(key);
            var encryptedData = EncryptAesV2(data, key);
            return UnloadEcPublicKey(ePublicKey).Concat(encryptedData).ToArray();
#endif
        }

        /// <summary>
        ///     Decrypts data wit EC cryptography.
        /// </summary>
        /// <param name="data">Encrypted data.</param>
        /// <param name="privateKey">Private key.</param>
        /// <returns>Plain data.</returns>
        public static byte[] DecryptEc(byte[] data, EcPrivateKey privateKey)
        {
#if !HAS_BOUNCYCASTLE
            var ePublicKey = LoadEcPublicKey(data);
            var encryptionKey = privateKey.DeriveKeyMaterial(ePublicKey);
            var encryptedData = new ReadOnlySpan<byte>(data, 65, data.Length - 65).ToArray();
            return DecryptAesV2(encryptedData, encryptionKey);
#else
            var ePublicKey = LoadEcPublicKey(data.Take(65).ToArray());
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(privateKey);
            var key = agreement.CalculateAgreement(ePublicKey).ToByteArrayUnsigned();
            key = SHA256.Create().ComputeHash(key);
            return DecryptAesV2(data.Skip(65).ToArray(), key);
#endif
        }

        internal static byte[] Base32ToBytes(string base32)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new List<byte>();
            var bytes = base32.ToCharArray();
            for (var bitIndex = 0; bitIndex / 5 + 1 < bytes.Length; bitIndex += 8)
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

            HMAC hmac = algorithm switch
            {
                "SHA1" => new HMACSHA1(secretBytes),
                "SHA256" => new HMACSHA256(secretBytes),
                "SHA512" => new HMACSHA512(secretBytes),
                "MD5" => new HMACMD5(secretBytes),
                _ => null,
            };

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

        private static void Shuffle<T>(T[] array)
        {
            if (!(array?.Length >= 2)) return;
            var bigArray = array.Length > byte.MaxValue;
            var randoms = GetRandomBytes(array.Length * (bigArray ? 4 : 1));
            for (var i = array.Length - 1; i >= 0; i--)
            {
                var random = bigArray ? (int) (BitConverter.ToUInt32(randoms, i * 4) & 0x7fffffff) : randoms[i];
                var j = random % array.Length;
                if (i != j)
                {
                    var ch = array[i];
                    array[i] = array[j];
                    array[j] = ch;
                }
            }
        }

        /// <summary>
        /// Special characters for password generator
        /// </summary>
        public static readonly string SpecialCharacters = "!@#$%()+;<>=?[]{}^.,";

        /// <summary>
        /// Generates random password.
        /// </summary>
        /// <param name="options">Password generation rules. Optional</param>
        /// <returns>Generated password</returns>
        public static string GeneratePassword(PasswordGenerationOptions options = null)
        {
            const int letterCount = 'z' - 'a' + 1;

            var length = options?.Length ?? 20;
            var upper = options?.Upper ?? 4;
            var lower = options?.Lower ?? 4;
            var digit = options?.Digit ?? 2;
            var special = options?.Special ?? -1;

            if (length <= 0)
            {
                length = 20;
            }

            if (upper < 0 && lower < 0 && digit < 0 && special < 0)
            {
                lower = length;
            }

            var required = Math.Max(upper, 0) + Math.Max(lower, 0) + Math.Max(digit, 0) + Math.Max(special, 0);
            var extra = required - length;
            if (extra > 0)
            {
                var left = extra;
                if (lower > 0)
                {
                    var toSubstract = (int) Math.Ceiling((float) lower / required * extra);
                    if (toSubstract > 0)
                    {
                        toSubstract = Math.Min(left, toSubstract);
                        lower -= toSubstract;
                        left -= toSubstract;
                    }
                }

                if (left > 0 && upper > 0)
                {
                    var toSubstract = (int) Math.Ceiling((float) upper / required * extra);
                    if (toSubstract > 0)
                    {
                        toSubstract = Math.Min(left, toSubstract);
                        upper -= toSubstract;
                        left -= toSubstract;
                    }
                }

                if (left > 0 && digit > 0)
                {
                    var toSubstract = (int) Math.Ceiling((float) digit / required * extra);
                    if (toSubstract > 0)
                    {
                        toSubstract = Math.Min(left, toSubstract);
                        digit -= toSubstract;
                        left -= toSubstract;
                    }
                }

                if (left > 0 && special > 0)
                {
                    var toSubstract = (int) Math.Ceiling((float) special / required * extra);
                    if (toSubstract > 0)
                    {
                        toSubstract = Math.Min(left, toSubstract);
                        special -= toSubstract;
                        left -= toSubstract;
                    }
                }

                Debug.Assert(left <= 0);
            }

            required = Math.Max(upper, 0) + Math.Max(lower, 0) + Math.Max(digit, 0) + Math.Max(special, 0);
            extra = length - required;
            while (extra > 0)
            {
                if (extra > 0 && lower >= 0)
                {
                    lower++;
                    extra--;
                }

                if (extra > 0 && upper >= 0)
                {
                    upper++;
                    extra--;
                }

                if (extra > 0 && digit >= 0)
                {
                    digit++;
                    extra--;
                }

                if (extra > 0 && special >= 0)
                {
                    special++;
                    extra--;
                }
            }


            var buffer = new char[length];
            var indexes = new int[length];
            for (var i = 0; i < indexes.Length; i++)
            {
                indexes[i] = i;
            }

            Shuffle(indexes);
            var randoms = GetRandomBytes(length);
            var specialCharacters = string.IsNullOrEmpty(options?.SpecialCharacters)
                ? SpecialCharacters
                : options.SpecialCharacters;
            foreach (var pos in indexes)
            {
                if (upper > 0)
                {
                    buffer[pos] = (char) ('A' + (randoms[pos] % letterCount));
                    upper--;
                }
                else if (lower > 0)
                {
                    buffer[pos] = (char) ('a' + (randoms[pos] % letterCount));
                    lower--;
                }
                else if (digit > 0)
                {
                    buffer[pos] = (char) ('0' + (randoms[pos] % 10));
                    digit--;
                }
                else if (special > 0)
                {
                    buffer[pos] = specialCharacters[randoms[pos] % specialCharacters.Length];
                    special--;
                }
                else
                {
                    buffer[pos] = (char) ('a' + (randoms[pos] % letterCount));
                }
            }

            Shuffle(buffer);
            return new string(buffer);
        }

    }

    /// <summary>
    /// Defines password generation rules.
    /// </summary>
    public class PasswordGenerationOptions
    {
        /// <summary>
        /// Password Length
        /// </summary>
        /// <remarks>Default: 20</remarks>
        public int Length { get; set; }

        /// <summary>
        /// Minimal number of lowercase characters. 
        /// </summary>
        /// <remarks>-1 to exclude lowercase characters</remarks>
        public int Lower { get; set; }

        /// <summary>
        /// Minimal number of uppercase characters. 
        /// </summary>
        /// <remarks>-1 to exclude uppercase characters</remarks>
        public int Upper { get; set; }

        /// <summary>
        /// Minimal number of digits
        /// </summary>
        /// <remarks>-1 to exclude digits</remarks>
        public int Digit { get; set; }

        /// <summary>
        /// Minimal number of special characters
        /// </summary>
        /// <remarks>-1 to exclude special characters</remarks>
        public int Special { get; set; }

        /// <summary>
        /// Special character vocabulary. <see cref="CryptoUtils.SpecialCharacters"/>
        /// </summary>
        public string SpecialCharacters { get; set; }
    }
}
