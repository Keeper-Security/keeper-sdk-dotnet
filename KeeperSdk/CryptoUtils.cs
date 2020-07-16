//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Paddings;
using System.Web;
using System.Collections.Generic;
using System.Diagnostics;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;

namespace KeeperSecurity.Sdk
{
    public static class CryptoUtils
    {
        private const string CorruptedEncryptionParametersMessage = "Corrupted encryption parameters";

        private static readonly SecureRandom RngCsp = new SecureRandom();

        internal static readonly ECDomainParameters EcParameters;

        static CryptoUtils()
        {
            var curve = ECNamedCurveTable.GetByName("secp256r1");
            EcParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N);
        }

        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            RngCsp.NextBytes(bytes);
            return bytes;
        }

        public static byte[] GenerateEncryptionKey()
        {
            return GetRandomBytes(32);
        }

        public static string GenerateUid()
        {
            return GetRandomBytes(16).Base64UrlEncode();
        }

        public static string Base64UrlEncode(this byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            return base64.TrimEnd('=').Replace("+", "-").Replace("/", "_");
        }

        public static byte[] Base64UrlDecode(this string text)
        {
            if (text == null) return null;
            var base64 = text
                .Replace("-", "+")
                .Replace("_", "/")
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

        public static RsaKeyParameters LoadPublicKey(byte[] key)
        {
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var publicKeyStructure = RsaPublicKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var publicKeyInfo = new SubjectPublicKeyInfo(algorithm, publicKeyStructure);

            return PublicKeyFactory.CreateKey(publicKeyInfo) as RsaKeyParameters;
        }

        public static RsaPrivateCrtKeyParameters LoadPrivateKey(byte[] key)
        {
            var algorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
            var privateKeyStructure = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(key));
            var privateKeyInfo = new PrivateKeyInfo(algorithm, privateKeyStructure);

            return PrivateKeyFactory.CreateKey(privateKeyInfo) as RsaPrivateCrtKeyParameters;
        }

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


        const int AesGcmNonceLength = 12;

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

        public static byte[] EncryptAesV2(byte[] data, byte[] key, int nonceLength = AesGcmNonceLength)
        {
            return EncryptAesV2(data, key, GetRandomBytes(nonceLength));
        }

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

        public static byte[] EncryptRsa(byte[] data, RsaKeyParameters publicKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, publicKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static byte[] DecryptRsa(byte[] data, RsaPrivateCrtKeyParameters privateKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        public static byte[] DeriveKeyV1(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            return ((KeyParameter) pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();
        }

        public static byte[] DeriveV1KeyHash(string password, byte[] salt, int iterations)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pdb.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), salt, iterations);
            var key = ((KeyParameter) pdb.GenerateDerivedMacParameters(32 * 8)).GetKey();

            return SHA256.Create().ComputeHash(key);
        }

        public static byte[] CreateAuthVerifier(string password, byte[] salt, int iterations)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationsBytes);
            }

            var key = DeriveKeyV1(password, salt, iterations);
            return new[] {versionBytes.Take(1), iterationsBytes.Skip(1), salt, key}.SelectMany(x => x).ToArray();
        }

        public static byte[] CreateEncryptionParams(string password, byte[] salt, int iterations, byte[] dataKey)
        {
            var versionBytes = BitConverter.GetBytes(1);
            var iterationsBytes = BitConverter.GetBytes(iterations);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(iterationsBytes);
            }

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

        public static byte[] DecryptEncryptionParams(string password, byte[] encryptionParams)
        {
            if (encryptionParams[0] != 1)
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }

            if (encryptionParams.Length != 1 + 3 + 16 + 16 + 64)
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }

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
            while (len < 64)
            {
                len += cipher.ProcessBlock(encryptionParams, len + 36, outBuffer, len);
            }

            if (!outBuffer.Take(32).SequenceEqual(outBuffer.Skip(32)))
            {
                throw new Exception(CorruptedEncryptionParametersMessage);
            }

            return outBuffer.Take(32).Take(32).ToArray();
        }

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

        public static byte[] DeriveKeyV2(string domain, string password, byte[] salt, int iterations)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(domain + password);

            var pdb = new Pkcs5S2ParametersGenerator(new Sha512Digest());
            pdb.Init(passwordBytes, salt, iterations);
            var key = ((KeyParameter) pdb.GenerateDerivedMacParameters(64 * 8)).GetKey();

            var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(domain));
        }

        public static void GenerateEcKey(out ECPrivateKeyParameters privateKey, out ECPublicKeyParameters publicKey)
        {
            var keyGeneratorParams = new ECKeyGenerationParameters(EcParameters, RngCsp);
            var keyGenerator = new ECKeyPairGenerator("ECDH");
            keyGenerator.Init(keyGeneratorParams);
            var keyPair = keyGenerator.GenerateKeyPair();
            privateKey = keyPair.Private as ECPrivateKeyParameters;
            publicKey = keyPair.Public as ECPublicKeyParameters;
        }

        public static byte[] UnloadEcPrivateKey(ECPrivateKeyParameters key)
        {
            return key.D.ToByteArrayUnsigned();
        }

        public static byte[] UnloadEcPublicKey(ECPublicKeyParameters key)
        {
            return key.Q.GetEncoded();
        }

        public static ECPrivateKeyParameters LoadPrivateEcKey(byte[] key)
        {
            return new ECPrivateKeyParameters(new BigInteger(1, key), EcParameters);
        }

        public static ECPublicKeyParameters LoadPublicEcKey(byte[] key)
        {
            var point = new X9ECPoint(EcParameters.Curve, new DerOctetString(key)).Point;
            return new ECPublicKeyParameters(point, EcParameters);
        }

        public static ECPublicKeyParameters GetPublicEcKey(ECPrivateKeyParameters privateKey)
        {
            return new ECPublicKeyParameters(privateKey.Parameters.G.Multiply(privateKey.D), privateKey.Parameters);
        }

        public static byte[] EncryptEc(byte[] data, ECPublicKeyParameters publicKey)
        {
            GenerateEcKey(out var ePrivateKey, out var ePublicKey);
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(ePrivateKey);
            var key = agreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
            var encryptedData = EncryptAesV2(data, key);
            return UnloadEcPublicKey(ePublicKey).Concat(encryptedData).ToArray();
        }

        public static byte[] DecryptEc(byte[] data, ECPrivateKeyParameters privateKey)
        {
            var ePublicKey = LoadPublicEcKey(data.Take(65).ToArray());
            var agreement = AgreementUtilities.GetBasicAgreement("ECDHC");
            agreement.Init(privateKey);
            var key = agreement.CalculateAgreement(ePublicKey).ToByteArrayUnsigned();
            return DecryptAesV2(data.Skip(65).ToArray(), key);
        }

        public static byte[] Base32ToBytes(string base32)
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
                output.Add((byte) (dualByte));
            }

            return output.ToArray();
        }

        public static Tuple<string, int, int> GetTotpCode(string url)
        {
            var uri = new Uri(url);
            if (uri.Scheme != "otpauth")
            {
                return null;
            }

            string secret = null;
            var algorithm = "SHA1";
            var digits = 6;
            var period = 30;
            var coll = HttpUtility.ParseQueryString(uri.Query);
            foreach (var key in coll.AllKeys)
            {
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
            }

            if (string.IsNullOrEmpty(secret))
            {
                return null;
            }

            var tmBase = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
            var tm = tmBase / period;
            var msg = BitConverter.GetBytes(tm);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(msg);
            }

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
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(codeBytes);
            }

            var codeInt = BitConverter.ToInt32(codeBytes, 0);
            codeInt %= Enumerable.Repeat(10, digits).Aggregate(1, (a, b) => a * b);
            var codeStr = codeInt.ToString();
            while (codeStr.Length < digits)
            {
                codeStr = "0" + codeStr;
            }

            return Tuple.Create(codeStr, (int) (tmBase % period), period);
        }
    }

    public class EncryptTransform : ICryptoTransform
    {
        public int InputBlockSize => cypher.GetBlockSize();

        public int OutputBlockSize => cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        readonly IBufferedCipher cypher;
        byte[] tail;

        public long EncryptedBytes { get; private set; }

        public EncryptTransform(IBufferedCipher cypher, byte[] key)
        {
            this.cypher = cypher;
            var iv = CryptoUtils.GetRandomBytes(cypher.GetBlockSize());
            this.cypher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            tail = iv;
            EncryptedBytes = 0;
        }

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            EncryptedBytes += inputCount;
            var encrypted = cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            if (tail.Length > 0)
            {
                if (tail.Length <= outputBuffer.Length + outputOffset + encrypted)
                {
                    Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + tail.Length, encrypted);
                    Array.Copy(tail, 0, outputBuffer, outputOffset, tail.Length);
                    encrypted += tail.Length;
                    tail = new byte[0];
                }
                else
                {
                    if (tail.Length <= encrypted)
                    {
                        var newTail = new byte[tail.Length];
                        Array.Copy(outputBuffer, outputOffset + encrypted - tail.Length, newTail, 0, tail.Length);
                        Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + tail.Length, encrypted);
                        Array.Copy(tail, 0, outputBuffer, outputOffset, tail.Length);
                        tail = newTail;
                    }
                    else
                    {
                        var newTail = new byte[tail.Length + encrypted];
                        Array.Copy(tail, 0, newTail, 0, tail.Length);
                        Array.Copy(outputBuffer, outputOffset, newTail, tail.Length, encrypted);
                        tail = newTail;
                        encrypted = 0;
                    }
                }
            }

            return encrypted;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            EncryptedBytes += inputCount;
            var final = cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            var result = new byte[tail.Length + final.Length];
            Array.Copy(tail, 0, result, 0, tail.Length);
            Array.Copy(final, 0, result, tail.Length, final.Length);
            return result;
        }
    }

    public class DecryptTransform : ICryptoTransform
    {
        public int InputBlockSize => cypher.GetBlockSize();

        public int OutputBlockSize => cypher.GetBlockSize();

        public bool CanTransformMultipleBlocks => true;

        public bool CanReuseTransform => false;

        readonly IBufferedCipher cypher;
        readonly byte[] key;
        bool initialized;

        public long DecryptedBytes { get; private set; }

        public DecryptTransform(IBufferedCipher cypher, byte[] key)
        {
            this.cypher = cypher;
            this.key = key;
            initialized = false;
            DecryptedBytes = 0;
        }

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            if (!initialized)
            {
                var iv = new byte[cypher.GetBlockSize()];
                Array.Copy(inputBuffer, inputOffset, iv, 0, iv.Length);
                inputOffset += iv.Length;
                inputCount -= iv.Length;
                cypher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                initialized = true;
            }

            var res = cypher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            DecryptedBytes += res;
            return res;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (!initialized)
            {
                var iv = new byte[cypher.GetBlockSize()];
                Array.Copy(inputBuffer, inputOffset, iv, 0, iv.Length);
                inputOffset += iv.Length;
                inputCount -= iv.Length;
                cypher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
                initialized = true;
            }

            var res = cypher.DoFinal(inputBuffer, inputOffset, inputCount);
            DecryptedBytes += res.LongLength;
            return res;
        }
    }

    public class EncryptAesV1Transform : EncryptTransform
    {
        public EncryptAesV1Transform(byte[] key) : base(
            new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()), key)
        {
        }
    }

    public class DecryptAesV1Transform : DecryptTransform
    {
        public DecryptAesV1Transform(byte[] key) : base(
            new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding()), key)
        {
        }
    }
}