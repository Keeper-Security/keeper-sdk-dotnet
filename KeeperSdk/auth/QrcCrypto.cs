#if NET10_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication
{
    internal sealed class QrcEncryptionMessage
    {
        public byte[] ClientEcPublicKey { get; set; }
        public byte[] MlKemEncapsulatedKey { get; set; }
        public byte[] Data { get; set; }
        public int MessageVersion { get; set; }
    }

    /// <summary>
    /// Implements the Commander QRC wire format (ECDH-P256 + ML-KEM-1024 + HKDF-SHA256).
    /// </summary>
    internal static class QrcCrypto
    {
        internal const int MessageVersion = 1;
        private const int MlKem1024PublicKeySize = 1568;
        private const string CipherSuite = "HPKE_ML-KEM-1024_ECDH-P256_HKDF-SHA256_AES-GCM-256";

        private static readonly IReadOnlyDictionary<int, byte[]> ServerMlKemPublicKeys =
            new Dictionary<int, byte[]>
            {
                [107] = DecodeBase64Url(
                    "rsSl4OfJIffO0Fxp6oBgGqJtniM8eyhi5lwlOiVZnwGrn_qnTch5fXbJwpAbnvoIa6VS00MeNShBvDo6bNIR2RRuq4lkgHUXNfap79l8JDi6xllfVLKRn5psVrGqXkybxjJH9UNQWJKr5TurXRnG9Wll0xXCC6ppHNszZ3e7D_xt5kFO2NS5PVl83uNp-Qp7iRAzcEtizvB55pkrAbyGkAALlCqsOSMPWXI544ult8EVCgU1CRk8vMsNSmNG8mO3FcCg0rmA7ljNdSQPQjQ231NJqDeRdlUAZclK8gks3WKF0CIsbVmbTZICFesd42Cw9CbHusZUjKoyVIDPVowFmHg72kcmPovBwMuesGg3coAj_NoFAlSyiXsvgPNMDciND-Z7OiRpK-eG6RGyUvhcdlw6k5FzjfNab5Zix9hHkoZhkyG-h9exzTxxgdeu6AMLEKl2QHtXpqle4zelOSiOtkgC8BRyPfjD5PBwrJsduwoXf0KljDXP0ceAmPbMaSMabeMj3CJY8OuHZOIxzQF2J8xEnAC9wuOD2ElNcVyOQ6lyFCueXfofHce_gMAIZpABZVZDxsB2jLBW1VF1yksRb1MAjPYBHFV7YJhHyiMI34VRbPo1o3lq9vk-4rwPwYUWDWQePDUkiYuxQTs36WwXVAtY-XOF9HMnkRjK25sqV_uwzbAIHAyf8SomVHUX7AtjyMYu52d33kkHhiA7ofqXjwBK69odR8Ckzam-egKkuUWlkPJeDXyR_AhpYhAqbzqgQHw7QhpEayBIS9xRcCixONLGkKtn8xIs-6HKhPCjTEDEN_IjVxM-HEY_rHpY_wSWibtNPEPAgAEtZSQIWyjJyPMRYTEgJZEBUUk1hiuNi_FFiNM71wkJldxngipdWYd9KFt5shExO4CAzxtd3MOTrHQEBuXNz6GL50diBJuioRR5QhgCddNejAcet8Ul0duAXuCyI2QDZnCQf0RO97Z9alwYllbA67EZMScBq6s81lAqqXWPJNNWQbQEVzidmdW28ZIbaOaPLOUuIqYJv_J60XuLLcYP4hrMBANqtwAb_HNlXGaW06vJT7wasEMzhDKVNSpFs4VYSMk1tIR6wjspGYJRGGE7hpiaDCPKOQRe24Y2HPJEBmNGWmMjREKpZYKg2nsV9nWvDVShKol1JpZM2kI9AEQPIIo9ZiHBleh_OnynWcCVAdl9ZsOkpOtMFPZap8gooqqMt2FO-gofSpGkFkNs41a5gxGeqRETiBsoa-ZNyqq2wJm77qJqSvC54oGOjFE_mfJBH0I4Fahy6Kkm-zKrJEAuehaVTXVHamgJeSkfLemt3WVlgPwZjNJMh5FsM8W8rclE78yI2WYpY9i0RhOJkNViBGcn5EovgERJPEsLO7SBviJwetmUQyUVbOAyX4ag_cBJ2fmUkwVQuhV6PdsnTqFfV2dM2ptbQgcopypvHyggh1vFooMYDIUCZ7qfBZYx7ZclV0woecJGjiK9mKgTlumnHtkx1zCETtNubQaDANkpAlZkKuS42WczUDEzpye8OpeYgaF6NIolqNFs_plgZVhg9_ZBEIZcnNGd1sgbg3it_Rk7EZXJDHB_6cWoS8VW1Wcq72FBpFDOWDiiCapw0QknC9pfB_gV7zm6nJpzFRcInIqGuNNJdMcCbmPAV0cKBxGR7PfKS4KCLoTCGctS3fKpE-Q-ZJBNwWRwB-cogesufQdr1oKJ3xXJtzGcoMK2n9OSAAStt3A_V-YvkVVzb0Z32HMG79NgAAeCG9xXkidVLIpzLuhg4AQRVzpXf8gry6qBZUppbPCriSSBr-vDlJIHh6gu7-y1cLi2zHinriOoElMK3fWI1JO7HUItxLCHrkzJt4R2N9nOD8gDqIK16-OG9SssQNlex5e0MVkbAA0BR1mn7MSTBvevw2VcsTJoIxXEIjS87fRvuadwrKqw3nKFOPSCZzgC7XFtzxIpazSCGWi_5RSDWnSXGLJvNcKhcvgfpgk4jSoEdDIJ30FUDFzHkusUnfVAbTnCIWCYDKWyk7G8bsRcVZwNxwKJ7G2Mz4a3yrkYuxaFmGJX5EdCEM4EWceF5rVW3ZQuvzo"),
                [124] = DecodeBase64Url(
                    "oOWRIAhfmuFV0WiH3QxnN1O81VqlUdPOXJqxIXpKFKFxZoJfKuGSPRZDzbhFYuwQccNswyJlvMZ0C5GuPfwoGWyPt2FOOKcoM8rASDpr1liu5nRmiBLFKTxMG6qccITD4XZyx6kb8KZZNnyu1euSQGE7dVl-DIM1ySi5MKNRJgWr3GpbhJA0oJxntxp_WWldAnqEq2tukWoKici34YEIhnQeXnBtekVAM0U7j7FzHEa5BaKdbIpP74VAS7ScsSMcRoloQWSsg5eIOPcAT7ZcycUhtbii7om6NQESEJxhUdjMWTTFiUGEoRBgtJYY59wkx0IvQbqUT8qSk0Ik3fasfjIRQehWeKk670KfFBswHRqgrNqY37wCUPOuDTKj4mnOq5gkQSiu55GvYzpUV4m4YJMxRPgp-RzPYwkbvKtZIKgMsLOeR0aGCTApdUAn3FoxQNxgLUqQW-aMNyUtHIsw9ZwXxnQAmEkif5UNiGDDfgScmkhKHKtC00FtRwNFRmaZuLUwqrly4DKnzfwJOJjPADCDSpoelwxQI7JE1yMZ9_UWxwSAk5AgFANXCfubrsl7J7ihFaywx-UhWGUX24xByXHAsGW_hPAROPV-r9lBYktaFkBfZmojijRCO6d0oEVzofJpkQMjZmVEzyZoiFw1mJMXppoSWVB_lEK_LpisWaUmT1JztoANlLZcb5fBktpihMNA7NHB_ioKdDWGNxa0miutZqhWDPOs87gOv8Nu70RdFxoUGnCMgAQwrHErebVdZKCGOxd8fYOrGeoH0kWC9mA7-8GKQqdsmOUtVcyQToCrsPkXBvjKhvqwfMirsjk70uiZ6QABdBy7j9svCyiyjaVHJYiSfRJDqNB47PyVskhH3WsnPqhfKcQroTI6pTnCYdJeJHgqKCp2ICeWZYKbRbeKQOI__DmYp2C1AB1PB7nFD1AVuvnGnOeLaRaE72h1dNyVQIFyzIOw8WY24-B_g1JXUmyaiQU4zvooGJlCrmm6n_MN36u0R2cwWwp9FjQ8bWMYCtqbSXtwtqQrM0PIKHxteUqqS6kWmjmy7_hPUwYbYiEszGKYI3fFD6HLutim8PISh6yDlflwzhaZO4KjewYc0TdKpsetmPF9AsBTlBciPylO66k9iEnCwIBgHSqtDraUUNVRbNaUz_VSixV_uEI8ZvoBzhExWwvH1hxC0yRdKskZ9GdiUzle-iAR4YBQ0oiXP8uDFCjF7qg__kHAOPtWBjKjN3tXwCmwJntwxURxbNAFqaGScqJSwGkQlGHOW_FLlRkZOgN_ztpDyKx4Trq4SgOd-KFiAee0GgpG9Qoq0_fHYJi6XsKdLiXMd5ZTUAWokCk4VoZeJYNY75Z4bkZFEgnCc5OjFvJmKwNzWvu5_ed5QoiLxeAWdpsyoGTKxruJR9VHCqMWkZieTnt-tQGNXqcy2Zqc2nBz8muk1gjNl6t2cZOvnACaW4nNxhYlTKHN49zDLPYmVzQU7YAEdLU-tIxv_IGOG9ulKhRdoYCrNgOInQVp7zJUSVIVDoK9jmxxrutMyyl0xbesB8lYeAO7f5DCuOF5Skq4KDHMY2GAo2zLIHJi4lR7mTirKgClyBUUBLZJAQSeArinnyRGy2Y9aBucHbdqvnqqjBgFXnFDZLaseDu0bMAGsVNLqHMUfaCq5nhHUDIe-pBaMuGmq9pMbMp1kNQj8ReJVEqBLAi2ZcR1QeK8zuyw98JF4cLAvZJ93PNZmdO87UmpBUJL72SXmKUJlzZtF2lma1QajwYCOTlyQcNP3ckd3Kit0VifCPVxJaqjxCDLnhiaQCALLFZnA7UuH8FEWeJZdpyxYEOqzOwA1Qq7JjYYdWJ-oUSfDGl6dgPFpIkVt2h37FFDz4hOCzM-SIgqlEqoA6rGDCAWrvSviveslAVUR2iDilKylpKiU_K2j2hKFnZ7B0Qv-rF-uUEHG-ZYzoOmkImArdeav1i7U-S4DZSuENJnO4NiwKlyxcAfrcd_GYIGolWa5pDPIctVwjqbUthGxzukiGku76sufqu2fRdPauLLuMdTnf6vXN0TRo-RPbf8GrijSi9UN-52OU7E7C7qUJLExlg"),
                [136] = DecodeBase64Url(
                    "F9FKL1aEqbMMsaSH-Ig3EOa1rJUdL1vPAXE3wcFSpbw8yUgI3NWbScM_S3ho3EQVxduSjTBWfpcbsVtkx6c5QauUYVx3rtx5bggMr-V_KSTC5RgYpkIZwHSSoxoO-PVamOWpnGKbNAsVsmQWc8Wi8JMQHDFn7uw5pVMZWEq5uNJRLAKvqlVo4Ux1dTSIaQgsBfLNvYZO9qFpc7XClaU-NhfHecNm3hEHQgmlixxs0HbOQqmi90YrCZwS3mkjFgvANauTmhTFiuWbgoUb3EWhausazlQ3A5tmjyRRm8ISniVrCmOrbEy-92qe2zasEyzL4mpdWUNjzCQC6qrKc4KfyHaJhwdaqocYp1VmwEmSrmdv5vKpHoSGcAZECMOFQVENuuEXlcsG7kYEOnEn0llllgOTbZwNsrIpVjHAKGJIaOCjxOsc46dB1XozHQuZs_QjZRpKEPsJJjcN3YVwglaDuLB3XgditEJJ1okrWYgC4ehHqkKYaSSoT_BTh6e8jqesYpF5SOjGMtAS0piZG_zGXxgYuCaZUUptaKi2FdyftfgCJEtLF9nFrNI_GOosDcydBBW2Z0sRf1aUDjI3nJKvMNokITQ77nRHj8yjoeEhDAZ6etm-jTDCROHIePoojgOwpRiTJRxeARy9m9i2BWGZuoq93eVxzuMv9nbFT5Nkpxwo1YnK0qAhp6ArkLShXIMy7dkLQRUVtVqKgPl2lyVwqiWSazM_t2KmAyY9LYJ9xCIxVNJUCvNrZzELrIsJdRRq9Cd0KBhuEmxUwGDD01qNzVOclgwnyQDMmTNHtnS46icX1AlDwkq3V3a1xDhF14SMwVZLHkixjyowVGKFoEswd6Ux2GAa5OV-8JODWVGxhIgtVspZklautfGMlXRl9sh8UiC63dyorsPHp8QrK7uBp2ZAhkmQDFIrrQydUhYkgUtEA3A9xhodaOa9XyZ6GVXFEDB1Q3iti2BkoaBZcLId8MSgjahOUzq4YYMT0mwP-orEkgujv2BhSmsuFkCuumksSxUOzpia96lsfpbN--utsiIhmqgm9rM9NAcj5mMbCwcuuYBbaPhW8QjAhYt_2uC53cEK4BUxgwUN-yCfMqGZw7WlIlemuUR5zMAksTyWPsq8esdfHnW_Q-Wh8shTOJQRDzkvo4KVBjIKoPJPOwKmo_Uv00gIiwB59imnQhEm7MYyW5sudNkDlwRjs_ehtYVTgiVyiBRKH3rKVmJQXSAbkVVuadyMZLQy6SkWvbmpekUzwgCEdYZjs3Mg6vXBiIGZ6Ym-K7Zsr7CzbmCWrcZblifFrOEIEagV7hGbyeFmIpZ-tVwVEjgpTPLAbqxfbtyHNuuK2RxN5NMLw7VxzJJTOTwvddk9OTNJk2Q5bMZJd-g258aOU-qmDaBIyYaPuHpS_3kjg0s8ZXG0w8MOZGN2-eaq8bWR3TbFd-ujsjR2sSkYVeYGcSJ6XvtF7UtXL7CfE2ujRMd8k_lW6tbDZ4uA17Bv2XVmo1cWENYiy2V5CXJk4Um9qRathlxRtjsifPaskYx26TC2yFlYNcJ-7CwKwXRvg4UWMSY2ngN53RUJigoQ82li5jsf3XtQwBIt58Qy6xlTzDST1scfTOuyc_AwiLgKECOCYxSTimiq4qOvszBJp_AAHGNHdXsgoxiTlkNDL6QIL-pIDcu374okz6m5e4t28wwWiDWPhWu1wAFmp0tsK8M-d-Z4UVY8FmYHrYgYNnA7i1jHUiwYijhGlyV3KUiWhqOxiGfN4LYRcJKi0vmlUox977F3yqR9BMMayIduHzirsCS6SqCcW3dZskUbk9jKLLBr8_IdmuaoZFNGnmUAQucOsHca6qpM3np-kVkI_Dl8ohAGcOOlDWhTr-CGaXcd3xJ63QQGMLYRFJirkUMP26qu6hqbhkuZXiO712laX4ybdUdmxde2GkmDnLyzhYOQSSUiMmDDYgmjbUc3GCcVrCRHmsbJTykq6neQB_Kj1lOFlAate4RDU_LGXyWxpImuQpHCqMazJpWCo-GauACBSBhFDucovzKbXjeds6Zpq3lBK_T9EaPvGASD6FO23qv-HxUEyHgnW-VkHhVirk4"),
            };

        internal static int? GetQrcKeyId(string server)
        {
            var value = server ?? string.Empty;
            if (!value.Contains("://", StringComparison.Ordinal))
            {
                value = "https://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            var keyId = uri.Host.ToLowerInvariant() switch
            {
                "qa.keepersecurity.com" => 107,
                "staging.keepersecurity.com" => 124,
                "keepersecurity.com" => 136,
                _ => (int?)null
            };

            return keyId.HasValue && ServerMlKemPublicKeys.ContainsKey(keyId.Value) ? keyId : null;
        }

        internal static QrcEncryptionMessage Encrypt(
            byte[] transmissionKey,
            EcPrivateKey clientEcPrivateKey,
            EcPublicKey serverEcPublicKey,
            int qrcKeyId)
        {
            if (transmissionKey == null) throw new ArgumentNullException(nameof(transmissionKey));
            if (clientEcPrivateKey == null) throw new ArgumentNullException(nameof(clientEcPrivateKey));
            if (serverEcPublicKey == null) throw new ArgumentNullException(nameof(serverEcPublicKey));
            if (!ServerMlKemPublicKeys.TryGetValue(qrcKeyId, out var serverMlKemPublicKey))
            {
                throw new CryptographicException($"ML-KEM public key {qrcKeyId} is not available.");
            }

            if (serverMlKemPublicKey.Length != MlKem1024PublicKeySize)
            {
                throw new CryptographicException($"Invalid ML-KEM-1024 public key size: {serverMlKemPublicKey.Length} bytes.");
            }

            var ecSharedSecret = clientEcPrivateKey.DeriveRawSecretAgreement(serverEcPublicKey);
            byte[] mlKemSharedSecret = null;
            byte[] aesKey = null;
            try
            {
                var clientEcPublicKey = CryptoUtils.UnloadEcPublicKey(clientEcPrivateKey.PublicKey);
                var serverEcPublicKeyBytes = CryptoUtils.UnloadEcPublicKey(serverEcPublicKey);

                using var mlKem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem1024, serverMlKemPublicKey);
                mlKem.Encapsulate(out var mlKemEncapsulatedKey, out mlKemSharedSecret);

                aesKey = DeriveAesKey(
                    ecSharedSecret,
                    mlKemSharedSecret,
                    serverEcPublicKeyBytes,
                    clientEcPublicKey,
                    mlKemEncapsulatedKey);
                var encryptedTransmissionKey = CryptoUtils.EncryptAesV2(transmissionKey, aesKey);

                return new QrcEncryptionMessage
                {
                    ClientEcPublicKey = clientEcPublicKey,
                    MlKemEncapsulatedKey = mlKemEncapsulatedKey,
                    Data = encryptedTransmissionKey,
                    MessageVersion = MessageVersion
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ecSharedSecret);
                if (mlKemSharedSecret != null)
                {
                    CryptographicOperations.ZeroMemory(mlKemSharedSecret);
                }

                if (aesKey != null)
                {
                    CryptographicOperations.ZeroMemory(aesKey);
                }
            }
        }

        private static byte[] DeriveAesKey(
            byte[] ecSecret,
            byte[] mlKemSecret,
            byte[] serverEcPublicKey,
            byte[] clientEcPublicKey,
            byte[] mlKemEncapsulatedKey)
        {
            var mlKemCiphertextHash = SHA256.HashData(mlKemEncapsulatedKey);
            var cipherSuite = Encoding.UTF8.GetBytes(CipherSuite);
            var info = new byte[cipherSuite.Length + serverEcPublicKey.Length + clientEcPublicKey.Length
                                + mlKemCiphertextHash.Length + 1];
            var offset = 0;
            Buffer.BlockCopy(cipherSuite, 0, info, offset, cipherSuite.Length);
            offset += cipherSuite.Length;
            Buffer.BlockCopy(serverEcPublicKey, 0, info, offset, serverEcPublicKey.Length);
            offset += serverEcPublicKey.Length;
            Buffer.BlockCopy(clientEcPublicKey, 0, info, offset, clientEcPublicKey.Length);
            offset += clientEcPublicKey.Length;
            Buffer.BlockCopy(mlKemCiphertextHash, 0, info, offset, mlKemCiphertextHash.Length);
            info[info.Length - 1] = MessageVersion;

            var inputKeyMaterial = new byte[ecSecret.Length + mlKemSecret.Length];
            Buffer.BlockCopy(ecSecret, 0, inputKeyMaterial, 0, ecSecret.Length);
            Buffer.BlockCopy(mlKemSecret, 0, inputKeyMaterial, ecSecret.Length, mlKemSecret.Length);

            // Commander uses a 32-byte zero salt and a 32-byte HKDF-SHA256 output.
            var salt = new byte[32];
            byte[] pseudoRandomKey = null;
            try
            {
                using (var extract = new HMACSHA256(salt))
                {
                    pseudoRandomKey = extract.ComputeHash(inputKeyMaterial);
                }

                using (var expand = new HMACSHA256(pseudoRandomKey))
                {
                    var expandInput = new byte[info.Length + 1];
                    Buffer.BlockCopy(info, 0, expandInput, 0, info.Length);
                    expandInput[expandInput.Length - 1] = 1;
                    return expand.ComputeHash(expandInput);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inputKeyMaterial);
                if (pseudoRandomKey != null)
                {
                    CryptographicOperations.ZeroMemory(pseudoRandomKey);
                }
            }
        }

        private static byte[] DecodeBase64Url(string value)
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2:
                    base64 += "==";
                    break;
                case 3:
                    base64 += "=";
                    break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}
#endif
