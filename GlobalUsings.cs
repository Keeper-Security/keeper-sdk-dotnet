#if NET8_0_OR_GREATER
global using RsaPrivateKey = System.Security.Cryptography.RSA;
global using RsaPublicKey = System.Security.Cryptography.RSA;
global using EcPrivateKey = System.Security.Cryptography.ECDiffieHellman;
global using EcPublicKey = System.Security.Cryptography.ECDiffieHellmanPublicKey;
#else
global using RsaPrivateKey = Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters;
global using RsaPublicKey = Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters;
global using EcPrivateKey = Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters; 
global using EcPublicKey = Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters;
#endif