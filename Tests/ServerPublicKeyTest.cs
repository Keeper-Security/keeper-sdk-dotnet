using System.Linq;
using System.Text;
using KeeperSecurity.Authentication;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Xunit;

namespace Tests;

public class ServerPublicKeyTest
{
  private const string SelfHostedServer = "keeper.company.com";

  private static (IConfigurationStorage storage, EcPrivateKey privateKey) GetStorage(string server, int keyId)
  {
    CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
    var storage = new InMemoryConfigurationStorage();
    storage.SetServerPublicKey(server, keyId, CryptoUtils.UnloadEcPublicKey(publicKey).Base64UrlEncode());
    return (storage, privateKey);
  }

  [Fact]
  public void TestAdHocKeyOverridesBuiltInKey()
  {
    // Key ID 7 is built into the library. The configured key must win.
    var (storage, privateKey) = GetStorage(SelfHostedServer, 7);
    var endpoint = new KeeperEndpoint(storage, SelfHostedServer);
    Assert.Equal(7, endpoint.ServerKeyId);

    var transmissionKey = CryptoUtils.GenerateEncryptionKey();
    var encrypted = endpoint.EncryptWithKeeperKey(transmissionKey, 7);
    Assert.Equal(transmissionKey, CryptoUtils.DecryptEc(encrypted, privateKey));
  }

  [Fact]
  public void TestAdHocKeyId()
  {
    // Key ID is not in the range of the keys built into the library.
    var (storage, privateKey) = GetStorage(SelfHostedServer, 101);
    var endpoint = new KeeperEndpoint(storage, SelfHostedServer);
    Assert.Equal(101, endpoint.ServerKeyId);

    var data = Encoding.UTF8.GetBytes("transmission key");
    var encrypted = endpoint.EncryptWithKeeperKey(data, 101);
    Assert.Equal(data, CryptoUtils.DecryptEc(encrypted, privateKey));
  }

  [Fact]
  public void TestBuiltInKeysAreStillAvailable()
  {
    var (storage, _) = GetStorage(SelfHostedServer, 101);
    var endpoint = new KeeperEndpoint(storage, SelfHostedServer);

    // RSA key
    Assert.NotEmpty(endpoint.EncryptWithKeeperKey(CryptoUtils.GenerateEncryptionKey(), 1));
    // EC key
    Assert.NotEmpty(endpoint.EncryptWithKeeperKey(CryptoUtils.GenerateEncryptionKey(), 18));
  }

  [Fact]
  public void TestUnknownKeyId()
  {
    var (storage, _) = GetStorage(SelfHostedServer, 101);
    var endpoint = new KeeperEndpoint(storage, SelfHostedServer);
    Assert.Throws<KeeperInvalidParameter>(() =>
      endpoint.EncryptWithKeeperKey(CryptoUtils.GenerateEncryptionKey(), 102));
  }

  [Fact]
  public void TestAdHocKeyIsNotUsedForAnotherServer()
  {
    var (storage, _) = GetStorage(SelfHostedServer, 101);
    var endpoint = new KeeperEndpoint(storage, "keepersecurity.com");
    Assert.Equal(7, endpoint.ServerKeyId);
    Assert.Throws<KeeperInvalidParameter>(() =>
      endpoint.EncryptWithKeeperKey(CryptoUtils.GenerateEncryptionKey(), 101));
  }

  [Fact]
  public void TestInvalidPublicKey()
  {
    var storage = new InMemoryConfigurationStorage();
    Assert.Throws<KeeperInvalidParameter>(() =>
      storage.SetServerPublicKey(SelfHostedServer, 101, "bm90IGEga2V5"));
  }

  [Fact]
  public void TestJsonRoundTrip()
  {
    CryptoUtils.GenerateEcKey(out _, out var publicKey);
    var encodedKey = CryptoUtils.UnloadEcPublicKey(publicKey).Base64UrlEncode();

    var loader = new JsonInMemoryLoader();
    var jsonStorage = new JsonConfigurationStorage(loader);
    jsonStorage.SetServerPublicKey(SelfHostedServer, 101, encodedKey);

    Assert.Contains("server_public_keys", Encoding.UTF8.GetString(loader.Data));

    var configuration = new JsonConfigurationStorage(loader).Get();
    var sc = configuration.Servers.Get(SelfHostedServer);
    Assert.NotNull(sc);
    Assert.Equal(101, sc.ServerKeyId);
    var pk = sc.PublicKeys.List.Single();
    Assert.Equal(101, pk.KeyId);
    Assert.Equal("101", pk.Id);
    Assert.Equal(encodedKey, pk.PublicKey);
  }

  [Fact]
  public void TestJsonKeyIsReplaced()
  {
    CryptoUtils.GenerateEcKey(out _, out var publicKey);
    CryptoUtils.GenerateEcKey(out var newPrivateKey, out var newPublicKey);
    var encodedKey = CryptoUtils.UnloadEcPublicKey(newPublicKey).Base64UrlEncode();

    var loader = new JsonInMemoryLoader();
    var jsonStorage = new JsonConfigurationStorage(loader);
    jsonStorage.SetServerPublicKey(SelfHostedServer, 101, CryptoUtils.UnloadEcPublicKey(publicKey).Base64UrlEncode());
    jsonStorage.SetServerPublicKey(SelfHostedServer, 101, encodedKey);

    var configuration = new JsonConfigurationStorage(loader).Get();
    var pk = configuration.Servers.Get(SelfHostedServer).PublicKeys.List.Single();
    Assert.Equal(encodedKey, pk.PublicKey);

    var endpoint = new KeeperEndpoint(new JsonConfigurationStorage(loader), SelfHostedServer);
    var data = CryptoUtils.GenerateEncryptionKey();
    Assert.Equal(data, CryptoUtils.DecryptEc(endpoint.EncryptWithKeeperKey(data, 101), newPrivateKey));
  }

  [Fact]
  public void TestIgnoreCertificateErrorsIsPerServer()
  {
    var loader = new JsonInMemoryLoader();
    new JsonConfigurationStorage(loader).SetIgnoreCertificateErrors(SelfHostedServer, true);

    Assert.Contains("ignore_certificate_errors", Encoding.UTF8.GetString(loader.Data));

    var sc = new JsonConfigurationStorage(loader).Get().Servers.Get(SelfHostedServer);
    Assert.True(sc.IgnoreCertificateErrors);

    var endpoint = new KeeperEndpoint(new JsonConfigurationStorage(loader), SelfHostedServer);
    Assert.True(endpoint.IgnoreCertificateErrors);

    // Must not affect any other Keeper server.
    endpoint.Server = "keepersecurity.com";
    Assert.False(endpoint.IgnoreCertificateErrors);

    endpoint.Server = SelfHostedServer;
    Assert.True(endpoint.IgnoreCertificateErrors);
  }

  [Fact]
  public void TestCertificateErrorsAreNotIgnoredByDefault()
  {
    var (storage, _) = GetStorage(SelfHostedServer, 101);
    var endpoint = new KeeperEndpoint(storage, SelfHostedServer);
    Assert.False(endpoint.IgnoreCertificateErrors);
  }

  [Fact]
  public void TestIgnoreCertificateErrorsIsReverted()
  {
    var loader = new JsonInMemoryLoader();
    var storage = new JsonConfigurationStorage(loader);
    storage.SetIgnoreCertificateErrors(SelfHostedServer, true);
    storage.SetIgnoreCertificateErrors(SelfHostedServer, false);

    var endpoint = new KeeperEndpoint(new JsonConfigurationStorage(loader), SelfHostedServer);
    Assert.False(endpoint.IgnoreCertificateErrors);
  }

  [Fact]
  public void TestIgnoreCertificateErrorsKeepsServerKeys()
  {
    CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
    var loader = new JsonInMemoryLoader();
    var storage = new JsonConfigurationStorage(loader);
    storage.SetServerPublicKey(SelfHostedServer, 101, CryptoUtils.UnloadEcPublicKey(publicKey).Base64UrlEncode());
    storage.SetIgnoreCertificateErrors(SelfHostedServer, true);

    var endpoint = new KeeperEndpoint(new JsonConfigurationStorage(loader), SelfHostedServer);
    Assert.True(endpoint.IgnoreCertificateErrors);
    Assert.Equal(101, endpoint.ServerKeyId);
    var data = CryptoUtils.GenerateEncryptionKey();
    Assert.Equal(data, CryptoUtils.DecryptEc(endpoint.EncryptWithKeeperKey(data, 101), privateKey));
  }

  [Fact]
  public void TestMalformedKeyIsIgnored()
  {
    var serverConfiguration = new ServerConfiguration(SelfHostedServer)
    {
      ServerKeyId = 101
    };
    serverConfiguration.PublicKeys.Put(new ServerPublicKeyConfiguration(101)
    {
      PublicKey = "bm90IGEga2V5"
    });
    IKeeperConfiguration configuration = new KeeperConfiguration();
    configuration.Servers.Put(serverConfiguration);

    var endpoint = new KeeperEndpoint(new InMemoryConfigurationStorage(configuration), SelfHostedServer);
    Assert.Equal(7, endpoint.ServerKeyId);
  }
}
