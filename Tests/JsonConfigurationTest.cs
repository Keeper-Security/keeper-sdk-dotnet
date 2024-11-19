using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Xunit;

namespace Tests;

public class JsonInMemoryLoader: IJsonConfigurationLoader
{
    private byte[] _data;
    public byte[] LoadJson()
    {
        return _data;
    }

    public void StoreJson(byte[] json)
    {
        _data = json;
    }
    
    public byte[] Data => _data;
}

public class JsonConfigurationTest
{
  [Fact]
  public void TestJsonLoader()
  {
    var loader = new JsonInMemoryLoader();
    loader.StoreJson(Encoding.UTF8.GetBytes(ConfigJson));
    var jsonStorage = new JsonConfigurationStorage(loader);
    var configuration = jsonStorage.Get();
    Assert.Equal(ServerName,configuration.LastServer);
    Assert.Equal(UserName, configuration.LastLogin);
    var uc = configuration.Users.Get(UserName);
    Assert.NotNull(uc);
    Assert.Equal(uc.Username, uc.Id);
    Assert.Equal(UserName, uc.Username);
    Assert.Equal(UserPassword, uc.Password);
    Assert.Equal(ServerName, uc.Server);
    Assert.NotNull(uc.LastDevice);
    Assert.Equal(DeviceToken, uc.LastDevice.DeviceToken);
    var dc = configuration.Devices.Get(DeviceToken);
    Assert.NotNull(dc);
    Assert.Equal(dc.DeviceToken, dc.Id);
    Assert.Equal(DeviceToken, dc.DeviceToken);
    Assert.Equal(dc.DeviceKey, "FrbPZYhfuch-qZR2wWgTIBa0FH0VimVm2hZwbX5BRPU".Base64UrlDecode());
    Assert.NotNull(dc.ServerInfo);
    var dsc = dc.ServerInfo.Get(ServerName);
    Assert.NotNull(dsc);
    Assert.Equal(ServerName, dsc.Server);
    Assert.Equal("62hNPvSGupRy62fyllHx2Q", dsc.CloneCode);
    var sc = configuration.Servers.Get(ServerName);
    Assert.NotNull(sc);
    Assert.Equal(ServerName, sc.Server);
    Assert.Equal(sc.Server, sc.Id);
    Assert.Equal(13, sc.ServerKeyId);
  }

  [Fact]
  public void TestJsonStore()
  {
    var loader = new JsonInMemoryLoader();
    loader.StoreJson(Encoding.UTF8.GetBytes(ConfigJson));
    var jsonStorage = new JsonConfigurationStorage(loader);
    var configuration = jsonStorage.Get();
    var uc = configuration.Users.Get(UserName);
    Assert.NotNull(uc);
    configuration.LastServer = UserName;
    configuration.LastLogin = ServerName;
    var dc = configuration.Devices.Get(DeviceToken);
    Assert.NotNull(dc);
    var newDeviceToken = DeviceToken.Reverse().ToString();
    var newPublicKey = dc.DeviceKey.Reverse().ToArray();
    var ndc = new DeviceConfiguration(newDeviceToken)
    {
      DeviceKey = newPublicKey
    };
    configuration.Devices.Put(ndc);
    configuration.Devices.Delete(DeviceToken);
    jsonStorage.Put(configuration);
    
    configuration = jsonStorage.Get();
    Assert.Equal(UserName, configuration.LastServer);
    Assert.Equal(ServerName, configuration.LastLogin);
    dc = configuration.Devices.Get(DeviceToken);
    Assert.Null(dc);
    dc = configuration.Devices.Get(newDeviceToken);
    Assert.NotNull(dc);
    Assert.Equal(dc.DeviceKey, newPublicKey);
  }

  [Fact]
  public void TestNotParsedValues()
  {
    var loader = new JsonInMemoryLoader();
    loader.StoreJson(Encoding.UTF8.GetBytes(ConfigJson));
    var jsonStorage = new JsonConfigurationStorage(loader);
    var configuration = jsonStorage.Get();
    configuration.LastServer = "";
    configuration.LastLogin = "";
    configuration.Devices.Delete(DeviceToken);
    jsonStorage.Put(configuration);

    var a = JsonUtils.ParseJson<A>(loader.Data);
    Assert.NotNull(a);
    Assert.False(a.Security);
    Assert.NotNull(a.Users);
    Assert.Single(a.Users);
    Assert.True(a.Users[0].VaultOnly);
  }

  [DataContract]
  public class B
  {
    [DataMember(Name="vault_only")]
    public bool VaultOnly { get; set; }
  }

  [DataContract]
  public class A
  {
    [DataMember(Name = "security")]
    public bool Security { get; set; }
    
    [DataMember(Name = "users")]
    public B[] Users { get; set; }
  }

  private const string ServerName = "company.com";
  private const string UserName = "user@company.com";
  private const string UserPassword = "password";
  private const string DeviceToken = "0_XjvsDFnN2PaZSfKThADQ924HGE4dfvedNu15uJldJeHA";

  private const string ConfigJson = 
    """
    {
      "security": false,
      "devices": [
        {
          "device_token": "0_XjvsDFnN2PaZSfKThADQ924HGE4dfvedNu15uJldJeHA",
          "private_key": "FrbPZYhfuch-qZR2wWgTIBa0FH0VimVm2hZwbX5BRPU",
          "server_info": [
            {
              "clone_code": "62hNPvSGupRy62fyllHx2Q",
              "server": "company.com"
            }
          ]
        }
      ],
      "last_login": "user@company.com",
      "last_server": "company.com",
      "servers": [
        {
          "server": "company.com",
          "server_key_id": 13
        }
      ],
      "users": [
        {
          "last_device": {
            "device_token": "0_XjvsDFnN2PaZSfKThADQ924HGE4dfvedNu15uJldJeHA"
          },
          "server": "company.com",
          "password": "password",
          "user": "user@company.com",
          "vault_only": true
        }
      ]
    }
    """;
}