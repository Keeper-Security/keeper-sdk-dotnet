using KeeperSecurity.Vault;
using System.Linq;
using Xunit;

namespace Tests;

public class VaultTest
{
    [Fact]
    public void TestHostRecordFieldSerialization()
    {
        IFieldTypeSerialize serializer;
        var hostField = new FieldTypeHost();
        serializer = hostField;

        string value = "keepersecurity.com:555";
        serializer.SetValueAsString(value);
        Assert.Equal("keepersecurity.com", hostField.HostName);
        Assert.Equal("555", hostField.Port);
        Assert.Equal(value, serializer.GetValueAsString());

        value = "keepersecurity.com";
        serializer.SetValueAsString(value);
        Assert.Equal("keepersecurity.com", hostField.HostName);
        Assert.Equal("", hostField.Port);
        Assert.Equal(value, serializer.GetValueAsString());

        value = ":555";
        serializer.SetValueAsString(value);
        Assert.Equal("", hostField.HostName);
        Assert.Equal("555", hostField.Port);
        Assert.Equal(value, serializer.GetValueAsString());

        value = "";
        serializer.SetValueAsString(value);
        Assert.Equal("", hostField.HostName);
        Assert.Equal("", hostField.Port);
        Assert.Equal(value, serializer.GetValueAsString());
    }

    [Fact]
    public void TestAddressRecordFieldSerialization()
    {
        IFieldTypeSerialize serializer;
        var addressField = new FieldTypeAddress();
        serializer = addressField;

        var value = "123 Main St., Middle Nowhere Town, CA 12345";
        serializer.SetValueAsString(value);
        Assert.Equal("123 Main St.", addressField.Street1);
        Assert.Equal("", addressField.Street2);
        Assert.Equal("Middle Nowhere Town", addressField.City);
        Assert.Equal("CA", addressField.State);
        Assert.Equal("12345", addressField.Zip);
        Assert.Equal(value.Replace(" ", ""), serializer.GetValueAsString().Replace(" ", ""));
    }

    [Fact]
    public void TestPhoneRecordFieldSerialization()
    {
        IFieldTypeSerialize serializer;
        var phoneField = new FieldTypePhone();
        serializer = phoneField;

        var value = "Mobile: +1 (916)555-1234";
        serializer.SetValueAsString(value);
        Assert.Equal("Mobile", phoneField.Type);
        Assert.Equal("+1", phoneField.Region);
        Assert.Equal("(916)555-1234", phoneField.Number);
        Assert.Equal("", phoneField.Ext);
        Assert.Equal(value.Replace(" ", ""), serializer.GetValueAsString().Replace(" ", ""));
    }

    [Fact]
    public void TestNameRecordFieldSerialization()
    {
        IFieldTypeSerialize serializer;
        var phoneField = new FieldTypeName();
        serializer = phoneField;

        var value = "Lastname, Firstname";
        serializer.SetValueAsString(value);
        Assert.Equal("Lastname", phoneField.Last);
        Assert.Equal("Firstname", phoneField.First);

        value = "Firstname Lastname";
        serializer.SetValueAsString(value);
        Assert.Equal("Lastname", phoneField.Last);
        Assert.Equal("Firstname", phoneField.First);

        value = serializer.GetValueAsString();
        var phoneField1 = new FieldTypeName();
        serializer = phoneField1;
        serializer.SetValueAsString(value);
        Assert.Equal(phoneField.Last, phoneField1.Last);
        Assert.Equal(phoneField.First, phoneField1.First);
    }


    [Fact]
    public void TestParseFolderPath()
    {
        var path = BatchVaultOperations.ParseFolderPath("Folder 1").ToArray();
        Assert.Single(path);
        Assert.Equal("Folder 1", path[0]);

        path = BatchVaultOperations.ParseFolderPath("\\Folder 1\\").ToArray();
        Assert.Single(path);
        Assert.Equal("Folder 1", path[0]);

        path = BatchVaultOperations.ParseFolderPath("\\Folder 1\\2").ToArray();
        Assert.Equal(2, path.Length);
        Assert.Equal("Folder 1", path[0]);
        Assert.Equal("2", path[1]);

        path = BatchVaultOperations.ParseFolderPath("1\\Folder 1\\2").ToArray();
        Assert.Equal(3, path.Length);
        Assert.Equal("1", path[0]);
        Assert.Equal("Folder 1", path[1]);
        Assert.Equal("2", path[2]);

        path = BatchVaultOperations.ParseFolderPath("1\\\\Folder 1\\\\2").ToArray();
        Assert.Single(path);
        Assert.Equal("1\\Folder 1\\2", path[0]);

        path = BatchVaultOperations.ParseFolderPath("1\\\\Fol\\der 1\\\\2").ToArray();
        Assert.Equal(2, path.Length);
        Assert.Equal("1\\Fol", path[0]);
        Assert.Equal("der 1\\2", path[1]);

        path = BatchVaultOperations.ParseFolderPath("Folder 1\\\\").ToArray();
        Assert.Single(path);
        Assert.Equal("Folder 1\\", path[0]);

        path = BatchVaultOperations.ParseFolderPath("\\\\Folder 1\\\\").ToArray();
        Assert.Single(path);
        Assert.Equal("\\Folder 1\\", path[0]);

        path = BatchVaultOperations.ParseFolderPath("Folder 1\\Folder 2").ToArray();
        Assert.Equal(2, path.Length);
        Assert.Equal("Folder 1", path[0]);
        Assert.Equal("Folder 2", path[1]);

        path = BatchVaultOperations.ParseFolderPath("Folder 1\\Folder 2\\Folder 3\\Folder 4").ToArray();
        Assert.Equal(4, path.Length);
        Assert.Equal("Folder 1", path[0]);
        Assert.Equal("Folder 2", path[1]);
        Assert.Equal("Folder 3", path[2]);
        Assert.Equal("Folder 4", path[3]);

    }
}