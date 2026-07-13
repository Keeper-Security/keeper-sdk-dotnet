#requires -Version 5.1

function Get-KeeperNSFBatchSampleJson {
    @'
{
  "records": [
    {
      "title": "Batch Demo - Login",
      "$type": "login",
      "login": "batch.demo.login@example.com",
      "password": "Replace-With-Your-Password",
      "login_url": "https://portal.example.com",
      "notes": "Standard login record. Replace credentials before importing."
    },
    {
      "title": "Batch Demo - Legacy General",
      "login": "legacy.user@example.com",
      "password": "Replace-With-Your-Password",
      "login_url": "https://legacy.example.com",
      "notes": "Legacy/general record (no $type)"
    },
    {
      "title": "Batch Demo - Bank Card",
      "$type": "bankCard",
      "notes": "Payment card record",
      "custom_fields": {
        "$paymentCard": {
          "cardNumber": "4111111111111111",
          "cardExpirationDate": "04/2028",
          "cardSecurityCode": "123"
        }
      }
    },
    {
      "title": "Batch Demo - Database Credentials",
      "$type": "databaseCredentials",
      "login": "db_app_user",
      "password": "Replace-With-Your-Password",
      "notes": "SQL Server application login",
      "custom_fields": {
        "$host": {
          "hostName": "192.168.1.10",
          "port": "1433"
        },
        "$databaseType": "sqlServer"
      }
    },
    {
      "title": "Batch Demo - Server Credentials",
      "$type": "serverCredentials",
      "login": "admin",
      "password": "Replace-With-Your-Password",
      "notes": "Linux admin account",
      "custom_fields": {
        "$host": {
          "hostName": "server.example.com",
          "port": "22"
        }
      }
    },
    {
      "title": "Batch Demo - SSH Keys",
      "$type": "sshKeys",
      "notes": "SSH key pair (demo placeholders - replace with real keys for production)",
      "custom_fields": {
        "$keyPair": {
          "publicKey": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0=",
          "privateKey": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="
        }
      }
    },
    {
      "title": "Batch Demo - Address",
      "$type": "address",
      "notes": "Office location",
      "custom_fields": {
        "$address:Work": {
          "street1": "123 Main Street",
          "street2": "Suite 400",
          "city": "San Jose",
          "state": "CA",
          "zip": "95110",
          "country": "US"
        }
      }
    },
    {
      "title": "Batch Demo - Contact",
      "$type": "contact",
      "notes": "Sample contact card",
      "custom_fields": {
        "$name": {
          "first": "Jane",
          "middle": "",
          "last": "Doe"
        },
        "$email": "jane.doe@example.com",
        "$phone:Mobile": {
          "region": "US",
          "number": "5551234567",
          "ext": "",
          "type": "mobile"
        }
      }
    },
    {
      "title": "Batch Demo - Secure Note",
      "$type": "secureNote",
      "notes": "Record-level notes",
      "custom_fields": {
        "$note": "Sensitive information stored in the secure note field."
      }
    },
    {
      "title": "Batch Demo - Bank Account",
      "$type": "bankAccount",
      "notes": "Business checking account",
      "custom_fields": {
        "$bankAccount": {
          "accountType": "Checking",
          "routingNumber": "021000021",
          "accountNumber": "1234567890"
        }
      }
    }
  ]
}
'@
}
