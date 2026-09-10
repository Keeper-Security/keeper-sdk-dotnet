#requires -Version 5.1

# Sample batch JSON for NSF PowerShell commands.
# Values are placeholders only (example.com emails, Replace-With-Your-Password, REPLACE_WITH_* UIDs).
# Do not put real secrets in sample files checked into source control.

# Placeholder JSON for New-KeeperNSFRecords / -DownloadSampleRecords.
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
      "notes": "Standard login record. Replace credentials before importing.",
      "folders": [
        { "folder": "REPLACE_WITH_NSF_FOLDER_UID_OR_NAME" }
      ]
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
      "notes": "Payment card record (placeholders only — replace before import)",
      "custom_fields": {
        "$paymentCard": {
          "cardNumber": "REPLACE_WITH_CARD_NUMBER",
          "cardExpirationDate": "MM/YYYY",
          "cardSecurityCode": "REPLACE_WITH_CVV"
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
          "routingNumber": "REPLACE_WITH_ROUTING_NUMBER",
          "accountNumber": "REPLACE_WITH_ACCOUNT_NUMBER"
        }
      }
    }
  ]
}
'@
}

# Placeholder JSON for Set-KeeperNSFRecords / -DownloadSampleRecords (update batch).
function Get-KeeperNSFBatchUpdateSampleJson {
    @'
{
  "records": [
    {
      "uid": "REPLACE_WITH_EXISTING_RECORD_UID_1",
      "title": "Batch Update Demo - Login",
      "$type": "login",
      "login": "updated.login@example.com",
      "password": "Replace-With-Your-Password",
      "login_url": "https://portal.example.com",
      "notes": "Updated via NSF batch update"
    },
    {
      "uid": "REPLACE_WITH_EXISTING_RECORD_UID_2",
      "title": "Batch Update Demo - Title Only",
      "notes": "Only title and notes changed; fields omitted are left as-is"
    },
    {
      "uid": "REPLACE_WITH_EXISTING_RECORD_UID_3",
      "$type": "databaseCredentials",
      "login": "db_app_user",
      "password": "Replace-With-Your-Password",
      "custom_fields": {
        "$host": { "hostName": "192.168.1.20", "port": "1433" },
        "$databaseType": "sqlServer"
      }
    }
  ]
}
'@
}

# Placeholder JSON for Share-KeeperNSFRecords / -DownloadSampleShares.
function Get-KeeperNSFShareBatchSampleJson {
    @'
{
  "shares": [
    {
      "uid": "REPLACE_WITH_RECORD_UID_1",
      "email": "colleague@example.com",
      "role": "viewer"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_2",
      "email": "colleague@example.com",
      "role": "content-manager",
      "expire_in": "30d"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_1",
      "email": "another.user@example.com",
      "role": "viewer",
      "expire_at": "2027-01-01T00:00:00Z"
    }
  ]
}
'@
}

# Placeholder JSON for Unshare-KeeperNSFRecords / -DownloadSampleUnshares.
function Get-KeeperNSFUnshareBatchSampleJson {
    @'
{
  "unshares": [
    {
      "uid": "REPLACE_WITH_RECORD_UID_1",
      "email": "colleague@example.com"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_2",
      "email": "colleague@example.com"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_1",
      "email": "another.user@example.com"
    }
  ]
}
'@
}

# Placeholder JSON for Remove-KeeperNSFRecords / -DownloadSampleRemovals.
function Get-KeeperNSFRemoveBatchSampleJson {
    @'
{
  "removals": [
    {
      "uid": "REPLACE_WITH_RECORD_UID_1",
      "operation": "owner-trash"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_2",
      "folder": "REPLACE_WITH_FOLDER_UID",
      "operation": "folder-trash"
    },
    {
      "uid": "REPLACE_WITH_RECORD_UID_3",
      "folder": "REPLACE_WITH_FOLDER_UID",
      "operation": "unlink"
    }
  ]
}
'@
}

# Placeholder JSON for New-KeeperNSFFolders / -DownloadSampleFolders.
function Get-KeeperNSFFolderBatchSampleJson {
    @'
{
  "folders": [
    {
      "name": "Batch Demo - Root Folder",
      "color": "#4A90D9",
      "inherit_permissions": true
    },
    {
      "name": "Batch Demo - Child Folder",
      "parent": "REPLACE_WITH_PARENT_FOLDER_UID",
      "color": "#33FF57",
      "inherit_permissions": true
    },
    {
      "name": "Batch Demo - No Inherit",
      "parent": "REPLACE_WITH_PARENT_FOLDER_UID",
      "inherit_permissions": false
    }
  ]
}
'@
}

# Placeholder JSON for Set-KeeperNSFFolders / -DownloadSampleFolders (update batch).
function Get-KeeperNSFFolderUpdateBatchSampleJson {
    @'
{
  "folders": [
    {
      "uid": "REPLACE_WITH_FOLDER_UID_1",
      "name": "Batch Update Demo - Renamed",
      "color": "#4A90D9"
    },
    {
      "uid": "REPLACE_WITH_FOLDER_UID_2",
      "color": "none"
    },
    {
      "uid": "REPLACE_WITH_FOLDER_UID_3",
      "inherit_permissions": false
    }
  ]
}
'@
}

# Placeholder JSON for Remove-KeeperNSFFolders / -DownloadSampleFolders.
function Get-KeeperNSFFolderRemoveBatchSampleJson {
    @'
{
  "folders": [
    {
      "uid": "REPLACE_WITH_FOLDER_UID_1",
      "operation": "folder-trash"
    },
    {
      "uid": "REPLACE_WITH_FOLDER_UID_2",
      "operation": "folder-trash"
    },
    {
      "uid": "REPLACE_WITH_FOLDER_UID_3",
      "operation": "delete-permanent"
    }
  ]
}
'@
}

# Placeholder JSON for Share-KeeperNSFFolderAccesses / -DownloadSampleAccesses (grant).
function Get-KeeperNSFFolderAccessGrantBatchSampleJson {
    @'
{
  "accesses": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "user1@example.com",
      "role": "viewer"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "Engineering Team",
      "role": "content-manager"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_2",
      "accessor": "user2@example.com",
      "role": "share-manager",
      "expire_in": "30d"
    }
  ]
}
'@
}

# Placeholder JSON for Update-KeeperNSFFolderAccesses / -DownloadSampleAccesses.
function Get-KeeperNSFFolderAccessUpdateBatchSampleJson {
    @'
{
  "accesses": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "user1@example.com",
      "role": "content-manager"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "Engineering Team",
      "role": "full-manager",
      "expire_at": "2027-01-01T00:00:00Z"
    }
  ]
}
'@
}

# Placeholder JSON for Unshare-KeeperNSFFolderAccesses / -DownloadSampleAccesses (revoke).
function Get-KeeperNSFFolderAccessRevokeBatchSampleJson {
    @'
{
  "accesses": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "user1@example.com"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "accessor": "Engineering Team"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_2",
      "accessor": "user2@example.com"
    }
  ]
}
'@
}

# Placeholder JSON for Link-KeeperNSFRecords / -DownloadSampleLinks.
function Get-KeeperNSFFolderRecordLinkBatchSampleJson {
    @'
{
  "links": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "record_uid": "REPLACE_WITH_RECORD_UID_1"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "record_uid": "REPLACE_WITH_RECORD_UID_2"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_2",
      "record_uid": "REPLACE_WITH_RECORD_UID_3"
    }
  ]
}
'@
}

# Placeholder JSON for Unlink-KeeperNSFRecords / -DownloadSampleUnlinks.
function Get-KeeperNSFFolderRecordUnlinkBatchSampleJson {
    @'
{
  "unlinks": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "record_uid": "REPLACE_WITH_RECORD_UID_1"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_2",
      "record_uid": "REPLACE_WITH_RECORD_UID_3"
    }
  ]
}
'@
}

# Placeholder JSON for Move-KeeperNSFRecords / -DownloadSampleMoves.
function Get-KeeperNSFRecordMoveBatchSampleJson {
    @'
{
  "moves": [
    {
      "source_folder_uid": "REPLACE_WITH_SOURCE_FOLDER_UID_1",
      "target_folder_uid": "REPLACE_WITH_TARGET_FOLDER_UID_1",
      "record_uid": "REPLACE_WITH_RECORD_UID_1"
    },
    {
      "source_folder_uid": "REPLACE_WITH_SOURCE_FOLDER_UID_1",
      "target_folder_uid": "REPLACE_WITH_TARGET_FOLDER_UID_2",
      "record_uid": "REPLACE_WITH_RECORD_UID_2"
    }
  ]
}
'@
}

# Placeholder JSON for Move-KeeperNSFFolders / -DownloadSampleMoves.
function Get-KeeperNSFFolderMoveBatchSampleJson {
    @'
{
  "moves": [
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_1",
      "target_parent_uid": "REPLACE_WITH_TARGET_PARENT_UID_1"
    },
    {
      "folder_uid": "REPLACE_WITH_FOLDER_UID_2",
      "target_parent_uid": "REPLACE_WITH_TARGET_PARENT_UID_2"
    }
  ]
}
'@
}
