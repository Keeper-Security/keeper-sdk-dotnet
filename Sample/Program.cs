//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2021 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using KeeperSecurity.Utils;
using Sample.RecordsExamples;
using Sample.AttachmentsExamples;
using Enterprise;
using System.Collections.Generic;



namespace Sample
{
    internal static class Program
    {
        private static async Task Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };
            try
            {
                // Authenticate once from Main - all examples share this vault
                var vault = await AuthenticateAndGetVault.GetVault(enablePersistentLogin: true, autoKeepAlive: false, usePushNotifications: true);
                // var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Could not authenticate. Exiting.");
                    return;
                }

                // var getRecords = new GetRecordsExample();
                // await getRecords.GetRecordsWithName( "Google");

                // // Shared folder without full sync: use ResolveAuthAsync so auth matches a prior GetVault in the same run.
                // var authStep = await AuthenticateAndGetVault.ResolveAuthAsync(enablePersistentLogin: true, autoKeepAlive: true, usePushNotifications : false);
                // await SharedFolderExamples.ShareFolderSkipSyncExample.PutTeamToSharedFolder(
                //     authStep, "<shared_folder_uid>", "<team_name_or_uid>", new SharedFolderUserOptions
                //     {
                //         ManageRecords = false,
                //         ManageUsers = true,
                //         Expiration = DateTimeOffset.Now.AddMinutes(10)
                //     });

                // // Add Record Example
                // await AddRecordExample.AddRecord(vault, name: "<recordName_here>", type: "bankCard", folderUid: "<folderUid_here>");

                // // Passphrase Example (SDK PassphraseGenerator + UpdateRecord)
                // await PassphraseRecordExample.UpdateRecordPassphrase(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     options: new PassphraseGenerationOptions
                //     {
                //         WordCount = 5,
                //         Separator = "-",
                //         UseCaps = true,
                //         UseDigits = true
                //     });

                // // Update Record Example
                // await UpdateRecordExample.UpdateRecord(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     newTitle: "UpdatedAddEx2",
                //     newRecordType: "serverCredentials"
                // );

                // // Delete Record Example
                // await DeleteRecordExample.DeleteRecord(vault, recordUid: "<recordUid_here>");

                // // List Records Example
                // await ListRecordExample.ListAllRecords(vault);

                // // Get Record Details Example
                // var getRecord = new GetRecordExample();
                // await getRecord.GetRecordDetails(vault, recordUid: "<recordUid_here>");

                // // Get Record History Example
                // var getRecordHistory = new GetRecordHistoryExample();
                // await getRecordHistory.GetRecordHistory1(vault, recordUid: "<recordUid_here>");

                // // Upload Attachment Example
                // await UploadAttachmentExample.UploadAttachment(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     filePath: "<file_path_here>",
                //     thumbnailPath: "<thumbnail_path_here>"
                // );

                // // Download Attachment Example
                // await DownloadAttachmentExample.DownloadAttachment(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     attachmentIdentifier: "<attachment id or name or title>",
                //     destinationPath: "<destination file path here>"
                // );

                // // Remove Attachment Example
                // await RemoveAttachmentExample.RemoveAttachment(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     attachmentId: "<attachment_id_or_name_or_title>"
                // );

                // // List Folders Example
                // await FoldersExample.ListFolderExample.ListFolder(vault);

                // // Move Folder Example
                // await FoldersExample.MoveFolderExample.MoveExistingFolder(
                //     vault,
                //     folderUid: "<folderUid_here>",
                //     newParentFolderUid: "<newParentFolderUid_here>",
                //     link: false
                // );

                // // Remove Folder Example
                // await FoldersExample.RemoveFolderExample.RemoveFolder(
                //     vault,
                //     folderUid: "<folderUid_here>"
                // );

                // // List Keeper NSF Records Example
                // await KeeperNSFExamples.ListKeeperNSFRecordsExample.ListAll(vault);

                // // Get Keeper NSF Record Example
                // await KeeperNSFExamples.GetKeeperNSFRecordExample.ShowDetails(
                //     vault,
                //     recordUidOrTitle: "<recordUid_or_title_here>"
                // );

                // // Create Keeper NSF Record Example
                // await KeeperNSFExamples.CreateKeeperNSFRecordExample.Create(
                //     vault,
                //     title: "TestNSFrec1",
                //     recordType: "login",
                //     folderUid: "",
                //     notes: "hello1",
                //     fields: new Dictionary<string, object>
                //     {
                //         { "login", "a1@examples" },
                //         { "password", "A123" }
                //     }
                // );

                // Create Keeper NSF Records (batch) Example - all common record types
                // await KeeperNSFExamples.CreateKeeperNSFRecordsBatchExample.CreateBatch(
                //     vault,
                //     defaultFolderUid: "");

                // Or load the embedded sample JSON (same as PowerCommander -DownloadSampleRecords):
                // await KeeperNSFExamples.CreateKeeperNSFRecordsBatchExample.CreateBatchFromSampleFile(
                //     vault,
                //     defaultFolderUid: "mGeYFviQ9Vwr9dm4302_CQ");
                //
                // PowerCommander: nsf-records-add -DownloadSampleRecords
                // PowerCommander: nsf-records-add -FilePath .\nsf-records-batch.sample.json

                // // Update Keeper NSF Record Example
                // await KeeperNSFExamples.UpdateKeeperNSFRecordExample.Update(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     title: "<newTitle_here>",
                //     recordType: "login",
                //     notes: "<newNotes_here>",
                //     fields: new Dictionary<string, object>
                //     {
                //         { "login", "<updatedUsername_here>" },
                //         { "password", "<updatedPassword_here>" }
                //     }
                // );

                // // Update Keeper NSF Records (batch) Example
                // await KeeperNSFExamples.UpdateKeeperNSFRecordsBatchExample.UpdateBatch(
                //     vault,
                //     new[]
                //     {
                //         new KeeperNSFRecordUpdateRequest
                //         {
                //             RecordUid = "<recordUid_1>",
                //             Title = "Updated Title 1",
                //             Fields = new Dictionary<string, object> { { "login", "a@example.com" } },
                //         },
                //         new KeeperNSFRecordUpdateRequest
                //         {
                //             RecordUid = "<recordUid_2>",
                //             Notes = "Updated via batch",
                //         },
                //     });
                //
                // PowerCommander: nsf-records-update -DownloadSampleRecords
                // PowerCommander: nsf-records-update -FilePath .\nsf-records-update-batch.sample.json

                // // Remove Keeper NSF Record Example (dryRun defaults to true — set false to confirm)
                // await KeeperNSFExamples.RemoveKeeperNSFRecordExample.Remove(
                //     vault,
                //     recordUidOrTitle: "<recordUid_or_title_here>",
                //     folderUidOrName: "<folderUid_or_name_here>",
                //     operation: KeeperNSFRecordRemoveOperation.FolderTrash,
                //     dryRun: true
                // );

                // // Remove Keeper NSF Records (batch) Example (dryRun defaults to true — set false to confirm)
                // await KeeperNSFExamples.RemoveKeeperNSFRecordsBatchExample.RemoveBatch(
                //     vault,
                //     KeeperNSFExamples.RemoveKeeperNSFRecordsBatchExample.BuildSampleRemovals(),
                //     dryRun: true
                // );
                //
                // PowerCommander: nsf-records-rm -DownloadSampleRemovals
                // PowerCommander: nsf-records-rm -FilePath .\nsf-records-remove-batch.sample.json

                // // List Keeper NSF Folders Example
                // await KeeperNSFExamples.ListKeeperNSFFoldersExample.ListAll(vault);

                // // Create Keeper NSF Folder Example
                // await KeeperNSFExamples.CreateKeeperNSFFolderExample.Create(
                //     vault,
                //     folderName: "<folderName_here>",
                //     parentFolderUid: "<parentFolderUid_here>",
                //     color: "#FF5733",
                //     inheritPermissions: true
                // );

                // // Create Keeper NSF Folders (batch) Example
                // await KeeperNSFExamples.CreateKeeperNSFFoldersBatchExample.CreateBatch(
                //     vault,
                //     KeeperNSFExamples.CreateKeeperNSFFoldersBatchExample.BuildSampleFolders()
                // );
                //
                // PowerCommander: nsf-mkdirs -DownloadSampleFolders
                // PowerCommander: nsf-mkdirs -FilePath .\nsf-folders-batch.sample.json

                // // Update Keeper NSF Folder Example
                // await KeeperNSFExamples.UpdateKeeperNSFFolderExample.RenameOrRecolor(
                //     vault,
                //     folderUidOrName: "<folderUid_or_name_here>",
                //     newName: "<newFolderName_here>",
                //     color: "#33FF57"
                // );

                // // Update Keeper NSF Folders (batch) Example
                // await KeeperNSFExamples.UpdateKeeperNSFFoldersBatchExample.UpdateBatch(
                //     vault,
                //     KeeperNSFExamples.UpdateKeeperNSFFoldersBatchExample.BuildSampleUpdates()
                // );
                //
                // PowerCommander: nsf-folders-update -DownloadSampleFolders
                // PowerCommander: nsf-folders-update -FilePath .\nsf-folders-update-batch.sample.json

                // // Remove Keeper NSF Folder Example (dryRun defaults to true — set false to confirm)
                // await KeeperNSFExamples.RemoveKeeperNSFFolderExample.Remove(
                //     vault,
                //     folderUidOrName: "<folderUid_or_name_here>",
                //     operation: KeeperNSFFolderRemoveOperation.FolderTrash,
                //     dryRun: true
                // );

                // // Remove Keeper NSF Folders (batch) Example
                // await KeeperNSFExamples.RemoveKeeperNSFFoldersBatchExample.RemoveBatch(
                //     vault,
                //     KeeperNSFExamples.RemoveKeeperNSFFoldersBatchExample.BuildSampleRemovals(),
                //     dryRun: true
                // );
                //
                // PowerCommander: nsf-rmdirs -DownloadSampleFolders
                // PowerCommander: nsf-rmdirs -FilePath .\nsf-folders-remove-batch.sample.json

                // // Link Keeper NSF Record to Folder Example
                // await KeeperNSFExamples.LinkKeeperNSFRecordToFolderExample.Link(
                //     vault,
                //     recordUidOrTitle: "<recordUid_or_title_here>",
                //     folderUidOrName: "<folderUid_or_name_here>"
                // );

                // // Link Keeper NSF Records to Folders (batch) Example
                // await KeeperNSFExamples.LinkKeeperNSFRecordsToFoldersBatchExample.LinkBatch(
                //     vault,
                //     KeeperNSFExamples.LinkKeeperNSFRecordsToFoldersBatchExample.BuildSampleLinks()
                // );
                //
                // PowerCommander: nsf-lns -DownloadSampleLinks
                // PowerCommander: nsf-lns -FilePath .\nsf-folder-records-link-batch.sample.json

                // // Unlink Keeper NSF Records from Folders (batch) Example
                // await KeeperNSFExamples.UnlinkKeeperNSFRecordsFromFoldersBatchExample.UnlinkBatch(
                //     vault,
                //     KeeperNSFExamples.UnlinkKeeperNSFRecordsFromFoldersBatchExample.BuildSampleUnlinks()
                // );
                //
                // PowerCommander: nsf-unln -DownloadSampleUnlinks
                // PowerCommander: nsf-unln -FilePath .\nsf-folder-records-unlink-batch.sample.json

                // // Keep Keeper NSF Record in Folder Example
                // await KeeperNSFExamples.KeepKeeperNSFRecordInFolderExample.KeepInFolder(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     keepFolderUid: "<folderUid_here>"
                // );

                // // Get Keeper NSF Shortcuts Example
                // await KeeperNSFExamples.GetKeeperNSFShortcutsExample.ListShortcuts(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     folderUid: "<folderUid_here>"
                // );

                // // Share Keeper NSF Record Example
                // await KeeperNSFExamples.ShareKeeperNSFRecordExample.Share(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     userEmail: "<userEmail_here>",
                //     role: "viewer"
                // );

                // // Share Keeper NSF Records (batch) Example
                // await KeeperNSFExamples.ShareKeeperNSFRecordsBatchExample.ShareBatch(
                //     vault,
                //     KeeperNSFExamples.ShareKeeperNSFRecordsBatchExample.BuildSampleShares()
                // );

                // // Unshare Keeper NSF Record Example
                // await KeeperNSFExamples.UnshareKeeperNSFRecordExample.Unshare(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     userEmail: "<userEmail_here>"
                // );

                // // Unshare Keeper NSF Records (batch) Example
                // await KeeperNSFExamples.UnshareKeeperNSFRecordsBatchExample.UnshareBatch(
                //     vault,
                //     KeeperNSFExamples.UnshareKeeperNSFRecordsBatchExample.BuildSampleUnshares()
                // );

                // // Transfer Keeper NSF Record Ownership Example
                // await KeeperNSFExamples.TransferKeeperNSFRecordOwnershipExample.Transfer(
                //     vault,
                //     recordUidOrTitles: new[] { "<recordUid_or_title_here>" },
                //     newOwnerEmail: "<newOwnerEmail_here>"
                // );

                // // Grant Keeper NSF Folder Access Example
                // await KeeperNSFExamples.GrantKeeperNSFFolderAccessExample.Grant(
                //     vault,
                //     folderUid: "<folderUid_here>",
                //     userEmail: "<userEmail_here>",
                //     role: "viewer"
                // );

                // // Grant Keeper NSF Folder Accesses (batch) Example
                // await KeeperNSFExamples.GrantKeeperNSFFolderAccessesBatchExample.GrantBatch(
                //     vault,
                //     KeeperNSFExamples.GrantKeeperNSFFolderAccessesBatchExample.BuildSampleGrants()
                // );
                //
                // PowerCommander: nsf-share-folders -DownloadSampleAccesses
                // PowerCommander: nsf-share-folders -FilePath .\nsf-folders-access-grant-batch.sample.json

                // // Update Keeper NSF Folder Accesses (batch) Example
                // await KeeperNSFExamples.UpdateKeeperNSFFolderAccessesBatchExample.UpdateBatch(
                //     vault,
                //     KeeperNSFExamples.UpdateKeeperNSFFolderAccessesBatchExample.BuildSampleUpdates()
                // );
                //
                // PowerCommander: nsf-update-folder-access -DownloadSampleAccesses
                // PowerCommander: nsf-update-folder-access -FilePath .\nsf-folders-access-update-batch.sample.json

                // // Revoke Keeper NSF Folder Access Example
                // await KeeperNSFExamples.RevokeKeeperNSFFolderAccessExample.Revoke(
                //     vault,
                //     folderUid: "<folderUid_here>",
                //     userEmail: "<userEmail_here>"
                // );

                // // Revoke Keeper NSF Folder Accesses (batch) Example
                // await KeeperNSFExamples.RevokeKeeperNSFFolderAccessesBatchExample.RevokeBatch(
                //     vault,
                //     KeeperNSFExamples.RevokeKeeperNSFFolderAccessesBatchExample.BuildSampleRevokes()
                // );
                //
                // PowerCommander: nsf-unshare-folders -DownloadSampleAccesses
                // PowerCommander: nsf-unshare-folders -FilePath .\nsf-folders-access-revoke-batch.sample.json

                // // Update Keeper NSF Record Permissions Example (dryRun defaults to true — set false to apply)
                // await KeeperNSFExamples.UpdateKeeperNSFRecordPermissionsExample.UpdatePermissions(
                //     vault,
                //     folderUid: "<folderUid_here>",
                //     action: "grant",
                //     role: "viewer",
                //     recursive: false,
                //     dryRun: true
                // );

                // // Create Shared Folder Example
                // var options = new SharedFolderOptions
                // {
                //     ManageRecords = true,
                //     ManageUsers = false,
                //     CanShare = true
                // };

                // await FoldersExample.CreateFolder.CreateNewFolder(
                //     vault,
                //     folderName: "NewFolderFromSDK",
                //     parentFolderUid: "<parentFolderUid_if_any>",
                //     sharedFolderOptions: options
                // );

                // // List Shared Folders Example
                // await SharedFolderExamples.ListSharedFolder.ListAllSharedFolders(vault);


                // // Change Record Permissions of a Shared Folder Example
                // var permissions = new SharedFolderRecordOptions
                // {
                //     CanEdit = true,
                //     CanShare = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(5)

                // };

                // await SharedFolderExamples.SharedFolderPermissions.ManageSharedFolderPermissions1(
                //     vault,
                //     sharedFolderUid: "<sharedFolderUid_here>",
                //     recordUid: "<recordUid_here>",
                //     permissionsOptions: permissions
                // );

                // Share Shared Folder to User Example
                // var userOptions = new SharedFolderUserOptions
                // {
                //     ManageRecords = true,
                //     ManageUsers = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await SharedFolderToUserExamples.ShareFolderToUser.ShareFolderWithUser(
                //     vault,
                //     sharedFolderUid: "<sharedFolderUid_here>",
                //     userId: "<userEmail_here>",
                //     userType: UserType.User,
                //     options: userOptions
                // );

                // // One-Time Share Record Example
                // await OneTimeShareExamples.OneTimeShare.ShareRecordOneTime(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     expireIn: TimeSpan.FromMinutes(2),
                //     shareName: "<shareName_here>"
                // );

                // // List One-Time Shares for a Record Example
                // await OneTimeShareListExamples.OneTimeShareList.GetOneTimeShareList(
                //     vault,
                //     recordUid: "<recordUid_here>"
                // );

                // // One-Time Share Remove
                // await RemoveOneTimeShareExamples.RemoveOneTimeShare.RemoveOneTimeShareRecord(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     clientIds: new[] { "<clientId_here>" }
                // );

                // // Share Record to User Example
                // var shareOptions = new SharedFolderRecordOptions
                // {
                //     CanEdit = true,
                //     CanShare = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await ShareRecordExamples.ShareRecordToUser.ShareRecordToUserWithPermissions(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>",
                //     options: shareOptions
                // );

                // // Remove User From Specified Record Example
                // await ShareRecordExamples.RevokeShareRecordToUser.RemoveShareRecordToUser(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // Remove User from All Shares Example
                // await ShareRecordExamples.RevokeAllSharesToUser.RemoveAllSharesToUser(
                //     vault,
                //     username: "<userEmail_here>"
                // );

                // // Transfer Ownership Example
                // await TransferOwnershipExamples.TransferOwnership.TransferRecordToUser(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // All RecordType Example
                // await RecordTypeExamples.RecordTypeInfoExample.RecordTypeInfo(vault);

                // // Specified Record Type Info Example
                // await RecordTypeExamples.RecordTypeInfoExample.RecordTypeInfo(
                //     vault,
                //     recordTypeName: "<recordTypeName_here>"
                // );

                // // Create RecordType Example
                // var recordTypeData = "{\"$id\":\"SDKEX1\",\"description\":\"My SDK record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}";
                // await RecordTypeExamples.CreateRecordTypeExample.CreateRecordType(
                //     vault,
                //     recordTypeData: recordTypeData
                // );

                // // Update RecordType Example
                // var updateRecordTypeData = "{\"$id\":\"SDKEX0\",\"description\":\"My SDK First record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}";
                // await RecordTypeExamples.UpdateRecordTypeExample.UpdateRecordType(
                //     vault,
                //     recordTypeId: "<recordTypeId_here>",
                //     recordTypeData: updateRecordTypeData
                // );

                // // Delete RecordType Example
                // await RecordTypeExamples.DeleteRecordTypeExample.DeleteRecordType(
                //     vault,
                //     recordTypeId: "<recordTypeId_here>"
                // );

                // // Import Example
                // string filename = @"C:\<SomePath>\Test.json";
                // var json = File.ReadAllText(filename);
                // var result = await ImportExportExamples.ImportExample.Import(vault, json);

                // // Export to Json Example
                // IEnumerable<string> recordUids = new List<string>
                //     {
                //         "<recordUId_here>",
                //         "<recordUId_here>"
                //     };
                // await ImportExportExamples.ExportToJsonExample.ExportToJson(
                //     vault,
                //     recordUids: recordUids,
                //     includeSharedFolders: true,
                //     logger: null
                // );

                // // Export to File Example
                // IEnumerable<string> recordUids1 = new List<string>
                //     {
                //          "<recordUId_here>",
                //          "<recordUId_here>"
                //     };
                // await ImportExportExamples.ExportToFileExample.ExportToFile(
                //     vault,
                //     filename: "<filePath_here>",
                //     recordUids: recordUids1,
                //     includeSharedFolders: true,
                //     logger: null
                // );

                // // DownloadMembership To FileObject Example
                // var options1 = new DownloadMembershipOptions
                // {
                //     FoldersOnly = true,
                //     ForceManageUsers = true,
                //     ForceManageRecords = true,
                //     SubFolderHandling = "flatten"   // or "ignore"
                // };

                // await ImportExportExamples.DownloadMembershipToFileObjectExample.DownloadMembershipToFileObject(
                //     vault,
                //     options1
                // );

                // // DownloadMembership To Json Example 
                // var options2 = new DownloadMembershipOptions
                // {
                //     FoldersOnly = true,
                //     ForceManageUsers = true,
                //     ForceManageRecords = true,
                //     SubFolderHandling = "flatten"   // or "ignore"
                // };

                // await ImportExportExamples.DownloadMembershipToJsonExample.DownloadToJson(
                //     vault,
                //     options2
                // );

                // // DownloadMembership To File Example 
                // var options3 = new DownloadMembershipOptions
                // {
                //     FoldersOnly = true,
                //     ForceManageUsers = true,
                //     ForceManageRecords = true,
                //     SubFolderHandling = "flatten"   // or "ignore"
                // };

                // await ImportExportExamples.DownloadMembershipToFileExample.DownloadToFile(
                //     vault,
                //     filename: "<filePath_here>",
                //     options3
                // );

                // // Merge DownloadMembership Example 
                // var options4 = new DownloadMembershipOptions
                // {
                //     FoldersOnly = true,
                //     ForceManageUsers = true,
                //     ForceManageRecords = true,
                //     SubFolderHandling = "flatten"   // or "ignore"
                // };

                // await ImportExportExamples.DownloadMembershipToMergeExample.MergeDownloadMembershipFile(
                //     vault,
                //     filename: "<filePath_here>",
                //     options4
                // );

                // // Load Record Type Example ---- issue not able to pass the input.
                // string jsonPath = @"C:\<path_to_file>\RecordType.json";
                // string loadRecordTypeData = File.ReadAllText(jsonPath);
                // await ImportExportExamples.LoadRecordTypeExample.LoadRecordType(
                //     vault,
                //     recordTypeData: loadRecordTypeData
                // );

                // // App Llist Example
                // await SecretManagerExamples.AppListExample.AppList(vault);

                // // App Create Example
                // await SecretManagerExamples.AppCreateExample.AppCreate(
                //     vault,
                //     applicationName: "<appName_here>"
                // );

                // // App View Example
                // await SecretManagerExamples.AppViewExample.AppView(
                //     vault,
                //     applicationUid: "<appUid_here>"
                // );

                // // App Delete Example
                // await SecretManagerExamples.AppDeleteExample.AppDelete(
                //     vault,
                //     applicationUid: "<appUid_here>"
                // );

                // // App Share Example
                // var userShareOptions = new SharedFolderUserOptions
                // {
                //     ManageRecords = true,
                //     ManageUsers = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await SecretManagerExamples.AppShareExample.AddUserToSharedFolder(
                //     vault,
                //     sharedFolderUid: "<shareFolderUid_here>",
                //     userId: "<userEmail_here>",
                //     userType: UserType.User,
                //     options: userShareOptions
                // );

                // var recordShareOptions = new SharedFolderRecordOptions
                // {
                //     CanEdit = true,
                //     CanShare = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await SecretManagerExamples.AppShareExample.ShareRecordToUser(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>",
                //     options: recordShareOptions
                // );

                // // App Un Share Example
                // await SecretManagerExamples.AppUnShareExample.RemoveUserToSharedFolder(
                //     vault,
                //     sharedFolderUid: "<recordUid_here>",
                //     userId: "<userEmail_here>",
                //     userType: UserType.User
                // );

                // await SecretManagerExamples.AppUnShareExample.RevokeShareToUser(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // Add Client Example
                // await SecretManagerExamples.AddClientExample.AddClient(
                //     vault,
                //     applicationId: "<appUid_here>",
                //     unlockIp: true,
                //     firstAccessExpireInMinutes: 60,
                //     accessExpiresInMinutes: null,
                //     name: "<clientName_here>",
                //     appClientType: Enterprise.AppClientType.General
                // );

                // List PAM Gateways Example
                await PAMExamples.GatewayExamples.ListGatewaysExample.ListGateways(
                    vault,
                    onlineOnly: false,
                    ignoreRouterDown: true,
                    verbose: false
                );

                // // Create PAM Gateway Example
                // await PAMExamples.GatewayExamples.CreateGatewayExample.CreateGateway(
                //     vault,
                //     gatewayName: "<gatewayName_here>",
                //     applicationId: "<ksmAppUid_or_title_here>",
                //     tokenExpiresInMinutes: 60,
                //     configInit: null   // or "json" / "b64" for initialized config
                // );

                // // Edit PAM Gateway Example
                // await PAMExamples.GatewayExamples.EditGatewayExample.EditGateway(
                //     vault,
                //     gatewayId: "<gatewayUid_or_name_here>",
                //     newName: "<newGatewayName_here>",
                //     nodeNameOrId: null   // optional: node ID or display name
                // );

                // // Set PAM Gateway Max Instances Example
                // await PAMExamples.GatewayExamples.SetGatewayMaxInstancesExample.SetMaxInstances(
                //     vault,
                //     gatewayId: "<gatewayUid_or_name_here>",
                //     maxInstances: 3
                // );

                // // Remove PAM Gateway Example
                // await PAMExamples.GatewayExamples.RemoveGatewayExample.RemoveGateway(
                //     vault,
                //     gatewayId: "<gatewayUid_or_name_here>"
                // );

                // // List PAM Rotations Example
                // await PAMExamples.RotationExamples.ListRotationsExample.ListRotations(
                //     vault,
                //     verbose: false
                // );

                // // PAM Rotation Info Example
                // await PAMExamples.RotationExamples.RotationInfoExample.ShowRotationInfo(
                //     vault,
                //     recordId: "<pamUserUid_or_title_here>"
                // );

                // // Edit PAM Rotation Example (general pamUser)
                // await PAMExamples.RotationExamples.EditRotationExample.EditRotation(
                //     vault,
                //     recordId: "<pamUserUid_or_title_here>",
                //     configId: "<pamConfigUid_or_title_here>",
                //     resourceId: "<pamResourceUid_or_title_here>",
                //     onDemand: true,
                //     // scheduleCron: "0 0 4 * * ?",
                //     // complexity: "32,5,5,5,5",
                //     enable: true
                // );

                // // List PAM Rotation Scripts Example
                // await PAMExamples.RotationExamples.ListRotationScriptsExample.ListScripts(
                //     vault,
                //     pattern: null   // optional: record UID or title filter
                // );

                // // Add PAM Rotation Script Example
                // await PAMExamples.RotationExamples.AddRotationScriptExample.AddScript(
                //     vault,
                //     recordId: "<pamUserUid_or_title_here>",
                //     scriptFilePath: @"C:\path\to\rotate.ps1",
                //     runCommand: "powershell -File rotate.ps1",
                //     addCredentialUids: null   // or new[] { "<credentialUid_here>" }
                // );

                // // Edit PAM Rotation Script Example
                // await PAMExamples.RotationExamples.EditRotationScriptExample.EditScript(
                //     vault,
                //     recordId: "<pamUserUid_or_title_here>",
                //     scriptId: "<scriptUid_or_name_here>",
                //     runCommand: "powershell -File rotate.ps1",
                //     addCredentialUids: null,
                //     removeCredentialUids: null
                // );

                // // Remove PAM Rotation Script Example
                // await PAMExamples.RotationExamples.RemoveRotationScriptExample.RemoveScript(
                //     vault,
                //     recordId: "<pamUserUid_or_title_here>",
                //     scriptId: "<scriptUid_or_name_here>"
                // );

                // // Remove Client Example
                // await SecretManagerExamples.RemoveClientExample.RemoveClient(
                //     vault,
                //     applicationId: "<appUid_here>",
                //     deviceId: "<deviceId_here>"
                // );

                // // Share Folder or Record to App
                // await SecretManagerExamples.SecretManagerShareExample.SecretManagerShare(
                //     vault,
                //     applicationId: "<appUid_here>",
                //     sharedFolderOrRecordUid: "<shareFolder_or_recordUId_here>",
                //     canEdit: true
                // );

                // // BreachWatch List Example
                // await BreachWatchExamples.BreachWatchListExample.BreachWatchList(vault);

                // // BreachScan and Store Example
                // await BreachWatchExamples.BreachWatchScanExample.BreachWatchScan(
                //     vault,
                //     recordUid: "<recordUid_here>",
                //     recordKey: "<recordKey_here>".Base64UrlDecode(),
                //     password: "<password_here>"
                // );

                // // BreachWatch Password Scan Example
                // var passwords = new List<(string Password, byte[] Euid)>
                // {
                //     ("123", null),
                //     ("MPass!", null),
                //     ("admin", null)
                // };

                // await Sample.BreachWatchExamples.BreachWatchPasswordExample.BreachWatchPassword(vault, passwords);

                // // BreachWatch Ignore Example
                // await BreachWatchExamples.BreachWatchIgnoreExample.IgnoreRecord(vault, recordUid: "<recordUid_here>");

                // await BreachWatchExamples.BreachWatchIgnoreExample.CheckIfIgnored(vault, recordUid: "<recordUid_here>");

                // // Enterprise Get Data Example
                // await EnterpriseManagementExamples.EnterpriseDownExample.EnterpriseGetData(vault);

                // // Enterprise User View Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserViewExample.ViewUser(vault, email: "<userEmail_here>");

                // // Enterprise Add User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseAddUserExample.InviteUser(vault, email: "<userEmail_here>", fullName: "<fullName_here>", nodeNameOrId: "<nodeNameOrId_here>");
                // // Create instance
                // var examples = new EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseEditUserExamples();

                // // Call methods
                // await examples.AddUsersToTeams(
                //     vault,
                //     new[] { "<userEmail_here>" },
                //     new[] { "<teamUid_here>" }
                // );

                // await examples.RemoveUsersFromTeams(
                //     vault,
                //     new[] { "<userEmail_here>" },
                //     new[] { "<teamUid_here>" }
                // );

                // // Enterprise Delete User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseDeleteUserExample.DeleteUser(vault, email: "<userEmail_here>");

                // // Enterprise User Lock/Unlock Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserLockUnlockExample.LockUnlockUser(vault, email: "<userEmail_here>", locked: true);
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserLockUnlockExample.LockUnlockUser(vault, email: "<userEmail_here>", locked: false);

                // // Enterprise Node View Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeView.ViewNode(vault, nodeNameOrId: "<nodeNameOrId_here>");

                // // Enterprise Node Add Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeAdd.AddNode(vault, nodeName: "<nodeName_here>", parentNodeNameOrId: "<parentNodeNameOrId_here>");

                // // Enterprise Node Edit Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeEdit.EditNode(vault, nodeNameOrId: "<nodeNameOrId_here>", newName: "<newNodeName_here>", newParentNodeIdentifier: "<newParentNodeIdentifier_here>");

                // // Enterprise Node Delete Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeDelete.DeleteNode(vault, nodeNameOrId: "<nodeNameOrId_here>");

                // // Enterprise Role View Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleView.ViewRole(vault, roleNameOrId: "<roleNameOrId_here>");

                // // Enterprise Role Add Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleAdd.AddRole(vault, roleName: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", newUserInherit: true);

                // // Enterprise Role Update Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleUpdateExample.EnterpriseUpdateRole(vault, roleNameOrId: "Test12", newUserInherit: false, visibleBelow: true, displayName: "UTest12");

                // // Enterprise Role Delete Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleDeleteExample.EnterpriseDeleteRole(vault, roleNameOrId: "70411693853162");

                // // Enterprise Role Admin Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleAdminExample.EnterpriseAddAdmin(vault, roleNameOrId: "", userName: "<userEmail_here>");

                // // Enterprise Role Membership Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleMembershipExample.EnterpriseRemoveRoleMembership(vault, roleNameOrId: "<roleNameOrId_here>", userName: "<userEmail_here>");

                // // Enterprise Team View Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamViewExample.EnterpriseTeamView(vault, teamNameOrId: "<teamNameOrId_here>");

                // // Enterprise Team Add Example
                // EnterpriseTeam newTeam = new EnterpriseTeam
                // {
                //     Name = "<teamName_here>",
                //     RestrictEdit = false,
                //     RestrictSharing = true,
                //     RestrictView = false,
                // };
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamAddExample.EnterpriseTeamAdd(vault, newTeam: newTeam);

                // // Enterprise Team Update Example
                // EnterpriseTeam updateTeam = new EnterpriseTeam
                // {
                //     Name = "<teamName_here>",
                //     RestrictEdit = true,
                //     RestrictSharing = true,
                //     RestrictView = false,
                // };
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamUpdateExample.EnterpriseTeamUpdate(vault, updateTeam: updateTeam);

                // // Enterprise Team Delete Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamDeleteExample.EnterpriseTeamDelete(vault, teamNameOrId: "<teamName_here>");

                // // Enterprise Team Membership Examples
                // // Add Users to Teams Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamMembershipExample.AddUsersToTeams(
                //     vault,
                //     new[] { "<userEmail_here>", "user_email_here" },
                //     new[] { "<teamUid_here>" }
                // );

                // // Remove Users from Teams Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamMembershipExample.RemoveUsersFromTeams(
                //     vault,
                //     new[] { "<userEmail_here>", "user_email_here" },
                //     new[] { "<teamUid_here>" }
                // );

                // // Enterprise List Teams Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamsListExample.EnterpriseTeamsList(vault);

                // // Enterprise Role Team Management Example
                // // Add Team to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleTeamManagementExample.AddTeamToRoleExample(vault, roleNameOrId: "<roleNameOrId_here>", teamNameOrId: "<teamNameOrId_here>");

                // // Remove Team to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleTeamManagementExample.RemoveTeamFromRoleExample(vault, roleNameOrId: "<roleNameOrId_here>", teamNameOrid: "<teamNameOrId_here>");

                // // Trash List Example
                // await TrashExamples.TrashList.TrashListAsync(vault);

                // // Trash Restore Example
                // await TrashExamples.TrashRestore.TrashRestoreAsync(vault, new List<string> { "<recordUid_here>" });

                // // Login Example
                // await LoginExamples.LoginExample.LoginAsync();
                // await LoginExamples.LogoutExample.LogoutAsync(vault);
                // await LoginExamples.WhoamiExample.WhoamiAsync(vault);

                // // Enterprise Role Managed Node Management Example
                // // Add Managed Node to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeAddExample.RoleManagedNodeAdd(vault, roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", cascadeNodeManagement: true);

                // // Update Managed Node to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeUpdateExample.RoleManagedNodeUpdate(vault, roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", cascadeNodeManagement: false);

                // // Remove Managed Node from Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeRemoveExample.RoleManagedNodeRemove(vault, roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>");

                // // Add Privilege to Managed Node Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodePrivilegeAddExample.RoleManagedNodePrivilegeAdd(vault, roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", privileges: new List<RoleManagedNodePrivilege> { RoleManagedNodePrivilege.MANAGE_USER, RoleManagedNodePrivilege.TRANSFER_ACCOUNT });

                // // Remove Privilege from Managed Node Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodePrivilegeRemoveExample.RoleManagedNodePrivilegeRemove(vault, roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", privileges: new List<RoleManagedNodePrivilege> { RoleManagedNodePrivilege.MANAGE_USER, RoleManagedNodePrivilege.TRANSFER_ACCOUNT });

                // // Add Enforcement to Role Example
                // // JSON value for TWO_FACTOR_BY_IP - IPs in this range don't require 2FA
                // var enforcementsToAdd = new Dictionary<RoleEnforcementPolicies, string> {
                //     { RoleEnforcementPolicies.RESTRICT_FILE_UPLOAD, "true" },
                //     { RoleEnforcementPolicies.RESTRICT_IP_ADDRESSES, "1.1.1.1" },
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LENGTH, "10"},
                //     { RoleEnforcementPolicies.RESTRICT_OFFLINE_ACCESS, "true"},
                //     { RoleEnforcementPolicies.RESTRICT_DOMAIN_ACCESS, "192.168.1.100/app123"},
                //     { RoleEnforcementPolicies.GENERATED_PASSWORD_COMPLEXITY, "google.com|12|4|1|3|1"},
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LOWER, "5"},
                //     { RoleEnforcementPolicies.REQUIRE_TWO_FACTOR, "true"},
                //     { RoleEnforcementPolicies.RESTRICT_SHARING_RECORD_ATTACHMENTS, "true"},
                //     { RoleEnforcementPolicies.LOGOUT_TIMER_DESKTOP, "100"},
                //     { RoleEnforcementPolicies.RESTRICT_IMPORT, "true"},
                // };
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementAddExample.RoleEnforcementAdd(vault, roleNameOrId: "<roleNameOrId_here>", enforcements: enforcementsToAdd);

                // // Remove Enforcement to Role Example
                // var enforcementsToRemove = new List<RoleEnforcementPolicies> {
                //     { RoleEnforcementPolicies.RESTRICT_FILE_UPLOAD},
                //     { RoleEnforcementPolicies.RESTRICT_IP_ADDRESSES},
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LENGTH},
                //     { RoleEnforcementPolicies.RESTRICT_OFFLINE_ACCESS},
                //     { RoleEnforcementPolicies.RESTRICT_DOMAIN_ACCESS},
                //     { RoleEnforcementPolicies.GENERATED_PASSWORD_COMPLEXITY},
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LOWER},
                //     { RoleEnforcementPolicies.REQUIRE_TWO_FACTOR},
                //     { RoleEnforcementPolicies.RESTRICT_SHARING_RECORD_ATTACHMENTS},
                //     { RoleEnforcementPolicies.LOGOUT_TIMER_DESKTOP},
                //     { RoleEnforcementPolicies.RESTRICT_IMPORT},
                // };
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementRemoveExample.RoleEnforcementRemove(vault, roleNameOrId: "<roleNameOrId_here>", enforcement: enforcementsToRemove);

                // // Update Enforcement to Role Example  ---- Dont Update Boolean Values you will get an error

                // var enforcementsToUpdate = new Dictionary<RoleEnforcementPolicies, string>
                // {
                //     { RoleEnforcementPolicies.RESTRICT_FILE_UPLOAD, "true" },
                //     { RoleEnforcementPolicies.RESTRICT_IP_ADDRESSES, "1.1.1.1-2.1.1.1" },
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LENGTH, "15"}
                // };
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementUpdateExample.RoleEnforcementUpdate(vault, roleNameOrId: "<roleNameOrId_here>", enforcements: enforcementsToUpdate);

                // // Resend Enterprise Invite Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.ResendEnterpriseInviteExample.ResendEnterpriseInvite(vault, "<userEmail_here>");

                // // Set Master Password Expire Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.SetMasterPasswordExpireExample.SetMasterPasswordExpire(vault, "<userEmail_here>");

                // // Update Enterprise Team User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.TeamEnterpriseUserUpdateExample.TeamEnterpriseUserUpdate(vault, "<teamUid_here>", "<userEmail_here>", 0);

                // // Update Enterprise User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserUpdateExample.EnterpriseUserUpdate(vault, "<userEmail_here>", "<nodeNameOrId_here>", "<fullName_here>", "<jobTitle_here>", "<language_here>");

                // // Set Enterprise Custom Invitation Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.SetEnterpriseCustomInvitationExample.SetEnterpriseCustomInvitation(vault, "<nodeNameOrId_here>", "<Path_to_jsonFile>");

                // // Get Enterprise Custom Invitation Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.GetEnterpriseCustomInvitationExample.GetEnterpriseCustomInvitation(vault, "<nodeNameOrId_here>");

                // // Set Enterprise Custom Logo Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.SetEnterpriseCustomLogoExample.SetEnterpriseCustomLogo(vault, "<nodeNameOrId_here>", "email", "<file_path_here>");

                // // Action Report Example
                // await ActionReportExamples.ActionReportExample.RunActionReport(
                //     vault,
                //     targetStatus: ActionReportTargetStatus.NoLogon,
                //     daysSince: 30,
                //     node: null
                // );

                // // Audit Report Example
                // await AuditReportExamples.AuditReportExample.RunAuditReport(vault,
                //     limit: 1
                // );

                // await AuditReportExamples.AuditReportExample.RunAuditReport(vault,
                //     limit: 1
                // );

                // // Clipboard Copy Example
                // await RecordsExamples.ClipboardCopyExample.CopyToClipboard(vault, "<recordUid_here>", "<secret_key_here>");

                // // Find Duplicates Example
                // await RecordsExamples.FindDuplicatesExample.FindDuplicates(
                //     vault,
                //     byTitle: true,
                //     byLogin: true,
                //     byPassword: true
                // );

                // // MSP - List Managed Companies Example
                // await MspExamples.MspListManagedCompaniesExample.ListManagedCompanies(vault);

                // // MSP - Create Managed Company Example
                // await MspExamples.MspCreateManagedCompanyExample.CreateManagedCompany(
                //     vault,
                //     companyName: "Test13 Company",
                //     planId: "business",   // business, businessPlus, enterprise, enterprisePlus
                //     maxSeats: 10,
                //     nodeNameOrId: "",  // optional: node name or ID, defaults to root
                //     storagePlan: "STORAGE_100GB",  // STORAGE_100GB, STORAGE_1TB, STORAGE_10TB
                //     addons: new KeeperSecurity.Enterprise.ManagedCompanyAddonOptions[]
                //     {
                //         new KeeperSecurity.Enterprise.ManagedCompanyAddonOptions { Addon = "enterprise_breach_watch" },
                //         new KeeperSecurity.Enterprise.ManagedCompanyAddonOptions { Addon = "connection_manager", NumberOfSeats = 5 }
                //     }
                // );

                // // MSP - Update Managed Company Example
                // await MspExamples.MspUpdateManagedCompanyExample.UpdateManagedCompany(
                //     vault,
                //     companyId: 317995,   // <companyId_here>
                //     newName: "Test13 Company Updated",
                //     newPlanId: "businessPlus",
                //     newMaxSeats: 50,
                //     newStoragePlan: "STORAGE_1TB"
                // );

                // // MSP - Remove Managed Company Example
                // await MspExamples.MspRemoveManagedCompanyExample.RemoveManagedCompany(
                //     vault,
                //     companyId: 317995   // <companyId_here>
                // );

                // // MSP - Switch To Managed Company Example
                // await MspExamples.MspSwitchToManagedCompanyExample.SwitchToManagedCompany(
                //     vault,
                //     companyId: 282670   // <companyId_here>
                // );

                // // MSP - Copy Role To Managed Companies Example
                // await MspExamples.MspCopyRoleToManagedCompanyExample.CopyRoleToManagedCompanies(
                //     vault,
                //     sourceRoleName: "Test Dev",
                //     targetCompanyIds: new[] { 282670 }   // <companyId_here>
                // );

                // // MSP - Billing Report Example
                // await MspExamples.MspBillingReportExample.GetBillingReport(
                //     vault,
                //     month: 1,    // optional: 1-12, defaults to previous month
                //     year: 2026   // optional: defaults to current year
                // );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}