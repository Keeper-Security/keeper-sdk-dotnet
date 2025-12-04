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
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Commands;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
using Sample.RecordsExamples;
using Sample.AttachmentsExamples;



namespace Sample
{
    internal static class Program
    {
        private static async Task Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };
            var getRecords = new GetRecordsExample();
            await getRecords.GetRecordsWithName("Google");

            // Add Record Example
            await AddRecordExample.AddRecord(name: "AddEx2", type: "bankCard", folderUid: "<folderUid_if_any>");

            // Update Record Example
            await UpdateRecordExample.UpdateRecord(
                recordUid: "<recordUid_here>",
                newTitle: "UpdatedAddEx2",
                newRecordType: "serverCredentials"
            );

            // Delete Record Example
            await DeleteRecordExample.DeleteRecord(recordUid: "<recordUid_here>");

            // List Records Example
            await ListRecordExample.ListAllRecords();

            // Get Record Details Example
            var getRecord = new GetRecordExample();
            await getRecord.GetRecordDetails(recordUid: "<recordUid_here>");

            // Get Record History Example
            var getRecordHistory = new GetRecordHistoryExample();
            await getRecordHistory.GetRecordHistory1(recordUid: "<recordUid_here>");

            // Upload Attachment Example
            await UploadAttachmentExample.UploadAttachment(
                recordUid: "<recordUid_here>",
                filePath: "<file to upload path here>",
                thumbnailPath: "<thumbnail of the file path here>"
            );

            // Download Attachment Example
            await DownloadAttachmentExample.DownloadAttachment(
                recordUid: "<recordUid_here>",
                attachmentIdentifier: "<attachment id or name or title>",
                destinationPath: "<destination file path here>"
            );

            // Remove Attachment Example
            await RemoveAttachmentExample.RemoveAttachment(
                recordUid: "<recordUid_here>",
                attachmentId: "<attachment id here>"
            );

            // List Folders Example
            await FoldersExample.ListFolderExample.ListFolder();

            // Move Folder Example
            await FoldersExample.MoveFolderExample.MoveExistingFolder(
                folderUid: "<folderUid_here>",
                newParentFolderUid: "<newParentFolderUid_here>",
                link: false
            );

            // Remove Folder Example
            await FoldersExample.RemoveFolderExample.RemoveFolder(
                folderUid: "<folderUid_here>"
            );

            // Create Shared Folder Example
            var options = new SharedFolderOptions
            {
                ManageRecords = true,
                ManageUsers = false,
                CanShare = true
            };

            await FoldersExample.CreateFolder.CreateNewFolder(
                folderName: "NewFolderFromSDK",
                parentFolderUid: "<parentFolderUid_if_any>",
                sharedFolderOptions: options
            );

            // List Shared Folders Example
            await SharedFolderExamples.ListSharedFolder.ListAllSharedFolders();

            // Change Record Permissions of a Shared Folder Example
            var permissions = new SharedFolderRecordOptions
            {
                CanEdit = true,
                CanShare = true,
                Expiration = DateTimeOffset.Now.AddMinutes(5)

            };

            await SharedFolderExamples.SharedFolderPermissions.ManageSharedFolderPermissions1(
                sharedFolderUid: "<sharedFolderUid_here>",
                recordUid: "<recordUid_here>",
                permissionsOptions: permissions
            );
        }
    }
}
