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



namespace Sample
{
    internal static class Program
    {
        private static async Task Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };
            try
            {
                // // Authenticate once from Main - all examples share this vault
                // var vault = await AuthenticateAndGetVault.GetVault(enablePersistentLogin: true);
                // // var vault = await AuthenticateAndGetVault.GetVault();
                // if (vault == null)
                // {
                //     Console.WriteLine("Could not authenticate. Exiting.");
                //     return;
                // }

                // var getRecords = new GetRecordsExample();
                // await getRecords.GetRecordsWithName( "Google");

                await SharedFolderToUserExamples.ShareFolderToUserNoSync.ShareFolderWithUser(
                    "sharedFolderUid_here",
                    "userId_here",
                    UserType.User,
                    new SharedFolderUserOptions
                    {
                        ManageRecords = true,
                        ManageUsers = true,
                        Expiration = DateTimeOffset.Now.AddMinutes(10)
                    },// user share options here
                    grant: false// grant: true to share, grant: false to revoke
                );

                // // Add Record Example
                // await AddRecordExample.AddRecord(name: "<recordName_here>", type: "bankCard", folderUid: "<folderUid_here>");

                // // Update Record Example
                // await UpdateRecordExample.UpdateRecord(
                //     recordUid: "<recordUid_here>",
                //     newTitle: "UpdatedAddEx2",
                //     newRecordType: "serverCredentials"
                // );

                // // Delete Record Example
                // await DeleteRecordExample.DeleteRecord(recordUid: "<recordUid_here>");

                // // List Records Example
                // await ListRecordExample.ListAllRecords();

                // // Get Record Details Example
                // var getRecord = new GetRecordExample();
                // await getRecord.GetRecordDetails(recordUid: "<recordUid_here>");

                // // Get Record History Example
                // var getRecordHistory = new GetRecordHistoryExample();
                // await getRecordHistory.GetRecordHistory1(recordUid: "<recordUid_here>");

                // // Upload Attachment Example
                // await UploadAttachmentExample.UploadAttachment(
                //     recordUid: "<recordUid_here>",
                //     filePath: "<file_path_here>",
                //     thumbnailPath: "<thumbnail_path_here>"
                // );

                // // Download Attachment Example
                // await DownloadAttachmentExample.DownloadAttachment(
                //     recordUid: "<recordUid_here>",
                //     attachmentIdentifier: "<attachment id or name or title>",
                //     destinationPath: "<destination file path here>"
                // );

                // // Remove Attachment Example
                // await RemoveAttachmentExample.RemoveAttachment(
                //     recordUid: "<recordUid_here>",
                //     attachmentId: "<attachment_id_or_name_or_title>"
                // );

                // // List Folders Example
                // await FoldersExample.ListFolderExample.ListFolder();

                // // Move Folder Example
                // await FoldersExample.MoveFolderExample.MoveExistingFolder(
                //     folderUid: "<folderUid_here>",
                //     newParentFolderUid: "<newParentFolderUid_here>",
                //     link: false
                // );

                // // Remove Folder Example
                // await FoldersExample.RemoveFolderExample.RemoveFolder(
                //     folderUid: "<folderUid_here>"
                // );

                // // Create Shared Folder Example
                // var options = new SharedFolderOptions
                // {
                //     ManageRecords = true,
                //     ManageUsers = false,
                //     CanShare = true
                // };

                // await FoldersExample.CreateFolder.CreateNewFolder(
                //     folderName: "NewFolderFromSDK",
                //     parentFolderUid: "<parentFolderUid_if_any>",
                //     sharedFolderOptions: options
                // );

                // // List Shared Folders Example
                // await SharedFolderExamples.ListSharedFolder.ListAllSharedFolders();


                // // Change Record Permissions of a Shared Folder Example
                // var permissions = new SharedFolderRecordOptions
                // {
                //     CanEdit = true,
                //     CanShare = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(5)

                // };

                // await SharedFolderExamples.SharedFolderPermissions.ManageSharedFolderPermissions1(
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
                //     sharedFolderUid: "<sharedFolderUid_here>",
                //     userId: "<userEmail_here>",
                //     userType: UserType.User,
                //     options: userOptions
                // );

                // // One-Time Share Record Example
                // await OneTimeShareExamples.OneTimeShare.ShareRecordOneTime(
                //     recordUid: "<recordUid_here>",
                //     expireIn: TimeSpan.FromMinutes(2),
                //     shareName: "<shareName_here>"
                // );

                // // List One-Time Shares for a Record Example
                // await OneTimeShareListExamples.OneTimeShareList.GetOneTimeShareList(
                //     recordUid: "<recordUid_here>"
                // );

                // // One-Time Share Remove
                // await RemoveOneTimeShareExamples.RemoveOneTimeShare.RemoveOneTimeShareRecord(
                //        recordUid: "<recordUid_here>",
                //         clientIds: new[] { "<clientId_here>" }
                //    );

                // // Share Record to User Example
                // var shareOptions = new SharedFolderRecordOptions
                // {
                //     CanEdit = true,
                //     CanShare = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await ShareRecordExamples.ShareRecordToUser.ShareRecordToUserWithPermissions(
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>",
                //     options: shareOptions
                // );

                // // Remove User From Specified Record Example
                // await ShareRecordExamples.RevokeShareRecordToUser.RemoveShareRecordToUser(
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // Remove User from All Shares Example
                // await ShareRecordExamples.RevokeAllSharesToUser.RemoveAllSharesToUser(
                //     username: "<userEmail_here>"
                // );

                // // Transfer Ownership Example
                // await TransferOwnershipExamples.TransferOwnership.TransferRecordToUser(
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // All RecordType Example
                // await RecordTypeExamples.RecordTypeInfoExample.RecordTypeInfo();

                // // Specified Record Type Info Example
                // await RecordTypeExamples.RecordTypeInfoExample.RecordTypeInfo(
                // recordTypeName: "<recordTypeName_here>"
                // );

                // // Create RecordType Example
                // var recordTypeData = "{\"$id\":\"SDKEX1\",\"description\":\"My SDK record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}";
                // await RecordTypeExamples.CreateRecordTypeExample.CreateRecordType(
                // recordTypeData: recordTypeData
                // );

                // // Update RecordType Example
                // var updateRecordTypeData = "{\"$id\":\"SDKEX0\",\"description\":\"My SDK First record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}";
                // await RecordTypeExamples.UpdateRecordTypeExample.UpdateRecordType(
                //     recordTypeId: "<recordTypeId_here>",
                //     recordTypeData: updateRecordTypeData
                // );

                // // Delete RecordType Example
                // await RecordTypeExamples.DeleteRecordTypeExample.DeleteRecordType(
                // recordTypeId: "<recordTypeId_here>"
                // );

                // Import Example
                // string filename = @"C:\Users\ananthreddy.mandli_m\Desktop\Keeper\Commander_.Net\keeper-sdk-dotnet\Sample\ImportExportExamples\Test.json";
                // var json = File.ReadAllText(filename);
                // var result = await ImportExportExamples.ImportExample.Import(json);

                // // Export to Json Example
                // IEnumerable<string> recordUids = new List<string>
                //     {
                //         "<recordUId_here>",
                //         "<recordUId_here>"
                //     };
                // await ImportExportExamples.ExportToJsonExample.ExportToJson(
                //     recordUids: recordUids,
                //     includeSharedFolders: true,
                //     logger: null
                //   );

                // // Export to File Example
                // IEnumerable<string> recordUids1 = new List<string>
                //     {
                //          "<recordUId_here>",
                //          "<recordUId_here>"
                //     };
                // await ImportExportExamples.ExportToFileExample.ExportToFile(
                //     filename: "<filePath_here>",
                //     recordUids: recordUids1,
                //     includeSharedFolders: true,
                //     logger: null
                //   );

                // // DownloadMembership To FileObject Example
                // var options1 = new DownloadMembershipOptions
                // {
                //     FoldersOnly = true,
                //     ForceManageUsers = true,
                //     ForceManageRecords = true,
                //     SubFolderHandling = "flatten"   // or "ignore"
                // };

                // await ImportExportExamples.DownloadMembershipToFileObjectExample.DownloadMembershipToFileObject(
                //     options1,
                //     logger: null
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
                //     options2,
                //     logger: null
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
                //     filename: "<filePath_here>",
                //     options3,
                //     logger: null
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
                //     filename: "<filePath_here>",
                //     options4,
                //     logger: null
                // );

                // // Load Record Type Example ---- issue not able to pass the input.
                // string jsonPath = @"C:\Users\AnanthReddyMandli\Documents\keeper-sdk-dotnet\keeper-sdk-dotnet\Sample\ImportExportExamples\RecordType.json";
                // string loadRecordTypeData = File.ReadAllText(jsonPath);
                // await ImportExportExamples.LoadRecordTypeExample.LoadRecordType(
                //     recordTypeData: loadRecordTypeData
                // );

                // // App Llist Example
                // await SecretManagerExamples.AppListExample.AppList();

                // // App Create Example
                // await SecretManagerExamples.AppCreateExample.AppCreate(
                //     applicationName: "<appName_here>"
                // );

                // // App View Example
                // await SecretManagerExamples.AppViewExample.AppView(
                //     applicationUid: "<appUid_here>"
                // );

                // // App Delete Example
                // await SecretManagerExamples.AppDeleteExample.AppDelete(
                //      applicationUid: "<appUid_here>"
                //    );

                // // App Share Example
                // var userShareOptions = new SharedFolderUserOptions
                // {
                //     ManageRecords = true,
                //     ManageUsers = true,
                //     Expiration = DateTimeOffset.Now.AddMinutes(10)
                // };

                // await SecretManagerExamples.AppShareExample.AddUserToSharedFolder(
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
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>",
                //     options: recordShareOptions
                // );

                // // App Un Share Example
                // await SecretManagerExamples.AppUnShareExample.RemoveUserToSharedFolder(
                //     sharedFolderUid: "<recordUid_here>",
                //     userId: "<userEmail_here>",
                //     userType: UserType.User
                // );

                // await SecretManagerExamples.AppUnShareExample.RevokeShareToUser(
                //     recordUid: "<recordUid_here>",
                //     username: "<userEmail_here>"
                // );

                // // Add Client Example
                // await SecretManagerExamples.AddClientExample.AddClient(
                //     applicationId: "<appUid_here>",
                //     unlockIp: true,
                //     firstAccessExpireInMinutes: 10,
                //     accessExpiresInMinutes: 60,
                //     name: "Test Client Added 2"
                // );

                // // Remove Client Example
                // await SecretManagerExamples.RemoveClientExample.RemoveClient(
                //     applicationId: "<appUid_here>",
                //     deviceId: "<deviceId_here>"
                // );

                // // Share Folder or Record to App
                // await SecretManagerExamples.SecretManagerShareExample.SecretManagerShare(
                //     applicationId: "<appUid_here>",
                //     sharedFolderOrRecordUid: "<shareFolder_or_recordUId_here>",
                //     canEdit: true
                // );

                // // BreachWatch List Example
                // await BreachWatchExamples.BreachWatchListExample.BreachWatchList();

                // // BreachScan and Store Example
                // await BreachWatchExamples.BreachWatchScanExample.BreachWatchScan(
                //     recordUids: "<recordUid_here>",
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

                // await Sample.BreachWatchExamples.BreachWatchPasswordExample.BreachWatchPassword(passwords);

                // // BreachWatch Ignore Example
                // await BreachWatchExamples.BreachWatchIgnoreExample.IgnoreRecord(recordUid: "<recordUid_here>");

                // await BreachWatchExamples.BreachWatchIgnoreExample.CheckIfIgnored(recordUid: "<recordUid_here>");

                // // Enterprise Get Data Example
                // await EnterpriseManagementExamples.EnterpriseDownExample.EnterpriseGetData();

                // // Enterprise User View Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserViewExample.ViewUser(email: "<userEmail_here>");

                // Enterprise Add User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseAddUserExample.InviteUser(email: "<userEmail_here>", fullName: "<fullName_here>", nodeNameOrId: "<nodeNameOrId_here>");
                // // Create instance
                // var examples = new EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseEditUserExamples();

                // // Call methods
                // await examples.AddUsersToTeams(
                //     new[] { "<userEmail_here>" },
                //     new[] { "<teamUid_here>" }
                // );

                // await examples.RemoveUsersFromTeams(
                //     new[] { "<userEmail_here>" },
                //     new[] { "<teamUid_here>" }
                // );

                // // Enterprise Delete User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseDeleteUserExample.DeleteUser(email: "<userEmail_here>");

                // // Enterprise User Lock/Unlock Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserLockUnlockExample.LockUnlockUser(email: "<userEmail_here>", locked: true);
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserLockUnlockExample.LockUnlockUser(email: "<userEmail_here>", locked: false);

                // // Enterprise Node View Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeView.ViewNode(nodeNameOrId: "<nodeNameOrId_here>");

                // // Enterprise Node Add Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeAdd.AddNode(nodeName: "<nodeName_here>", parentNodeNameOrId: "<parentNodeNameOrId_here>");

                // // Enterprise Node Edit Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeEdit.EditNode(nodeNameOrId: "<nodeNameOrId_here>", newName: "<newNodeName_here>", newParentNodeIdentifier: "<newParentNodeIdentifier_here>");

                // // Enterprise Node Delete Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.EnterpriseNodeDelete.DeleteNode(nodeNameOrId: "<nodeNameOrId_here>");

                // // Enterprise Role View Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleView.ViewRole(roleNameOrId: "<roleNameOrId_here>");

                // // Enterprise Role Add Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleAdd.AddRole(roleName: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", newUserInherit: true);

                // // Enterprise Role Update Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleUpdateExample.EnterpriseUpdateRole(roleNameOrId: "Test12", newUserInherit: false, visibleBelow: true, displayName: "UTest12");

                // // Enterprise Role Delete Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleDeleteExample.EnterpriseDeleteRole(roleNameOrId: "70411693853162");

                // // Enterprise Role Admin Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleAdminExample.EnterpriseAddAdmin(roleNameOrId: "", userName: "<userEmail_here>");

                // // Enterprise Role Membership Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleMembershipExample.EnterpriseRemoveRoleMembership(roleId: <roleUid_here>, userName: "<userEmail_here>");

                // // Enterprise Team View Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamViewExample.EnterpriseTeamView(teamNameOrId: "<teamNameOrId_here>");

                // // Enterprise Team Add Example
                // EnterpriseTeam newTeam = new EnterpriseTeam
                // {
                //     Name = "<teamName_here>",
                //     RestrictEdit = false,
                //     RestrictSharing = true,
                //     RestrictView = false,
                // };
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamAddExample.EnterpriseTeamAdd(newTeam: newTeam);

                // // Enterprise Team Update Example
                // EnterpriseTeam updateTeam = new EnterpriseTeam
                // {
                //     Name = "<teamName_here>",
                //     RestrictEdit = true,
                //     RestrictSharing = true,
                //     RestrictView = false,
                // };
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamUpdateExample.EnterpriseTeamUpdate(updateTeam: updateTeam);

                // // Enterprise Team Delete Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamDeleteExample.EnterpriseTeamDelete(teamNameOrId: "<teamName_here>");

                // // Enterprise Team Membership Examples
                // // Add Users to Teams Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamMembershipExample.AddUsersToTeams(
                //     new[] { "<userEmail_here>", "user_email_here" },
                //     new[] { "<teamUid_here>" }
                // );

                // // Remove Users from Teams Example
                //     await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamMembershipExample.RemoveUsersFromTeams(
                //         new[] { "<userEmail_here>", "user_email_here" },
                //         new[] { "<teamUid_here>" }
                //    );

                // // Enterprise List Teams Example
                // await EnterpriseManagementExamples.EnterpriseTeamExamples.EnterpriseTeamsListExample.EnterpriseTeamsList();

                // // Enterprise Role Team Management Example
                // // Add Team to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleTeamManagementExample.AddTeamToRoleExample(roleNameOrId: "<roleNameOrId_here>", teamNameOrId: "<teamNameOrId_here>");

                // // Remove Team to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.EnterpriseRoleTeamManagementExample.RemoveTeamFromRoleExample(roleNameOrId: "<roleNameOrId_here>", teamNameOrid: "<teamNameOrId_here>");

                // // Trash List Example
                // await TrashExamples.TrashList.TrashListAsync();

                // // Trash Restore Example
                // await TrashExamples.TrashRestore.TrashRestoreAsync(new List<string> { "<recordUid_here>" });

                // Login Example
                // await LoginExamples.LoginExample.LoginAsync();
                // await LoginExamples.LogoutExample.LogoutAsync();
                // await LoginExamples.WhoamiExample.WhoamiAsync();

                // // Enterprise Role Managed Node Management Example
                // // Add Managed Node to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeAddExample.RoleManagedNodeAdd(roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", cascadeNodeManagement: true);

                // // Update Managed Node to Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeUpdateExample.RoleManagedNodeUpdate(roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", cascadeNodeManagement: false);

                // Remove Managed Node from Role Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodeRemoveExample.RoleManagedNodeRemove(roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>");

                // Add Privilege to Managed Node Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodePrivilegeAddExample.RoleManagedNodePrivilegeAdd(roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", privileges: new List<RoleManagedNodePrivilege> { RoleManagedNodePrivilege.MANAGE_USER, RoleManagedNodePrivilege.TRANSFER_ACCOUNT });

                // Remove Privilege from Managed Node Example
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleManagedNodePrivilegeRemoveExample.RoleManagedNodePrivilegeRemove(roleNameOrId: "<roleNameOrId_here>", nodeNameOrId: "<nodeNameOrId_here>", privileges: new List<RoleManagedNodePrivilege> { RoleManagedNodePrivilege.MANAGE_USER, RoleManagedNodePrivilege.TRANSFER_ACCOUNT });

                // Add Enforcement to Role Example
                // JSON value for TWO_FACTOR_BY_IP - IPs in this range don't require 2FA
                // var enforcements = new Dictionary<RoleEnforcementPolicies, string> {
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
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementAddExample.RoleEnforcementAdd(roleNameOrId: "<roleNameOrId_here>", enforcements: enforcements);

                // Remove Enforcement to Role Example
                // var enforcements = new List<RoleEnforcementPolicies> {
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
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementRemoveExample.RoleEnforcementRemove(roleNameOrId: "<roleNameOrId_here>", enforcement: enforcements);

                // Update Enforcement to Role Example  ---- Dont Update Boolean Values you will get an error

                // var enforcements = new Dictionary<RoleEnforcementPolicies, string>
                // {
                //     { RoleEnforcementPolicies.RESTRICT_FILE_UPLOAD, "true" },
                //     { RoleEnforcementPolicies.RESTRICT_IP_ADDRESSES, "1.1.1.1-2.1.1.1" },
                //     { RoleEnforcementPolicies.MASTER_PASSWORD_MINIMUM_LENGTH, "15"}
                // };
                // await EnterpriseManagementExamples.EnterpriseRoleExamples.RoleEnforcementUpdateExample.RoleEnforcementUpdate(roleNameOrId: "<roleNameOrId_here>", enforcements: enforcements);

                // Resend Enterprise Invite Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.ResendEnterpriseInviteExample.ResendEnterpriseInvite("<userEmail_here>");

                // Set Master Password Expire Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.SetMasterPasswordExpireExample.SetMasterPasswordExpire("<userEmail_here>");

                // Update Enterprise Team User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.TeamEnterpriseUserUpdateExample.TeamEnterpriseUserUpdate("<teamUid_here>", "<userEmail_here>", 0);

                // Update Enterprise User Example
                // await EnterpriseManagementExamples.EnterpriseUserExamples.EnterpriseUserUpdateExample.EnterpriseUserUpdate("<userEmail_here>", "<nodeNameOrId_here>", "<fullName_here>", "<jobTitle_here>", "<language_here>");

                // Set Enterprise Custom Invitation Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.SetEnterpriseCustomInvitationExample.SetEnterpriseCustomInvitation("<nodeNameOrId_here>", "<Path_to_jsonFile>");

                // Get Enterprise Custom Invitation Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.GetEnterpriseCustomInvitationExample.GetEnterpriseCustomInvitation("<nodeNameOrId_here>");

                // Set Enterprise Custom Logo Example
                // await EnterpriseManagementExamples.EnterpriseNodeExamples.SetEnterpriseCustomLogoExample.SetEnterpriseCustomLogo("<nodeNameOrId_here>", "email", "<file_path_here>");

                // Action Report Example
                // await ActionReportExamples.ActionReportExample.RunActionReport(
                //     targetStatus: ActionReportTargetStatus.NoLogon,
                //     daysSince: 30,
                //     node: null
                // );

                // Audit Report Example
                // await AuditReportExamples.AuditReportExample.RunAuditReport(
                //     limit: 100
                // );

                // // Clipboard Copy Example
                // await RecordsExamples.ClipboardCopyExample.CopyToClipboard("<recordUid_here>", "<secret_key_here>");

               // Find Duplicates Example
                // await RecordsExamples.FindDuplicatesExample.FindDuplicates(
                //     byTitle: true,
                //     byLogin: true,
                //     byPassword: true
                // );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}