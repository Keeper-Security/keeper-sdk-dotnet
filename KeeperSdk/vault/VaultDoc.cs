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

using System.Runtime.CompilerServices;

namespace KeeperSecurity.Vault
{
    /// <summary>
    ///     Provides types for loading and storing the Keeper Vault data.
    /// </summary>
    /// <example>
    ///     <code>
    /// using System.Linq;
    /// using System.Threading;
    /// using System.Threading.Tasks;
    /// using KeeperSecurity.Authentication;
    /// using KeeperSecurity.Vault;
    /// 
    /// internal static class Program
    /// {
    ///     private static async Task Main()
    ///     {
    ///         IAuthentication auth = await ConnectToKeeperAs("username@company.com");
    ///         var vault = new VaultOnline(auth);
    ///         Console.WriteLine("\nRetrieving records...");
    ///         await vault.SyncDown();
    /// 
    ///         Console.WriteLine($"Hello {auth.Username}!");
    ///         Console.WriteLine($"Your vault has {vault.RecordCount} records.");
    /// 
    ///         // Find record with title "Google"
    ///         var search = vault.Records.FirstOrDefault(x => string.Compare(x.Title, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
    ///         // Create a record if it does not exist.
    ///         if (search == null)
    ///         {
    ///             search = new PasswordRecord
    ///             {
    ///                 Title = "Google",
    ///                 Login = "/Account Name/",
    ///                 Password = "/Account Password/",
    ///                 Link = "https://google.com",
    ///                 Notes = "Stores google credentials"
    ///             };
    ///             search = await vault.CreateRecord(search);
    ///         }
    /// 
    ///         // Update record.
    ///         search.SetCustomField("Security Token", "11111111");
    ///         search = await vault.UpdateRecord(search);
    /// 
    ///         // find file attachment.
    ///         var attachment = search.Attachments
    ///             .FirstOrDefault(x => string.Compare(x.Title, "google", StringComparison.InvariantCultureIgnoreCase) == 0);
    ///         if (attachment == null)
    ///         {
    ///             // Upload local file "google.txt"
    ///             var uploadTask = new FileAttachmentUploadTask("google.txt")
    ///             {
    ///                 Title = "Google",
    ///             };
    ///             await vault.UploadAttachment(search, uploadTask);
    ///         }
    ///         else
    ///         {
    ///             // Download attachment into local file "google.txt"
    ///             await using var stream = File.OpenWrite("google.txt");
    ///             await vault.DownloadAttachment(search, attachment.Id, stream);
    /// 
    ///             // Delete attachment. Remove it from the record 
    ///             search.Attachments.Remove(attachment);
    ///             await vault.UpdateRecord(search);
    ///         }
    /// 
    ///         // Find shared folder with name "Google".
    ///         var sharedFolder = vault.SharedFolders
    ///             .FirstOrDefault(x => string.Compare(x.Name, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
    ///         if (sharedFolder == null)
    ///         {
    ///             // Create shared folder.
    ///             var folder = await vault.CreateFolder("Google", null, new SharedFolderOptions
    ///             {
    ///                 ManageRecords = true,
    ///                 ManageUsers = false,
    ///                 CanEdit = false,
    ///                 CanShare = false,
    ///             });
    ///             vault.TryGetSharedFolder(folder.FolderUid, out sharedFolder);
    ///         }
    /// 
    ///         // Add user to shared folder.
    ///         await vault.PutUserToSharedFolder(sharedFolder.Uid, "user@google.com", UserType.User, new SharedFolderUserOptions
    ///         {
    ///             ManageRecords = false,
    ///             ManageUsers = false,
    ///         });
    /// 
    ///         // Add record to shared folder.
    ///         await vault.MoveRecords(new[] { new RecordPath { RecordUid = search.Uid } }, sharedFolder.Uid, true);
    ///     }
    /// }
    /// </code>
    /// </example>
    /// <seealso cref="Authentication.IAuthentication" />
    /// <seealso cref="IVaultData" />
    /// <seealso cref="VaultOnline" />
    /// <seealso cref="VaultOnline.DownloadAttachment" />
    [CompilerGenerated]
    internal class NamespaceDoc
    {
    }
}
