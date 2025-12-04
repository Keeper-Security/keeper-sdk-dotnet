using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.AttachmentsExamples
{
    public static class DownloadAttachmentExample
    {
        public static async Task DownloadAttachment(string recordUid, string attachmentIdentifier, string destinationPath)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var record = vault.GetRecord(recordUid);
            await DownloadAttachment(vault, record, attachmentIdentifier, destinationPath);
        }

        public static async Task DownloadAttachment(
            VaultOnline vault,
            KeeperRecord record,
            string attachmentIdentifier,
            string destinationPath)
        {
            if (vault == null || record == null)
            {
                Console.WriteLine("Vault or record is null.");
                return;
            }

            var attachment = vault.RecordAttachments(record)
                .Where(x =>
                    string.IsNullOrEmpty(attachmentIdentifier) ||
                    attachmentIdentifier.Equals(x.Id, StringComparison.OrdinalIgnoreCase) ||
                    attachmentIdentifier.Equals(x.Name, StringComparison.OrdinalIgnoreCase) ||
                    attachmentIdentifier.Equals(x.Title, StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();

            if (attachment == null)
            {
                Console.WriteLine($"Attachment '{attachmentIdentifier}' not found in record '{record.Title}'.");
                return;
            }
            string originalFileName = attachment switch
            {
                AttachmentFile f => f.Name,
                FileRecord fr => fr.Title ?? fr.Name,
                _ => "downloaded_file"
            };

            string destinationFolder = Path.GetDirectoryName(destinationPath);
            string finalPath = Path.Combine(destinationFolder, originalFileName);
            Directory.CreateDirectory(destinationFolder);

            using (var fs = new FileStream(finalPath, FileMode.Create, FileAccess.Write))
            {
                switch (attachment)
                {
                    case AttachmentFile attachmentFile:
                        await vault.DownloadAttachmentFile(record.Uid, attachmentFile, fs);
                        break;

                    case FileRecord fileRecord:
                        await vault.DownloadFile(fileRecord, fs);
                        break;

                    default:
                        Console.WriteLine($"Attachment type '{attachment.GetType().Name}' is not supported.");
                        return;
                }
            }

            Console.WriteLine($"Attachment '{attachment.Name}' downloaded successfully to '{finalPath}'.");
        }


    }
}
