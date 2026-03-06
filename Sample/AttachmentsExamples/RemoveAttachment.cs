using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.AttachmentsExamples
{
    /// <summary>
    /// Provides methods for removing attachments from Keeper records.
    /// </summary>
    public static class RemoveAttachmentExample
    {
        public static async Task RemoveAttachment(VaultOnline vault, string recordUid, string attachmentId)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var record = vault.GetRecord(recordUid);
            
            if (record == null)
            {
                Console.WriteLine($"Record '{recordUid}' not found.");
                return;
            }

            var deleted = await RemoveAttachmentSimple(vault, record, attachmentId);

            Console.WriteLine(deleted
                ? $"Attachment '{attachmentId}' removed from record '{record.Title}' ({recordUid})."
                : $"Attachment '{attachmentId}' not found in record '{record.Title}' ({recordUid}).");
        }

        public static async Task<bool> RemoveAttachmentSimple(VaultOnline vault, KeeperRecord record, string attachmentIdentifier)
        {
            if (vault == null)
            {
                Console.WriteLine("Vault instance is null.");
                return false;
            }

            if (record == null)
            {
                Console.WriteLine("Record is null.");
                return false;
            }

            if (string.IsNullOrWhiteSpace(attachmentIdentifier))
            {
                Console.WriteLine("Attachment identifier is required.");
                return false;
            }

            var attachment = vault.RecordAttachments(record)
                .FirstOrDefault(x =>
                    attachmentIdentifier.Equals(x.Id, StringComparison.OrdinalIgnoreCase) ||
                    attachmentIdentifier.Equals(x.Name, StringComparison.OrdinalIgnoreCase) ||
                    attachmentIdentifier.Equals(x.Title, StringComparison.OrdinalIgnoreCase));

            if (attachment == null)
            {
                Console.WriteLine($"Attachment '{attachmentIdentifier}' not found in record '{record.Title}'.");
                return false;
            }

            Console.WriteLine($"Found attachment: ID={attachment.Id}, Name={attachment.Name}, Title={attachment.Title}");

            var deleted = await vault.DeleteAttachment(record, attachment.Id);

            if (deleted)
            {
                Console.WriteLine("Attachment reference removed from record.");
            }
            else
            {
                Console.WriteLine($"Failed to remove attachment from record.");
            }

            return deleted;
        }
    }
}
