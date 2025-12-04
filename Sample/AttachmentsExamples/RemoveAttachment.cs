using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.AttachmentsExamples
{
    public static class RemoveAttachmentExample
    {
        public static async Task RemoveAttachment(string recordUid, string attachmentId)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var record = vault.GetRecord(recordUid);

            var deleted = await RemoveAttachmentSimple(vault, record, attachmentId);

            Console.WriteLine(deleted
                ? $"Attachment '{attachmentId}' removed from record '{recordUid}'."
                : $"Attachment '{attachmentId}' not found in record '{recordUid}'.");
        }

        public static async Task<bool> RemoveAttachmentSimple(VaultOnline vault, KeeperRecord record, string attachmentIdentifier)
        {
            var deleted = false;
            switch (record)
            {
                case PasswordRecord password:
                    var atta = password.Attachments?.FirstOrDefault(x => x.Id == attachmentIdentifier
                        || x.Name == attachmentIdentifier
                        || x.Title == attachmentIdentifier);
                    if (atta != null)
                    {
                        deleted = password.Attachments.Remove(atta);
                    }
                    break;
                case TypedRecord typed:
                {
                    var fileRef = typed.Fields
                        .Where(x => x.FieldName == "fileRef")
                        .OfType<TypedField<string>>()
                        .FirstOrDefault();

                    if (fileRef == null)
                    {
                        Console.WriteLine("fileRef field not found in TypedRecord.");
                        return false;
                    }

                    var attachment = vault.RecordAttachments(record)
                        .FirstOrDefault(x =>
                               attachmentIdentifier.Equals(x.Id, StringComparison.OrdinalIgnoreCase)
                            || attachmentIdentifier.Equals(x.Name, StringComparison.OrdinalIgnoreCase)
                            || attachmentIdentifier.Equals(x.Title, StringComparison.OrdinalIgnoreCase));
                    Console.WriteLine($"Attachment found: {attachment?.Id}, {attachment?.Name}, {attachment?.Title}");

                    if (attachment == null)
                    {
                        Console.WriteLine($"Attachment '{attachmentIdentifier}' not found in record '{record.Title}'.");
                        return false;
                    }
                    deleted = fileRef.Values.Remove(attachment.Id);
                    break;
                }

            }
            if (deleted)
            {
                await vault.UpdateRecord(record, false);
            }

            return deleted;
        }
    }
}

