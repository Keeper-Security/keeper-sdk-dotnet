using System;
using System.IO;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.AttachmentsExamples
{
    public static class UploadAttachmentExample
    {
        public static async Task UploadAttachment(VaultOnline vault, string recordUid, string filePath, string thumbnailPath = null)
        {
            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            if (string.IsNullOrWhiteSpace(filePath))
            {
                Console.WriteLine("File path is required.");
                return;
            }

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Attachment file '{filePath}' does not exist.");
                return;
            }

            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var record = vault.GetRecord(recordUid);
            if (record == null)
            {
                Console.WriteLine($"Record with UID '{recordUid}' not found.");
                return;
            }

            ThumbnailUploadTask thumbnail = null;
            if (!string.IsNullOrEmpty(thumbnailPath))
            {
                if (!File.Exists(thumbnailPath))
                {
                    Console.WriteLine($"Thumbnail file '{thumbnailPath}' does not exist. Skipping thumbnail.");
                }
                else
                {
                    thumbnail = new ThumbnailUploadTask(thumbnailPath);
                }
            }

            var uploadTask = new FileAttachmentUploadTask(filePath, thumbnail);

            try
            {
                await vault.UploadAttachment(record, uploadTask);
                Console.WriteLine($"File '{Path.GetFileName(filePath)}' uploaded successfully to record '{record.Title}' ({record.Uid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to upload file '{Path.GetFileName(filePath)}': {ex.Message}");
            }
            finally
            {
                uploadTask.Dispose();
                thumbnail?.Dispose();
            }
        }

        public class ThumbnailUploadTask : IThumbnailUploadTask
        {
            public string MimeType { get; }
            public Stream Stream { get; }
            public int Size { get; }

            public ThumbnailUploadTask(string thumbnailPath)
            {
                if (!File.Exists(thumbnailPath))
                    throw new FileNotFoundException($"Thumbnail file not found: {thumbnailPath}");

                MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(thumbnailPath));
                Stream = File.Open(thumbnailPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                Size = (int)Stream.Length;
            }

            public void Dispose() => Stream?.Dispose();
        }
    }
}
