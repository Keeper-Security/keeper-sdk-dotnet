using System;
using System.IO;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.AttachmentsExamples
{
    public static class UploadAttachmentExample
    {
        public static async Task UploadAttachment(string recordUid, string filePath, string thumbnailPath = null)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var record = vault.GetRecord(recordUid);

            if (record == null)
            {
                Console.WriteLine($"Record with UID '{recordUid}' not found.");
                return;
            }

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Attachment file '{filePath}' does not exist.");
                return;
            }

            IThumbnailUploadTask thumbnail = null;
            if (!string.IsNullOrEmpty(thumbnailPath))
            {
                if (!File.Exists(thumbnailPath))
                {
                    Console.WriteLine($"Thumbnail file '{thumbnailPath}' does not exist. Skipping thumbnail.");
                }
                else
                {
                    Console.WriteLine($"Uploading thumbnail from '{thumbnailPath}'.");
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
            }
        }



        public class ThumbnailUploadTask : IThumbnailUploadTask
        {
            public string MimeType { get; private set; }
            public Stream Stream { get; private set; }
            public int Size { get; private set; }

            public ThumbnailUploadTask(string imagePath)
            {
                if (!File.Exists(imagePath))
                {
                    throw new FileNotFoundException($"Thumbnail file not found: {imagePath}");
                }

                try
                {
                    MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(imagePath));
                }
                catch {/*Mime is calculated from the extension*/}

                Stream = File.Open(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                
                // Set thumbnail size (20x20 pixels)
                // Note: In a production app, you might want to read actual image dimensions
                // using a cross-platform image library like SixLabors.ImageSharp
                Size = 20;

            }
            public void Dispose()
            {
                Stream?.Dispose();
                Console.WriteLine("Thumbnail stream disposed.");
            }
        }
    }
}
