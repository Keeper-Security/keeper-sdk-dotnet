using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using System.Net.Http;
using System.Net;

namespace KeeperSecurity.Vault
{

    /// <summary>
    /// Creates an attachment upload task.
    /// </summary>
    public class AttachmentUploadTask : IAttachmentUploadTask
    {
        /// <summary>
        /// Initializes a new instance of <see cref="AttachmentUploadTask"/> class.
        /// </summary>
        /// <param name="attachmentStream"></param>
        /// <param name="thumbnail"></param>
        public AttachmentUploadTask(Stream attachmentStream, IThumbnailUploadTask thumbnail = null)
        {
            Thumbnail = thumbnail;
            Stream = attachmentStream;
        }

        /// <inheritdoc/>
        public string Name { get; set; }

        /// <inheritdoc/>
        public string Title { get; set; }

        /// <inheritdoc/>
        public string MimeType { get; set; }

        /// <inheritdoc/>
        public Stream Stream { get; protected set; }

        /// <inheritdoc/>
        public IThumbnailUploadTask Thumbnail { get; protected set; }
    }

    /// <summary>
    /// Creates a file attachment upload task.
    /// </summary>
    public class FileAttachmentUploadTask : AttachmentUploadTask, IDisposable
    {
        /// <summary>
        /// Initializes a new instance of <see cref="FileAttachmentUploadTask"/> class.
        /// </summary>
        /// <param name="fileName">File name.</param>
        /// <param name="thumbnail">Thumbnail upload task. Optional.</param>
        public FileAttachmentUploadTask(string fileName, IThumbnailUploadTask thumbnail = null)
            : base(null, thumbnail)
        {
            if (!File.Exists(fileName))
            {
                throw new Exception($"Cannot open file \"{fileName}\"");
            }
            Name = Path.GetFileName(fileName);
            Title = Name;
            try
            {
                MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(fileName));
            }
            catch {/*ignored*/}

            Stream = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public void Dispose()
        {
            Stream?.Dispose();
        }
    }

    public partial class VaultOnline : IVaultFileAttachment
    {
        /// <inheritdoc/>
        public IEnumerable<IAttachment> RecordAttachments(KeeperRecord record)
        {
            switch (record)
            {
                case PasswordRecord password:
                    if (password.Attachments != null)
                    {
                        foreach (var atta in password.Attachments)
                        {
                            yield return atta;
                        }
                    }

                    break;

                case TypedRecord typed:
                    var fileRef = typed.Fields
                        .Where(x => x.FieldName == "fileRef")
                        .OfType<TypedField<string>>().FirstOrDefault();
                    if (fileRef != null)
                    {
                        foreach (var fileUid in fileRef.Values)
                        {
                            if (!TryGetKeeperRecord(fileUid, out var kr)) continue;
                            if (kr is FileRecord fr)
                            {
                                yield return fr;
                            }
                        }
                    }

                    break;

                case FileRecord file:
                    yield return file;
                    break;
            }
        }


        /// <inheritdoc/>
        public async Task DownloadAttachment(KeeperRecord record, string attachment, Stream destination)
        {
            var atta = RecordAttachments(record)
                .Where(x =>
                {
                    if (string.IsNullOrEmpty(attachment))
                    {
                        return true;
                    }

                    return attachment == x.Id || attachment == x.Name || attachment == x.Title;
                })
                .FirstOrDefault();

            if (atta == null)
            {
                throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", attachment, "not found");
            }

            switch (atta)
            {
                case AttachmentFile attachmentFile:
                    await DownloadAttachmentFile(record.Uid, attachmentFile, destination);
                    break;

                case FileRecord fileRecord:
                    await DownloadFile(fileRecord, destination);
                    break;

                default:
                    throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", atta.GetType().Name, "attachment type is not supported");

            }
        }


        /// <inheritdoc/>
        public async Task UploadAttachment(KeeperRecord record, IAttachmentUploadTask uploadTask)
        {
            switch (record)
            {
                case PasswordRecord password:
                    await UploadPasswordAttachment(password, uploadTask);
                    break;

                case TypedRecord typed:
                    await UploadTypedAttachment(typed, uploadTask);
                    break;
                default:
                    throw new KeeperInvalidParameter("Vault::UploadAttachment", "record", record.GetType().Name, "unsupported record type");
            }
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteAttachment(KeeperRecord record, string attachmentId)
        {
            var deleted = false;
            switch (record)
            {
                case PasswordRecord password:
                    var atta = password.Attachments?.FirstOrDefault(x => x.Id == attachmentId);
                    if (atta != null)
                    {
                        deleted = password.Attachments.Remove(atta);
                    }
                    break;
                case TypedRecord typed:
                    var fileRef = typed.Fields
                        .Where(x => x.FieldName == "fileRef")
                        .OfType<TypedField<string>>().FirstOrDefault();
                    if (fileRef != null)
                    {
                        deleted = fileRef.Values.Remove(attachmentId);
                    }
                    break;
            }

            if (deleted)
            {
                await UpdateRecord(record, false);
            }

            return deleted;
        }

        private static async Task DownloadFromUrl(Uri uri, Stream outputStream, IWebProxy proxy)
        {
            var httpMessageHandler = new HttpClientHandler();
            if (proxy != null)
            {
                httpMessageHandler.Proxy = proxy;
            }

            using var httpClient = new HttpClient(httpMessageHandler, true);
            var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);
            using var rss = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead);
            rss.EnsureSuccessStatusCode();
            using var stream = await rss.Content.ReadAsStreamAsync();
            await stream.CopyToAsync(outputStream);
        }

        /// <exclude/>
        public async Task DownloadFile(FileRecord fileRecord, Stream destination)
        {
            var rq = new Records.FilesGetRequest
            {
                ForThumbnails = false
            };
            rq.RecordUids.Add(ByteString.CopyFrom(fileRecord.Uid.Base64UrlDecode()));
            var rs = await Auth.ExecuteAuthRest<Records.FilesGetRequest, Records.FilesGetResponse>(
                "vault/files_download", rq);
            var fileResult = rs.Files[0];
            if (fileResult.Status != Records.FileGetResult.FgSuccess)
            {
                var status = fileResult.Status.ToString().ToSnakeCase();
                if (status.StartsWith("fg_"))
                {
                    status = status.Substring(3);
                }

                throw new KeeperApiException(status, fileRecord.Name ?? fileRecord.Title);
            }

            using var ms = new MemoryStream();
            await DownloadFromUrl(new Uri(fileResult.Url), ms, Auth.Endpoint.WebProxy);
            var plainData = CryptoUtils.DecryptAesV2(ms.ToArray(), fileRecord.RecordKey);
            await destination.WriteAsync(plainData, 0, plainData.Length);
        }

        /// <exclude />
        public async Task DownloadAttachmentFile(string recordUid, AttachmentFile attachment, Stream destination)
        {
            var command = new RequestDownloadCommand
            {
                RecordUid = recordUid,
                FileIDs = new[] { attachment.Id }
            };
            this.ResolveRecordAccessPath(command);
            var rs = await Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);

            var download = rs.Downloads[0];

            using var ms = new MemoryStream();
            await DownloadFromUrl(new Uri(download.Url), ms, Auth.Endpoint.WebProxy);
            var plainData = CryptoUtils.DecryptAesV1(ms.ToArray(), attachment.Key.Base64UrlDecode());
            await destination.WriteAsync(plainData, 0, plainData.Length);
        }

        private static async Task UploadSingleFile(UploadParameters upload, byte[] data, IWebProxy proxy)
        {
            var content = new MultipartFormDataContent();
            foreach (var pair in upload.Parameters) content.Add(new StringContent(pair.Value), pair.Key);
            var fileContent = new ByteArrayContent(data);
            content.Add(fileContent, upload.FileParameter);
            
            var httpMessageHandler = new HttpClientHandler();
            if (proxy != null)
            {
                httpMessageHandler.Proxy = proxy;
            }
            using var httpClient = new HttpClient(httpMessageHandler, true);
            var rs = await httpClient.PostAsync(upload.Url, content);
            if ((int) rs.StatusCode != upload.SuccessStatusCode)
                throw new Exception($"File upload HTTP error: {rs.StatusCode}");
        }

        private async Task UploadPasswordAttachment(PasswordRecord record, IAttachmentUploadTask uploadTask)
        {
            var fileStream = uploadTask.Stream;
            if (fileStream == null)
            {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "uploadTask", "GetStream()", "null");
            }

            var thumbStream = uploadTask.Thumbnail?.Stream;
            var command = new RequestUploadCommand
            {
                FileCount = 1,
                ThumbnailCount = thumbStream != null ? 1 : 0
            };

            var rs = await Auth.ExecuteAuthCommand<RequestUploadCommand, RequestUploadResponse>(command);
            if (rs.FileUploads == null || rs.FileUploads.Length < 1)
            {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "request_upload", "file_uploads", "empty");
            }

            var fileUpload = rs.FileUploads[0];
            UploadParameters thumbUpload = null;
            if (rs.ThumbnailUploads != null && rs.ThumbnailUploads.Length > 0)
            {
                thumbUpload = rs.ThumbnailUploads[0];
            }

            var key = CryptoUtils.GenerateEncryptionKey();
            var atta = new AttachmentFile
            {
                Id = fileUpload.FileId,
                Name = uploadTask.Name,
                Title = uploadTask.Title,
                Key = key.Base64UrlEncode(),
                MimeType = uploadTask.MimeType,
                LastModified = DateTimeOffset.Now,
            };

            using var ms = new MemoryStream();
            await fileStream.CopyToAsync(ms);
            var plainData = ms.ToArray();
            atta.Size = plainData.Length;
            var encryptedData = CryptoUtils.EncryptAesV1(plainData, key);
            await UploadSingleFile(fileUpload, encryptedData, Auth.Endpoint.WebProxy);

            if (thumbUpload != null && thumbStream != null)
            {
                try
                {
                    ms.Seek(0, SeekOrigin.Begin);
                    await thumbStream.CopyToAsync(ms);
                    encryptedData = CryptoUtils.EncryptAesV1(ms.ToArray(), key);
                    await UploadSingleFile(thumbUpload, encryptedData, Auth.Endpoint.WebProxy);

                    var thumbnail = new AttachmentFileThumb
                    {
                        Id = thumbUpload.FileId,
                        Type = uploadTask.Thumbnail.MimeType,
                        Size = uploadTask.Thumbnail.Size
                    };
                    var ts = new[] { thumbnail };
                    atta.Thumbnails = atta.Thumbnails == null ? ts : atta.Thumbnails.Concat(ts).ToArray();
                }
                catch (Exception e)
                {
                    Trace.TraceError("Upload Thumbnail: {0}: \"{1}\"", e.GetType().Name, e.Message);
                }
            }

            record.Attachments.Add(atta);

            await UpdateRecord(record);
        }

        private async Task UploadTypedAttachment(TypedRecord record, IAttachmentUploadTask uploadTask)
        {
            var fileStream = uploadTask.Stream;
            if (fileStream == null)
            {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "uploadTask", "GetStream()", "null");
            }

            var fileData = new RecordFileData
            {
                Type = uploadTask.MimeType,
                Name = uploadTask.Name,
                Title = uploadTask.Title,
                Size = null,
                ThumbnailSize = null,
                LastModified = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            var fileKey = CryptoUtils.GenerateEncryptionKey();

            byte[] encryptedData = null;
            byte[] encryptedThumb = null;

            using var ms = new MemoryStream();

            ms.Seek(0, SeekOrigin.Begin);
            await uploadTask.Stream.CopyToAsync(ms);
            await ms.FlushAsync();
            var plainData = ms.ToArray();
            fileData.Size = plainData.Length;
            encryptedData = CryptoUtils.EncryptAesV2(plainData, fileKey);

            if (uploadTask.Thumbnail != null)
            {
                ms.Seek(0, SeekOrigin.Begin);
                await uploadTask.Stream.CopyToAsync(ms);
                await ms.FlushAsync();
                plainData = ms.ToArray();
                fileData.ThumbnailSize = plainData.Length;
                encryptedThumb = CryptoUtils.EncryptAesV2(ms.ToArray(), fileKey);
            }

            var fileUid = CryptoUtils.GenerateUid();
            var fileRq = new Records.File
            {
                RecordUid = ByteString.CopyFrom(fileUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(fileKey, Auth.AuthContext.DataKey)),
                Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(fileData), fileKey)),
                FileSize = encryptedData.Length + 100,
                ThumbSize = encryptedThumb?.Length ?? 0,
            };
            var rq = new Records.FilesAddRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            rq.Files.Add(fileRq);
            var fileRs = await Auth.ExecuteAuthRest<Records.FilesAddRequest, Records.FilesAddResponse>("vault/files_add", rq);
            var uploadRs = fileRs.Files[0];
            var fileUpload = new UploadParameters
            {
                Url = uploadRs.Url,
                FileParameter = "file",
                SuccessStatusCode = uploadRs.SuccessStatusCode,
                Parameters = JsonUtils.ParseJson<Dictionary<string, string>>(Encoding.UTF8.GetBytes(uploadRs.Parameters))
            };
            if (record.LinkedKeys == null)
            {
                record.LinkedKeys = new Dictionary<string, byte[]>();
            }
            record.LinkedKeys[fileUid] = fileKey;

            try
            {
                await UploadSingleFile(fileUpload, encryptedData, Auth.Endpoint.WebProxy);
            }
            catch (Exception e)
            {
                Trace.TraceError("Upload Thumbnail: {0}: \"{1}\"", e.GetType().Name, e.Message);
            }

            if (encryptedThumb != null && !string.IsNullOrEmpty(uploadRs.ThumbnailParameters))
            {
                var thumbUpload = new UploadParameters
                {
                    Url = uploadRs.Url,
                    FileParameter = "thumb",
                    SuccessStatusCode = uploadRs.SuccessStatusCode,
                    Parameters = JsonUtils.ParseJson<Dictionary<string, string>>(Encoding.UTF8.GetBytes(uploadRs.ThumbnailParameters))
                };
                try
                {
                    await UploadSingleFile(thumbUpload, encryptedThumb, Auth.Endpoint.WebProxy);
                }
                catch (Exception e)
                {
                    Trace.TraceError("Upload Thumbnail: {0}: \"{1}\"", e.GetType().Name, e.Message);
                }
            }

            var facade = new TypedRecordFacade<TypedRecordFileRef>(record);
            if (facade.Fields.FileRef != null)
            {
                var uids = facade.Fields.FileRef.Values;
                if (uids.Count > 0 && string.IsNullOrEmpty(uids[0]))
                {
                    uids[0] = fileUid;
                }
                else
                {
                    uids.Add(fileUid);
                }
            }

            await UpdateRecord(record);
        }
    }
}
