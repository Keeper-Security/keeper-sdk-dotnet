using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;

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
            if (File.Exists(fileName))
            {
                Name = Path.GetFileName(fileName);
                Title = Name;
                try
                {
                    MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(fileName));
                }
                catch
                {
                    // ignored
                }

                Stream = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            else
            {
                Trace.TraceError("FileAttachmentUploadTask: fileName: \"{0}\" not found.", fileName);
            }
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
                            if (TryGetKeeperRecord(fileUid, out var kr))
                            {
                                if (kr is FileRecord fr)
                                {
                                    yield return fr;
                                }
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

                    if (attachment == x.Id || attachment == x.Name || attachment == x.Title)
                    {
                        return true;
                    }

                    return false;

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
                    if (password.Attachments != null)
                    {
                        var atta = password.Attachments.FirstOrDefault(x => x.Id == attachmentId);
                        if (atta != null)
                        {
                            deleted = password.Attachments.Remove(atta);
                        }
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

            var request = WebRequest.Create(new Uri(fileResult.Url));

            using (var response = (HttpWebResponse) await request.GetResponseAsync())
            {
                using (var stream = response.GetResponseStream())
                {
                    var transform = new DecryptAesV2Transform(fileRecord.RecordKey);
                    using (var decodeStream = new CryptoStream(stream, transform, CryptoStreamMode.Read))
                    {
                        if (destination != null)
                        {
                            await decodeStream.CopyToAsync(destination);
                        }
                    }
                }
            }
        }

        /// <exclude />
        public async Task DownloadAttachmentFile(string recordUid, AttachmentFile attachment, Stream destination)
        {
            var command = new RequestDownloadCommand
            {
                RecordUid = recordUid,
                FileIDs = new[] { attachment .Id}
            };
            this.ResolveRecordAccessPath(command);
            var rs = await this.Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);

            var download = rs.Downloads[0];
            var request = WebRequest.Create(new Uri(download.Url));
            using (var response = (HttpWebResponse) await request.GetResponseAsync())
            using (var stream = response.GetResponseStream())
            {
                var transform = new DecryptAesV1Transform(attachment.Key.Base64UrlDecode());
                using (var decodeStream = new CryptoStream(stream, transform, CryptoStreamMode.Read))
                {
                    if (destination != null)
                    {
                        await decodeStream.CopyToAsync(destination);
                    }
                }
            }
        }

        internal static async Task UploadSingleFile(UploadParameters upload, Stream source)
        {
            var boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            var boundaryBytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary);

            var request = (HttpWebRequest) WebRequest.Create(new Uri(upload.Url));
            request.Method = "POST";
            request.ContentType = "multipart/form-data; boundary=" + boundary;

            using (var requestStream = await Task.Factory.FromAsync(request.BeginGetRequestStream, request.EndGetRequestStream, null))
            {
                const string parameterTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";
                if (upload.Parameters != null)
                {
                    foreach (var pair in upload.Parameters)
                    {
                        await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                        var formItem = string.Format(parameterTemplate, pair.Key, pair.Value);
                        var formItemBytes = Encoding.UTF8.GetBytes(formItem);
                        await requestStream.WriteAsync(formItemBytes, 0, formItemBytes.Length);
                    }
                }

                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                const string fileTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                var fileItem = string.Format(fileTemplate, upload.FileParameter);
                var fileBytes = Encoding.UTF8.GetBytes(fileItem);
                await requestStream.WriteAsync(fileBytes, 0, fileBytes.Length);

                await source.CopyToAsync(requestStream);

                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                var trailer = Encoding.ASCII.GetBytes("--\r\n");
                await requestStream.WriteAsync(trailer, 0, trailer.Length);
            }

            HttpWebResponse response;
            try
            {
                response = (HttpWebResponse) await Task.Factory.FromAsync(request.BeginGetResponse, request.EndGetResponse, null);
                if ((int) response.StatusCode != upload.SuccessStatusCode)
                {
                    throw new KeeperInvalidParameter("Vault::UploadSingleFile", "StatusCode", response.StatusCode.ToString(), "not success");
                }
            }
            catch (WebException e)
            {
                response = (HttpWebResponse) e.Response;
                if (response == null || response.ContentType != "application/xml") throw;
                using (var stream = new MemoryStream())
                {
                    var srcStream = response.GetResponseStream();
                    if (srcStream == null) throw;
                    await srcStream.CopyToAsync(stream);
                    Trace.TraceError(Encoding.UTF8.GetString(stream.ToArray()));
                }

                throw;
            }
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
            var transform = new EncryptAesV1Transform(key);
            using (var cryptoStream = new CryptoStream(fileStream, transform, CryptoStreamMode.Read))
            {
                await UploadSingleFile(fileUpload, cryptoStream);
                atta.Size = transform.EncryptedBytes;
            }

            if (thumbUpload != null && thumbStream != null)
            {
                try
                {
                    transform = new EncryptAesV1Transform(key);
                    using (var cryptoStream = new CryptoStream(thumbStream, transform, CryptoStreamMode.Read))
                    {
                        await UploadSingleFile(thumbUpload, cryptoStream);
                    }

                    var thumbnail = new AttachmentFileThumb
                    {
                        Id = thumbUpload.FileId,
                        Type = uploadTask.Thumbnail.MimeType,
                        Size = uploadTask.Thumbnail.Size
                    };
                    var ts = new[] {thumbnail};
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
            byte[] encryptedThumb = null;
            if (uploadTask.Thumbnail != null)
            {
                using (var ts = new MemoryStream())
                {
                    await uploadTask.Stream.CopyToAsync(ts);
                    await ts.FlushAsync();
                    var thumbBytes = ts.ToArray();
                    fileData.ThumbnailSize = thumbBytes.Length;
                    encryptedThumb = CryptoUtils.EncryptAesV2(thumbBytes, fileKey);
                }
            }

            var tempFile = Path.GetTempFileName();
            var transform = new EncryptAesV2Transform(fileKey);
            using (var encryptedFile = File.OpenWrite(tempFile))
            using (var cryptoStream = new CryptoStream(uploadTask.Stream, transform, CryptoStreamMode.Read))
            {
                await cryptoStream.CopyToAsync(encryptedFile);
                fileData.Size = transform.EncryptedBytes;
            }

            var fileInfo = new FileInfo(tempFile);
            var fileUid = CryptoUtils.GenerateUid();
            var fileRq = new Records.File
            {
                RecordUid = ByteString.CopyFrom(fileUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(fileKey, Auth.AuthContext.DataKey)),
                Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(fileData), fileKey)),
                FileSize = fileInfo.Length,
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
                Parameters = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(uploadRs.Parameters))
            };
            if (record.LinkedKeys == null) 
            {
                record.LinkedKeys = new Dictionary<string, byte[]>();
            }
            record.LinkedKeys[fileUid] = fileKey;

            try
            {
                using (var cryptoStream = File.OpenRead(tempFile))
                {
                    await UploadSingleFile(fileUpload, cryptoStream);
                }
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
                    Parameters = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(uploadRs.ThumbnailParameters))
                };
                try
                {
                    using (var cryptoStream = new MemoryStream(encryptedThumb))
                    {
                        await UploadSingleFile(thumbUpload, cryptoStream);
                    }
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
