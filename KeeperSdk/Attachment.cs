//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.IO;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public interface IThumbnailUploadTask
    {
        string MimeType { get; }
        int Size { get; }
        Stream Stream { get; }
    }
    public interface IAttachmentUploadTask
    { 
        string Name { get; }
        string Title { get; }
        string MimeType { get; }
        Stream Stream { get; }

        IThumbnailUploadTask Thumbnail { get; }
    }

    public class FileAttachmentUploadTask : IAttachmentUploadTask, IDisposable
    { 
        public FileAttachmentUploadTask(string fileName, IThumbnailUploadTask thumbnail)
        {
            Thumbnail = thumbnail;
            if (File.Exists(fileName)) {
                Name = Path.GetFileName(fileName);
                Title = Name;
                try {
                    MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(fileName));
                }
                catch {/*ignored*/}

                _fileStream = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            } else {
                Trace.TraceError("FileAttachmentUploadTask: fileName: \"{0}\" not found.", fileName);
            }
        }
        private FileStream _fileStream;

        public virtual void PrepareThumbnail() { }

        public string Name { get; set; }
        public string Title { get; set; }
        public string MimeType { get; set; }
        public Stream Stream => _fileStream;
        public IThumbnailUploadTask Thumbnail { get; }

        public void Dispose()
        {
            if (_fileStream != null) {
                _fileStream.Dispose();
                _fileStream = null;
            }

            if (Thumbnail == null) return;
            if (Thumbnail is IDisposable disp) {
                disp.Dispose();
            }
        }
    }

    public static class AttachmentExtensions
    {

        public static async Task<WebRequest> CreateAttachmentDownloadRequest(this Vault vault, string recordUid, string attachmentId)
        {
            var command = new RequestDownloadCommand
            {
                RecordUid = recordUid, 
                FileIDs = new string[] {attachmentId}
            };
            vault.ResolveRecordAccessPath(command);

            var rs = await vault.Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);

            var download = rs.Downloads[0];
            return WebRequest.Create(new Uri(download.Url));
        }

        public static async Task DownloadAttachment(this Vault vault, PasswordRecord record, string attachment, Stream destination)
        {
            if (record.Attachments == null)
            {
                throw new KeeperInvalidParameter("Vault::DownloadAttachment", "record", record.Uid, "has no attachments");
            }
            AttachmentFile attachmentFile = null;
            if (string.IsNullOrEmpty(attachment))
            {
                if (record.Attachments.Count == 1)
                {
                    attachmentFile = record.Attachments[0];
                }
                else
                {
                    throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", "", "is empty");
                }
            }
            else
            {
                attachmentFile = record.Attachments
                    .FirstOrDefault(x =>
                    {
                        if (attachment == x.Id || attachment == x.Name || attachment == x.Title)
                        {
                            return true;
                        }
                        if (x.Thumbnails != null)
                        {
                            var thumbId = x.Thumbnails.Select(y => y.Id).FirstOrDefault(y => y == attachment);
                            if (!string.IsNullOrEmpty(thumbId))
                            {
                                return true;
                            }
                        }
                        return false;
                    });
            }
            if (attachmentFile == null)
            {
                throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", attachment, "not found");
            }

            var attachmentId = attachmentFile.Id;
            if (attachmentFile.Thumbnails != null)
            {
                foreach (var th in attachmentFile.Thumbnails)
                {
                    if (th.Id == attachment)
                    {
                        attachmentId = th.Id;
                        break;
                    }
                }
            }

            var request = await CreateAttachmentDownloadRequest(vault, record.Uid, attachmentId);
            using (var response = (HttpWebResponse) await request.GetResponseAsync())
            {
                using (var stream = response.GetResponseStream())
                {
                    var transform = new DecryptAesV1Transform(attachmentFile.Key.Base64UrlDecode());
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

        internal static async Task UploadSingleFile(UploadParameters upload, Stream source) {
            var boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            var boundaryBytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary);

            var request = (HttpWebRequest)WebRequest.Create(new Uri(upload.Url));
            request.Method = "POST";
            request.ContentType = "multipart/form-data; boundary=" + boundary;

            using (var requestStream = await Task.Factory.FromAsync(request.BeginGetRequestStream, request.EndGetRequestStream, null))
            {
                const string parameterTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";
                if (upload.Parameters != null) { 
                    foreach (var pair in upload.Parameters) {
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
            try {
                response = (HttpWebResponse)await Task.Factory.FromAsync(request.BeginGetResponse, request.EndGetResponse, null);
                if ((int)response.StatusCode != upload.SuccessStatusCode)
                {
                    throw new KeeperInvalidParameter("Vault::UploadSingleFile", "StatusCode", response.StatusCode.ToString(), "not success");
                }
            }
            catch (WebException e) {
                response = (HttpWebResponse)e.Response;
                if (response == null || response.ContentType != "application/xml") throw;
                using (var stream = new MemoryStream())
                {
                    var srcStream = response.GetResponseStream();
                    if (srcStream == null) throw;
                    await srcStream.CopyToAsync(stream);
                    var responseText = Encoding.UTF8.GetString(stream.ToArray());
                    Trace.TraceError(responseText);
                }
                throw;
            }
        }

        public static async Task UploadAttachment(this Vault vault, PasswordRecord record, IAttachmentUploadTask uploadTask)
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

            var rs = await vault.Auth.ExecuteAuthCommand<RequestUploadCommand, RequestUploadResponse>(command);
            if (rs.FileUploads == null || rs.FileUploads.Length < 1) {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "request_upload", "file_uploads", "empty");
            }

            var fileUpload = rs.FileUploads[0];
            UploadParameters thumbUpload = null;
            if (rs.ThumbnailUploads != null && rs.ThumbnailUploads.Length > 0) {
                thumbUpload = rs.ThumbnailUploads[0];
            }

            var key = CryptoUtils.GenerateEncryptionKey();
            var atta = new AttachmentFile { 
                Id = fileUpload.FileId,
                Name = uploadTask.Name,
                Title = uploadTask.Title,
                Key = key.Base64UrlEncode(),
                Type = uploadTask.MimeType,
                LastModified = DateTimeOffset.Now,
            };
            var transform = new EncryptAesV1Transform(key);
            using (var cryptoStream = new CryptoStream(fileStream, transform, CryptoStreamMode.Read)) {
                await UploadSingleFile(fileUpload, cryptoStream);
                atta.Size = transform.EncryptedBytes;
            }
            if (thumbUpload != null && thumbStream != null) {
                try {
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
                    var ts = new[] { thumbnail };
                    atta.Thumbnails = atta.Thumbnails == null ? ts : atta.Thumbnails.Concat(ts).ToArray();
                }
                catch (Exception e) {
                    Trace.TraceError("Upload Thumbnail: {0}: \"{1}\"", e.GetType().Name, e.Message);
                }
            }

            record.Attachments.Add(atta);
        }
    }

    [DataContract]
    internal class RequestDownloadCommand : AuthenticatedCommand, IRecordAccessPath
    {
        public RequestDownloadCommand() : base("request_download") { }

        [DataMember(Name = "file_ids")]
        public string[] FileIDs;

        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    [DataContract]
    internal class RequestUploadCommand : AuthenticatedCommand
    {
        public RequestUploadCommand() : base("request_upload") { }

        [DataMember(Name = "file_count")]
        public int FileCount = 0;

        [DataMember(Name = "thumbnail_count")]
        public int ThumbnailCount = 0;
    }

#pragma warning disable 0649
    [DataContract]
    internal class RequestDownload
    {
        [DataMember(Name = "success_status_code")]
        public int SuccessStatusCode;
        [DataMember(Name = "url")]
        public string Url;
    }

    [DataContract]
    [KnownType(typeof(RequestDownload))]
    internal class RequestDownloadResponse : KeeperApiResponse
    {

        [DataMember(Name = "downloads")]
        public RequestDownload[] Downloads;
    }

    [DataContract]
    internal class UploadParameters
    {
        [DataMember(Name = "url")]
        public string Url;

        [DataMember(Name = "max_size")]
        public long MaxSize;

        [DataMember(Name = "success_status_code")]
        public int SuccessStatusCode;

        [DataMember(Name = "file_id")]
        public string FileId;

        [DataMember(Name = "file_parameter")]
        public string FileParameter;

        [DataMember(Name = "parameters")]
        public IDictionary<string, object> Parameters;

    }

    [DataContract]
    internal class RequestUploadResponse : KeeperApiResponse
    {
        [DataMember(Name = "file_uploads")]
        public UploadParameters[] FileUploads;

        [DataMember(Name = "thumbnail_uploads")]
        public UploadParameters[] ThumbnailUploads;
    }

#pragma warning restore 0649


}
