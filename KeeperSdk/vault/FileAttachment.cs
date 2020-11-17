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

using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KeeperSecurity
{
    namespace Vault
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

            /// <summary>
            /// Attachment name.
            /// </summary>
            public string Name { get; set; }

            /// <summary>
            /// Attachment title.
            /// </summary>
            public string Title { get; set; }

            /// <summary>
            /// Attachment MIME type.
            /// </summary>
            public string MimeType { get; set; }

            /// <summary>
            /// Attachment input stream.
            /// </summary>
            public Stream Stream { get; protected set; }

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
            /// <summary>
            /// Creates a file attachment download HTTP request.
            /// </summary>
            /// <param name="recordUid">Record UID.</param>
            /// <param name="attachmentId">Attachment ID.</param>
            /// <returns></returns>
            public async Task<WebRequest> CreateAttachmentDownloadRequest(string recordUid, string attachmentId)
            {
                var command = new RequestDownloadCommand
                {
                    RecordUid = recordUid,
                    FileIDs = new[] {attachmentId}
                };
                this.ResolveRecordAccessPath(command);

                var rs = await Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);

                var download = rs.Downloads[0];
                return WebRequest.Create(new Uri(download.Url));
            }

            /// <summary>
            /// Downloads and decrypts file attachment.
            /// </summary>
            /// <param name="record">Keeper record.</param>
            /// <param name="attachment">Attachment name, title, or ID.</param>
            /// <param name="destination">Writable stream.</param>
            /// <returns>Awaitable task.</returns>
            /// <seealso cref="IVaultFileAttachment.DownloadAttachment"/>
            public async Task DownloadAttachment(PasswordRecord record, string attachment, Stream destination)
            {
                if (record.Attachments == null)
                {
                    throw new KeeperInvalidParameter("Vault::DownloadAttachment", "record", record.Uid, "has no attachments");
                }

                AttachmentFile attachmentFile;
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

                var request = await CreateAttachmentDownloadRequest(record.Uid, attachmentId);
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
                        var responseText = Encoding.UTF8.GetString(stream.ToArray());
                        Trace.TraceError(responseText);
                    }

                    throw;
                }
            }

            /// <summary>
            /// Encrypts and uploads file attachment.
            /// </summary>
            /// <param name="record">Keeper record.</param>
            /// <param name="uploadTask">Upload task</param>
            /// <returns>Awaitable task.</returns>
            /// <seealso cref="IVaultFileAttachment.UploadAttachment"/>
            public async Task UploadAttachment(PasswordRecord record, IAttachmentUploadTask uploadTask)
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
                    Type = uploadTask.MimeType,
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
            }
        }
    }

    namespace Commands
    {
        [DataContract]
        internal class RequestDownloadCommand : AuthenticatedCommand, IRecordAccessPath
        {
            public RequestDownloadCommand() : base("request_download")
            {
            }

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
            public RequestUploadCommand() : base("request_upload")
            {
            }

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
}
