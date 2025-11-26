using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Commands;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Options for file report generation
    /// </summary>
    public class FileReportOptions
    {
        /// <summary>
        /// Test download accessibility for each attachment
        /// </summary>
        public bool TryDownload { get; set; }
    }

    /// <summary>
    /// File attachment information for report
    /// </summary>
    public class FileReportItem
    {
        /// <summary>
        /// Record title
        /// </summary>
        public string RecordTitle { get; set; }

        /// <summary>
        /// Record UID
        /// </summary>
        public string RecordUid { get; set; }

        /// <summary>
        /// Record type (for typed records)
        /// </summary>
        public string RecordType { get; set; }

        /// <summary>
        /// File/Attachment ID
        /// </summary>
        public string FileId { get; set; }

        /// <summary>
        /// File name
        /// </summary>
        public string FileName { get; set; }

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Download status (if TryDownload is enabled)
        /// </summary>
        public string Downloadable { get; set; }
    }

    /// <summary>
    /// File report generation methods
    /// </summary>
    public static class KeeperFileReport
    {
        /// <summary>
        /// Default timeout for testing file download accessibility (in seconds)
        /// </summary>
        private const int DownloadTestTimeoutSeconds = 10;

        /// <summary>
        /// Generate a report of all records with file attachments
        /// </summary>
        public static async Task<List<FileReportItem>> GenerateFileReport(
            this VaultOnline vault,
            FileReportOptions options = null,
            Action<Severity, string> logger = null)
        {
            options = options ?? new FileReportOptions();
            var report = new List<FileReportItem>();

            foreach (var record in vault.KeeperRecords)
            {
                var items = await GetRecordFileItems(vault, record, options, logger);
                report.AddRange(items);
            }

            return report;
        }

        private static async Task<List<FileReportItem>> GetRecordFileItems(
            VaultOnline vault,
            KeeperRecord record,
            FileReportOptions options,
            Action<Severity, string> logger)
        {
            var items = new List<FileReportItem>();

            switch (record)
            {
                case PasswordRecord pr:
                    if (pr.Attachments != null && pr.Attachments.Count > 0)
                    {
                        items.AddRange(await GetPasswordRecordFileItemsAsync(vault, pr, options, logger));
                    }
                    break;

                case TypedRecord tr:
                    items.AddRange(await GetTypedRecordFileItemsAsync(vault, tr, options, logger));
                    break;
            }

            return items;
        }

        private static async Task<List<FileReportItem>> GetPasswordRecordFileItemsAsync(
            VaultOnline vault,
            PasswordRecord record,
            FileReportOptions options,
            Action<Severity, string> logger)
        {
            var items = new List<FileReportItem>();
            Dictionary<string, string> downloadStatuses = null;

            if (options.TryDownload)
            {
                downloadStatuses = await TestAttachmentDownloadsAsync(vault, record.Uid, record.Title, logger);
            }

            foreach (var attachment in record.Attachments)
            {
                var item = new FileReportItem
                {
                    RecordTitle = record.Title,
                    RecordUid = record.Uid,
                    RecordType = "",
                    FileId = attachment.Id,
                    FileName = attachment.Title ?? attachment.Name,
                    FileSize = attachment.Size
                };

                if (downloadStatuses != null && downloadStatuses.TryGetValue(attachment.Id, out var status))
                {
                    item.Downloadable = status;
                }

                items.Add(item);
            }

            return items;
        }

        private static async Task<List<FileReportItem>> GetTypedRecordFileItemsAsync(
            VaultOnline vault,
            TypedRecord record,
            FileReportOptions options,
            Action<Severity, string> logger)
        {
            var items = new List<FileReportItem>();

            // Find file reference fields
            var fileRefFields = record.Fields?.Where(f =>
                string.Equals(f.FieldName, "fileRef", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (fileRefFields == null || fileRefFields.Count == 0)
                return items;

            Dictionary<string, string> downloadStatuses = null;
            if (options.TryDownload)
            {
                downloadStatuses = await TestAttachmentDownloadsAsync(vault, record.Uid, record.Title, logger);
            }

            foreach (var fileRefField in fileRefFields)
            {
                for (int i = 0; i < fileRefField.Count; i++)
                {
                    var fileUid = fileRefField.GetValueAt(i) as string;
                    if (string.IsNullOrEmpty(fileUid))
                        continue;

                    if (vault.TryGetKeeperRecord(fileUid, out var fileRecord) && fileRecord is FileRecord fr)
                    {
                        var item = new FileReportItem
                        {
                            RecordTitle = record.Title,
                            RecordUid = record.Uid,
                            RecordType = record.TypeName ?? "",
                            FileId = fr.Uid,
                            FileName = fr.Title ?? fr.Name,
                            FileSize = fr.FileSize
                        };

                        if (downloadStatuses != null && downloadStatuses.TryGetValue(fr.Uid, out var status))
                        {
                            item.Downloadable = status;
                        }

                        items.Add(item);
                    }
                }
            }

            return items;
        }

        private static async Task<Dictionary<string, string>> TestAttachmentDownloadsAsync(
            VaultOnline vault,
            string recordUid,
            string recordTitle,
            Action<Severity, string> logger)
        {
            var statuses = new Dictionary<string, string>();

            try
            {
                var downloads = await PrepareAttachmentDownloadAsync(vault, recordUid);
                
                if (downloads.Count > 0)
                {
                    logger?.Invoke(Severity.Information, $"Downloading attachment(s) for record: {recordTitle}");
                }
                
                foreach (var download in downloads)
                {
                    try
                    {
                        var status = await TestDownloadUrlAsync(download.Url, vault.Auth.Endpoint.WebProxy);
                        statuses[download.FileId] = status;
                    }
                    catch (Exception ex)
                    {
                        logger?.Invoke(Severity.Information, $"Error testing download for {download.FileId}: {ex.Message}");
                        statuses[download.FileId] = "Error";
                    }
                }
            }
            catch (Exception ex)
            {
                logger?.Invoke(Severity.Warning, $"Failed to test downloads for record: {ex.Message}");
            }
            
            return statuses;
        }

        private static async Task<List<AttachmentDownloadInfo>> PrepareAttachmentDownloadAsync(VaultOnline vault, string recordUid)
        {
            var downloads = new List<AttachmentDownloadInfo>();

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                return downloads;
            }

            if (record is PasswordRecord pr && pr.Attachments != null && pr.Attachments.Count > 0)
            {
                var command = new RequestDownloadCommand
                {
                    RecordUid = recordUid,
                    FileIDs = pr.Attachments.Select(a => a.Id).ToArray()
                };
                vault.ResolveRecordAccessPath(command);
                
                var response = await vault.Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);
                
                for (int i = 0; i < response.Downloads.Length && i < pr.Attachments.Count; i++)
                {
                    var download = response.Downloads[i];
                    if (!string.IsNullOrEmpty(download.Url))
                    {
                        downloads.Add(new AttachmentDownloadInfo
                        {
                            FileId = pr.Attachments[i].Id,
                            Url = download.Url
                        });
                    }
                }
            }
            else if (record is TypedRecord tr)
            {
                var fileRefFields = tr.Fields?.Where(f =>
                    string.Equals(f.FieldName, "fileRef", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (fileRefFields != null && fileRefFields.Count > 0)
                {
                    var fileUids = new List<string>();
                    foreach (var fileRefField in fileRefFields)
                    {
                        for (int i = 0; i < fileRefField.Count; i++)
                        {
                            var fileUid = fileRefField.GetValueAt(i) as string;
                            if (!string.IsNullOrEmpty(fileUid))
                            {
                                fileUids.Add(fileUid);
                            }
                        }
                    }

                    if (fileUids.Count > 0)
                    {
                        var request = new Records.FilesGetRequest
                        {
                            ForThumbnails = false
                        };

                        foreach (var fileUid in fileUids)
                        {
                            request.RecordUids.Add(Google.Protobuf.ByteString.CopyFrom(fileUid.Base64UrlDecode()));
                        }

                        var response = await vault.Auth.ExecuteAuthRest(
                            "vault/files_download",
                            request,
                            typeof(Records.FilesGetResponse)) as Records.FilesGetResponse;

                        if (response != null)
                        {
                            foreach (var fileStatus in response.Files)
                            {
                                if (fileStatus.Status == Records.FileGetResult.FgSuccess && !string.IsNullOrEmpty(fileStatus.Url))
                                {
                                    var fileUid = fileStatus.RecordUid.ToByteArray().Base64UrlEncode();
                                    downloads.Add(new AttachmentDownloadInfo
                                    {
                                        FileId = fileUid,
                                        Url = fileStatus.Url
                                    });
                                }
                            }
                        }
                    }
                }
            }

            return downloads;
        }

        private static async Task<string> TestDownloadUrlAsync(string url, System.Net.IWebProxy proxy)
        {
            try
            {
                var httpMessageHandler = new HttpClientHandler();
                if (proxy != null)
                {
                    httpMessageHandler.Proxy = proxy;
                }

                using var httpClient = new HttpClient(httpMessageHandler, true);
                httpClient.Timeout = TimeSpan.FromSeconds(DownloadTestTimeoutSeconds);

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("Range", "bytes=0-1");

                var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                
                if (response.StatusCode == System.Net.HttpStatusCode.OK || 
                    response.StatusCode == System.Net.HttpStatusCode.PartialContent)
                {
                    return "OK";
                }
                
                return ((int)response.StatusCode).ToString();
            }
            catch (TaskCanceledException ex)
            {
                return $"Timeout ({ex.Message})";
            }
            catch (HttpRequestException ex)
            {
                return $"Request Error: {ex.Message}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.GetType().Name} - {ex.Message}";
            }
        }

        private class AttachmentDownloadInfo
        {
            public string FileId { get; set; }
            public string Url { get; set; }
        }
    }
}

