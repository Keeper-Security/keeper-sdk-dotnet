using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
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
                        items.AddRange(await GetPasswordRecordFileItems(vault, pr, options, logger));
                    }
                    break;

                case TypedRecord tr:
                    items.AddRange(await GetTypedRecordFileItems(vault, tr, options, logger));
                    break;
            }

            return items;
        }

        private static Task<List<FileReportItem>> GetPasswordRecordFileItems(
            VaultOnline vault,
            PasswordRecord record,
            FileReportOptions options,
            Action<Severity, string> logger)
        {
            var items = new List<FileReportItem>();
            Dictionary<string, string> downloadStatuses = null;

            if (options.TryDownload)
            {
                downloadStatuses = TestAttachmentDownloads(vault, record.Uid, record.Title, logger);
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

            return Task.FromResult(items);
        }

        private static Task<List<FileReportItem>> GetTypedRecordFileItems(
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
                return Task.FromResult(items);

            Dictionary<string, string> downloadStatuses = null;
            if (options.TryDownload)
            {
                downloadStatuses = TestAttachmentDownloads(vault, record.Uid, record.Title, logger);
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

            return Task.FromResult(items);
        }

        private static Dictionary<string, string> TestAttachmentDownloads(
            VaultOnline vault,
            string recordUid,
            string recordTitle,
            Action<Severity, string> logger)
        {
            var statuses = new Dictionary<string, string>();
            logger?.Invoke(Severity.Information, $"Testing download accessibility for record: {recordTitle}");

            logger?.Invoke(Severity.Warning, "Download testing is not fully implemented in this version");

            return statuses;
        }
    }
}

