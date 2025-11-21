using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class FileReportCommandExtensions
    {
        public static async Task FileReportCommand(this VaultContext context, FileReportCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error || severity == Severity.Information)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

            Console.WriteLine("Generating file attachment report...");

            var reportOptions = new FileReportOptions
            {
                TryDownload = options.TryDownload
            };

            var report = await context.Vault.GenerateFileReport(reportOptions, Logger);

            if (report.Count == 0)
            {
                Console.WriteLine("No records with file attachments found.");
                return;
            }

            Console.WriteLine($"Found {report.Count} file attachment(s) in {report.Select(r => r.RecordUid).Distinct().Count()} record(s).");
            Console.WriteLine();

            DisplayReport(report, options.TryDownload);
        }

        private static void DisplayReport(System.Collections.Generic.List<FileReportItem> report, bool includeDownloadable)
        {
            var columnCount = includeDownloadable ? 7 : 6;
            var table = new Tabulate(columnCount)
            {
                DumpRowNo = true,
                LeftPadding = 4
            };

            var headers = new[] { "Title", "Record UID", "Record Type", "File ID", "File Name", "File Size" };
            if (includeDownloadable)
            {
                headers = headers.Concat(new[] { "Downloadable" }).ToArray();
            }

            table.AddHeader(headers);

            foreach (var item in report)
            {
                var row = new object[]
                {
                    item.RecordTitle,
                    item.RecordUid ?? "",
                    item.RecordType ?? "",
                    item.FileId ?? "",
                    item.FileName ?? "",
                    FormatFileSize(item.FileSize)
                };

                if (includeDownloadable)
                {
                    row = row.Concat(new object[] { item.Downloadable ?? "" }).ToArray();
                }

                table.AddRow(row);
            }

            table.Dump();
        }

        private static string FormatFileSize(long size)
        {
            if (size < 1024)
                return $"{size} B";
            else if (size < 1024 * 1024)
                return $"{size / 1024.0:F1} KB";
            else if (size < 1024 * 1024 * 1024)
                return $"{size / (1024.0 * 1024):F1} MB";
            else
                return $"{size / (1024.0 * 1024 * 1024):F2} GB";
        }
    }

    class FileReportCommandOptions
    {
        [Option('d', "try-download", Required = false, Default = false,
            HelpText = "Try downloading every attachment you have access to")]
        public bool TryDownload { get; set; }
    }
}

