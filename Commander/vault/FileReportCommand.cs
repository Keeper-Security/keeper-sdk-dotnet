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
        /// <summary>
        /// Generates and displays a report of file attachments in the vault.
        /// </summary>
        public static async Task FileReportCommand(this VaultContext context, FileReportCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Information)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

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

            Console.WriteLine();
            DisplayReport(report, options.TryDownload);
        }

        private const int BaseColumnCount = 6;
        private const int DownloadableColumnCount = 7;

        private static void DisplayReport(System.Collections.Generic.List<FileReportItem> report, bool includeDownloadable)
        {
            var columnCount = includeDownloadable ? DownloadableColumnCount : BaseColumnCount;
            var table = new Tabulate(columnCount)
            {
                DumpRowNo = false,
                LeftPadding = 0
            };

            var headers = includeDownloadable
                ? new[] { "Title", "Record UID", "Record Type", "File ID", "File Name", "File Size", "Downloadable" }
                : new[] { "Title", "Record UID", "Record Type", "File ID", "File Name", "File Size" };

            table.AddHeader(headers);

            foreach (var item in report)
            {
                var row = includeDownloadable
                    ? new object[] { item.RecordTitle ?? "", item.RecordUid ?? "", item.RecordType ?? "", item.FileId ?? "", item.FileName ?? "", item.FileSize.ToString(), item.Downloadable ?? "" }
                    : new object[] { item.RecordTitle ?? "", item.RecordUid ?? "", item.RecordType ?? "", item.FileId ?? "", item.FileName ?? "", item.FileSize.ToString() };

                table.AddRow(row);
            }

            table.Dump();
        }
    }

    class FileReportCommandOptions
    {
        [Option('d', "try-download", Required = false, Default = false,
            HelpText = "Try downloading every attachment you have access to")]
        public bool TryDownload { get; set; }
    }
}

