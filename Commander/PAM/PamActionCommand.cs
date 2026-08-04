using System;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Commander;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
    /// <summary>
    /// pam-action: rotate credentials and check job status.
    /// </summary>
    internal class PamActionCommand : PamCommandBase
    {
        public PamActionCommand(IEnterpriseContext context) : base(context)
        {
        }

        /// <summary>
        /// Runs rotate or job-info subcommands.
        /// </summary>
        public async Task ExecuteAsync(PamActionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options),
                    "Invalid pam-action command arguments. Available commands: rotate, job-info");
            }

            var command = string.IsNullOrEmpty(options.Command) ? "" : options.Command.Trim().ToLowerInvariant();
            switch (command)
            {
                case "rotate":
                case "r":
                    await RotateAsync(options);
                    break;
                case "job-info":
                case "ji":
                    await JobInfoAsync(options);
                    break;
                default:
                    Console.WriteLine("Unsupported command. Available commands: rotate, job-info");
                    break;
            }
        }

        private async Task RotateAsync(PamActionOptions options)
        {
            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available.");
            }

            try
            {
                var result = await ActionUtils.RotateAsync(vault, new PamRotateOptions
                {
                    RecordUid = options.RecordUid,
                    Folder = options.Folder,
                    DryRun = options.DryRun,
                });

                if (result.IsFolderMode)
                {
                    var folder = result.FolderResult;
                    Console.WriteLine(
                        $"Selected for rotation - folders: {folder.FolderCount}, records: {folder.RecordCount}");
                    if (folder.DryRun)
                    {
                        return;
                    }

                    foreach (var item in folder.Results)
                    {
                        PrintActionResult(item);
                    }

                    foreach (var error in folder.Errors)
                    {
                        Console.WriteLine($"Record UID: {error.RecordUid} skipped: {error.Message}");
                    }

                    return;
                }

                PrintActionResult(result.RecordResult);
            }
            catch (PamException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private async Task JobInfoAsync(PamActionOptions options)
        {
            var vault = Context.GetVault();
            if (vault?.Auth == null)
            {
                throw new VaultException("Vault is not available.");
            }

            if (string.IsNullOrWhiteSpace(options.JobId))
            {
                Console.WriteLine(
                    "job_id is required. Usage: pam-action job-info \"<job_id>\" [--gateway UID]");
                Console.WriteLine("Tip: quote job ids that contain '/'.");
                return;
            }

            Console.WriteLine($"Job id to check [{options.JobId}]");
            try
            {
                var result = await ActionUtils.GetJobInfoAsync(vault.Auth, options.JobId, options.Gateway);
                PrintActionResult(result, printJobDetails: true);
            }
            catch (PamException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static void PrintActionResult(PamGatewayActionResult result, bool printJobDetails = false)
        {
            if (result == null)
            {
                return;
            }

            if (!result.IsOk)
            {
                Console.WriteLine(result.RawPayloadJson ?? "Action failed.");
                return;
            }

            if (result.IsScheduled)
            {
                var conversationId = result.ConversationId ?? "";
                var gwinfo = string.IsNullOrEmpty(result.GatewayUid) ? "" : $" --gateway={result.GatewayUid}";
                Console.WriteLine($"Scheduled action id: {conversationId}");
                Console.WriteLine(
                    $"The action has been scheduled, use command 'pam-action job-info \"{conversationId}\"{gwinfo}' to get status of the scheduled action");
                return;
            }

            if (printJobDetails)
            {
                PrintJobInfoDetails(result);
                return;
            }

            if (!string.IsNullOrEmpty(result.RawPayloadJson))
            {
                Console.WriteLine(result.RawPayloadJson);
            }
        }

        private static void PrintJobInfoDetails(PamGatewayActionResult result)
        {
            var job = result?.JobInfo;
            if (job == null
                || (string.IsNullOrEmpty(job.Status)
                    && string.IsNullOrEmpty(job.Duration)
                    && string.IsNullOrEmpty(job.ResponseMessage)
                    && string.IsNullOrEmpty(job.ExecutionException)))
            {
                Console.WriteLine(result?.RawPayloadJson ?? "No job details returned.");
                return;
            }

            Console.WriteLine("Execution Details");
            Console.WriteLine("-------------------------");
            if (!string.IsNullOrEmpty(job.Status))
            {
                Console.WriteLine($"\tStatus              : {job.Status}");
            }

            if (!string.IsNullOrEmpty(job.Duration))
            {
                Console.WriteLine($"\tDuration            : {job.Duration}");
            }

            if (!string.IsNullOrEmpty(job.ResponseMessage))
            {
                Console.WriteLine($"\tResponse Message    : {job.ResponseMessage}");
            }

            if (!string.IsNullOrEmpty(job.ExecutionException))
            {
                Console.WriteLine($"\tExecution Exception : {job.ExecutionException}");
            }
        }
    }

    internal class PamActionOptions
    {
        [Value(0, Required = false, HelpText = "Command: rotate, job-info")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Job id (for job-info). Quote if it contains '/'.")]
        public string JobId { get; set; }

        [Option('r', "record-uid", Required = false, HelpText = "Record UID to rotate")]
        public string RecordUid { get; set; }

        [Option('f', "folder", Required = false,
            HelpText = "Shared folder UID or title regex pattern to rotate pamUser records")]
        public string Folder { get; set; }

        [Option('n', "dry-run", Required = false, HelpText = "Enable dry-run mode (folder rotate only)")]
        public bool DryRun { get; set; }

        [Option('g', "gateway", Required = false, HelpText = "Gateway UID (for job-info when multiple gateways)")]
        public string Gateway { get; set; }
    }
}
