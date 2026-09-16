using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ActionExamples
{
    /// <summary>
    /// Checks the status of a previously scheduled PAM gateway job via <see cref="ActionUtils.GetJobInfoAsync"/>.
    /// </summary>
    public static class PamActionJobInfoExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="jobId">Job or conversation ID returned when the rotate action was scheduled.</param>
        /// <param name="gatewayUid">Gateway UID; required when more than one gateway is online.</param>
        public static async Task GetJobInfo(VaultOnline vault, string jobId, string gatewayUid = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(jobId))
                {
                    Console.WriteLine("Job id is required.");
                    return;
                }

                var result = await ActionUtils.GetJobInfoAsync(vault.Auth, jobId, gatewayUid);
                if (!result.IsOk)
                {
                    Console.WriteLine(result.RawPayloadJson ?? "Job info request failed.");
                    return;
                }

                var job = result.JobInfo;
                if (job == null)
                {
                    Console.WriteLine(result.RawPayloadJson ?? "No job details returned.");
                    return;
                }

                Console.WriteLine("Execution Details");
                Console.WriteLine("-------------------------");
                if (!string.IsNullOrEmpty(job.Status))
                {
                    Console.WriteLine($"  Status              : {job.Status}");
                }

                if (!string.IsNullOrEmpty(job.Duration))
                {
                    Console.WriteLine($"  Duration            : {job.Duration}");
                }

                if (!string.IsNullOrEmpty(job.ResponseMessage))
                {
                    Console.WriteLine($"  Response Message    : {job.ResponseMessage}");
                }

                if (!string.IsNullOrEmpty(job.ExecutionException))
                {
                    Console.WriteLine($"  Execution Exception : {job.ExecutionException}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
