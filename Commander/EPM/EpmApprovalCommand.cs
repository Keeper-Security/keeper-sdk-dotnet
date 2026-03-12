using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Plugins.EPM;
using KeeperSecurity.Utils;

namespace Commander.EPM
{
    internal class EpmApprovalCommand : EpmCommandBase
    {
        public EpmApprovalCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(EpmApprovalOptions options)
        {
            if (options == null)
                return;
            if (!await EnsurePluginAsync())
                return;

            var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();

            switch (command)
            {
                case "list":
                    ListApprovals(options);
                    break;

                case "view":
                    ViewApproval(options.ApprovalUid);
                    break;

                case "approve":
                    await ApproveAsync(options.ApprovalUid);
                    break;

                case "deny":
                    await DenyAsync(options.ApprovalUid);
                    break;

                case "remove":
                case "delete":
                    await RemoveApprovalAsync(options.ApprovalUid);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{command}'. Available commands: list, view, approve, deny, remove");
                    break;
            }
        }

        private void ListApprovals(EpmApprovalOptions options)
        {
            var approvals = Plugin.Approvals.GetAll().ToList();
            var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (options?.ExpiredOnly == true)
            {
                approvals = approvals.Where(a => IsApprovalExpired((IEpmAdmin)Plugin, a, nowSeconds)).ToList();
            }
            else
            {
                approvals = approvals.Where(a => !IsApprovalExpired((IEpmAdmin)Plugin, a, nowSeconds)).ToList();
            }

            if (approvals.Count == 0)
            {
                Console.WriteLine(options?.ExpiredOnly == true ? "No expired approvals found." : "No approvals found.");
            }
            else
            {
                var tab = new Tabulate(9);
                tab.AddHeader("Approval UID", "Approval Type", "Status", "Agent UID", "Account Info", "Application Info", "Justification", "Expire In", "Created");
                foreach (var appr in approvals.OrderBy(x => x.ApprovalUid))
                {
                    var accountInfo = ParseApprovalField(appr.AccountInfo);
                    var applicationInfo = ParseApprovalField(appr.ApplicationInfo);
                    var justification = ParseApprovalField(appr.Justification);
                    var status = GetApprovalStatusDisplay((IEpmAdmin)Plugin, appr.ApprovalUid, appr.Created, appr.ExpireIn);
                    var expireIn = appr.ExpireIn > 0 ? $"{appr.ExpireIn}s" : "";
                    var created = DateTimeOffset.FromUnixTimeSeconds(appr.Created).ToString("yyyy-MM-dd HH:mm:ss");
                    tab.AddRow(appr.ApprovalUid, appr.ApprovalType.ToString(), status, appr.AgentUid ?? "", accountInfo, applicationInfo, justification, expireIn, created);
                }
                tab.Dump();
            }
        }

        private static bool IsApprovalExpired(IEpmAdmin plugin, EpmApproval a, long nowSeconds)
        {
            if (a.ExpireIn <= 0) return false;
            var statusInt = GetApprovalStatusInt(plugin, a.ApprovalUid);
            if (statusInt != 0) return false;
            var expireTime = a.Created + a.ExpireIn;
            return nowSeconds > expireTime;
        }

        private void ViewApproval(string approvalUid)
        {
            if (string.IsNullOrEmpty(approvalUid))
            {
                Console.WriteLine("Approval UID is required for 'view' command.");
                return;
            }

            var approval = Plugin.Approvals.GetEntity(approvalUid);
            if (approval == null)
            {
                Console.WriteLine($"Approval '{approvalUid}' not found.");
                return;
            }

            Console.WriteLine($"Approval: {approvalUid}");
            Console.WriteLine($"  Type: {approval.ApprovalType}");
            Console.WriteLine($"  Status: {GetApprovalStatusDisplay((IEpmAdmin)Plugin, approvalUid, approval.Created, approval.ExpireIn)}");
            Console.WriteLine($"  Agent UID: {approval.AgentUid ?? ""}");
            Console.WriteLine($"  Account Info: {ParseApprovalField(approval.AccountInfo)}");
            Console.WriteLine($"  Application Info: {ParseApprovalField(approval.ApplicationInfo)}");
            Console.WriteLine($"  Justification: {ParseApprovalField(approval.Justification)}");
            Console.WriteLine($"  Expire In: {(approval.ExpireIn > 0 ? $"{approval.ExpireIn}s" : "N/A")}");
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeSeconds(approval.Created):yyyy-MM-dd HH:mm:ss}");
        }

        private async Task ApproveAsync(string approvalUid)
        {
            if (string.IsNullOrEmpty(approvalUid))
            {
                Console.WriteLine("Approval UID is required for 'approve' command.");
                return;
            }

            var approval = Plugin.Approvals.GetEntity(approvalUid);
            if (approval == null)
            {
                Console.WriteLine($"Approval '{approvalUid}' not found.");
                return;
            }

            var currentStatus = GetApprovalStatusInt((IEpmAdmin)Plugin, approvalUid);
            if (currentStatus == 1) 
            {
                Console.WriteLine($"Approval '{approvalUid}' is already APPROVED. Cannot approve again.");
                return;
            }
            if (currentStatus == 2)
            {
                Console.WriteLine($"Approval '{approvalUid}' is already DENIED. Cannot approve a denied request.");
                return;
            }

            var approveStatus = await Plugin.ModifyApprovals(
                toApproveUids: new[] { approvalUid },
                toDenyUids: null,
                toRemoveUids: null);

            Console.WriteLine($"Approval '{approvalUid}' approved.");
            if (approveStatus.Add?.Count > 0 || approveStatus.Update?.Count > 0 || approveStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(approveStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task DenyAsync(string approvalUid)
        {
            if (string.IsNullOrEmpty(approvalUid))
            {
                Console.WriteLine("Approval UID is required for 'deny' command.");
                return;
            }

            var approval = Plugin.Approvals.GetEntity(approvalUid);
            if (approval == null)
            {
                Console.WriteLine($"Approval '{approvalUid}' not found.");
                return;
            }

            var currentStatus = GetApprovalStatusInt((IEpmAdmin)Plugin, approvalUid);
            if (currentStatus == 2) 
            {
                Console.WriteLine($"Approval '{approvalUid}' is already DENIED. Cannot deny again.");
                return;
            }
            if (currentStatus == 1) 
            {
                Console.WriteLine($"Approval '{approvalUid}' is already APPROVED. Cannot deny an approved request.");
                return;
            }

            var denyStatus = await Plugin.ModifyApprovals(
                toApproveUids: null,
                toDenyUids: new[] { approvalUid },
                toRemoveUids: null);

            Console.WriteLine($"Approval '{approvalUid}' denied.");
            if (denyStatus.Add?.Count > 0 || denyStatus.Update?.Count > 0 || denyStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(denyStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveApprovalAsync(string approvalUid)
        {
            if (string.IsNullOrEmpty(approvalUid))
            {
                Console.WriteLine("Approval UID is required for 'remove' command.");
                return;
            }

            var removeStatus = await Plugin.ModifyApprovals(
                toApproveUids: null,
                toDenyUids: null,
                toRemoveUids: new[] { approvalUid });

            Console.WriteLine($"Approval '{approvalUid}' removed.");
            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }

        private static string ParseApprovalField(byte[] fieldData)
        {
            if (fieldData == null || fieldData.Length == 0)
                return "";

            try
            {
                var text = Encoding.UTF8.GetString(fieldData);
                
                if (IsValidText(text))
                {
                    try
                    {
                        var json = JsonUtils.ParseJson<Dictionary<string, object>>(fieldData);
                        if (json != null && json.Count > 0)
                        {
                            var parts = json.Select(kvp => $"{kvp.Key}: {kvp.Value}").Take(3);
                            var result = string.Join(", ", parts);
                            if (json.Count > 3)
                                result += "...";
                            return result;
                        }
                    }
                    catch (Exception)
                    {
                    }
                    
                    if (text.Length > 50)
                        return text.Substring(0, 47) + "...";
                    return text;
                }
            }
            catch (Exception)
            {
            }

            return $"(encrypted, {fieldData.Length} bytes)";
        }

        private static bool IsValidText(string text)
        {
            if (string.IsNullOrEmpty(text))
                return false;

            int nonPrintableCount = 0;
            foreach (var ch in text)
            {
                if (char.IsControl(ch) && ch != '\n' && ch != '\r' && ch != '\t')
                    nonPrintableCount++;
            }

            return (nonPrintableCount * 100.0 / text.Length) < 10;
        }

        private static string GetApprovalStatus(IEpmAdmin plugin, string approvalUid)
        {
            var statusInt = GetApprovalStatusInt(plugin, approvalUid);
            return statusInt switch
            {
                0 => "PENDING",
                1 => "APPROVED",
                2 => "DENIED",
                _ => "UNKNOWN"
            };
        }

        /// <summary>
        /// Returns display status: PENDING, APPROVED, DENIED, or EXPIRED when stored status is PENDING
        /// and the approval has passed its expire time (created + expire_in), matching Python Commander PR #1697.
        /// </summary>
        private static string GetApprovalStatusDisplay(IEpmAdmin plugin, string approvalUid, long created, int expireIn)
        {
            var statusInt = GetApprovalStatusInt(plugin, approvalUid);
            if (statusInt == 0 && expireIn > 0)
            {
                var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var expireTime = created + expireIn;
                if (nowSeconds > expireTime)
                    return "EXPIRED";
            }
            return statusInt switch
            {
                0 => "PENDING",
                1 => "APPROVED",
                2 => "DENIED",
                _ => "UNKNOWN"
            };
        }

        private static int GetApprovalStatusInt(IEpmAdmin plugin, string approvalUid)
        {
            return plugin?.GetApprovalStatus(approvalUid) ?? 0; // 0 = PENDING when unknown
        }
    }

    internal class EpmApprovalOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, approve, deny, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Approval UID")]
        public string ApprovalUid { get; set; }

        [Option("expired", Required = false, Default = false, HelpText = "List only expired approvals (for list command)")]
        public bool ExpiredOnly { get; set; }
    }
}

