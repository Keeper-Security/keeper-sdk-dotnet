using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Plugins.PEDM;
using KeeperSecurity.Utils;

namespace Commander.PEDM
{
    internal class PedmApprovalCommand : PedmCommandBase
    {
        public PedmApprovalCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmApprovalOptions options)
        {
            if (!await EnsurePluginAsync())
                return;

            if (string.IsNullOrEmpty(options.Command))
            {
                options.Command = "list";
            }

            options.Command = options.Command.ToLowerInvariant();

            switch (options.Command)
            {
                case "list":
                    ListApprovals();
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
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, approve, deny, remove");
                    break;
            }
        }

        private void ListApprovals()
        {
            var approvals = Plugin.Approvals.GetAll().ToList();
            if (approvals.Count == 0)
            {
                Console.WriteLine("No approvals found.");
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
                    var status = GetApprovalStatus(Plugin, appr.ApprovalUid);
                    var expireIn = appr.ExpireIn > 0 ? $"{appr.ExpireIn}s" : "";
                    var created = DateTimeOffset.FromUnixTimeMilliseconds(appr.Created).ToString("yyyy-MM-dd HH:mm:ss");
                    tab.AddRow(appr.ApprovalUid, appr.ApprovalType.ToString(), status, appr.AgentUid ?? "", accountInfo, applicationInfo, justification, expireIn, created);
                }
                tab.Dump();
            }
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
            Console.WriteLine($"  Status: {GetApprovalStatus(Plugin, approvalUid)}");
            Console.WriteLine($"  Agent UID: {approval.AgentUid ?? ""}");
            Console.WriteLine($"  Account Info: {ParseApprovalField(approval.AccountInfo)}");
            Console.WriteLine($"  Application Info: {ParseApprovalField(approval.ApplicationInfo)}");
            Console.WriteLine($"  Justification: {ParseApprovalField(approval.Justification)}");
            Console.WriteLine($"  Expire In: {(approval.ExpireIn > 0 ? $"{approval.ExpireIn}s" : "N/A")}");
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(approval.Created):yyyy-MM-dd HH:mm:ss}");
        }

        private async Task ApproveAsync(string approvalUid)
        {
            if (string.IsNullOrEmpty(approvalUid))
            {
                Console.WriteLine("Approval UID is required for 'approve' command.");
                return;
            }

            var approvalUidBytes = approvalUid.Base64UrlDecode();
            var approveStatus = await Plugin.ModifyApprovals(
                toApprove: new[] { approvalUidBytes },
                toDeny: null,
                toRemove: null);

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

            var approvalUidBytes = approvalUid.Base64UrlDecode();
            var denyStatus = await Plugin.ModifyApprovals(
                toApprove: null,
                toDeny: new[] { approvalUidBytes },
                toRemove: null);

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

            var approvalUidBytes = approvalUid.Base64UrlDecode();
            var removeStatus = await Plugin.ModifyApprovals(
                toApprove: null,
                toDeny: null,
                toRemove: new[] { approvalUidBytes });

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
                    catch
                    {
                    }
                    
                    if (text.Length > 50)
                        return text.Substring(0, 47) + "...";
                    return text;
                }
            }
            catch
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

        private static string GetApprovalStatus(PedmPlugin plugin, string approvalUid)
        {
            try
            {
                var storageField = typeof(PedmPlugin).GetField("_storage", BindingFlags.NonPublic | BindingFlags.Instance);
                if (storageField != null)
                {
                    var storage = storageField.GetValue(plugin);
                    var approvalStatusProperty = storage?.GetType().GetProperty("ApprovalStatus");
                    if (approvalStatusProperty != null)
                    {
                        var approvalStatusStorage = approvalStatusProperty.GetValue(storage);
                        var getEntityMethod = approvalStatusStorage?.GetType().GetMethod("GetEntity", new[] { typeof(string) });
                        if (getEntityMethod != null)
                        {
                            var statusEntity = getEntityMethod.Invoke(approvalStatusStorage, new object[] { approvalUid });
                            if (statusEntity != null)
                            {
                                var statusProperty = statusEntity.GetType().GetProperty("ApprovalStatus");
                                if (statusProperty != null)
                                {
                                    var statusValue = statusProperty.GetValue(statusEntity);
                                    if (statusValue is int statusInt)
                                    {
                                        return statusInt switch
                                        {
                                            0 => "PENDING",
                                            1 => "APPROVED",
                                            2 => "DENIED",
                                            _ => "UNKNOWN"
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
            }
            return "PENDING";
        }
    }

    internal class PedmApprovalOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, approve, deny, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Approval UID")]
        public string ApprovalUid { get; set; }
    }
}

