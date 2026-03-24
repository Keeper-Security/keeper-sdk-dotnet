using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Authentication;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Utils;

namespace Commander.Enterprise
{
    [Verb("security-audit-report", HelpText = "Run a security audit report.")]
    internal class SecurityAuditReportOptions
    {
        [Option("format", Required = false, Default = "table",
            HelpText = "Output format: table, json, csv")]
        public string Format { get; set; }

        [Option('o', "output", Required = false,
            HelpText = "Output to the given filename")]
        public string Output { get; set; }

        [Option("syntax-help", Required = false, Default = false,
            HelpText = "Display description of each column in the report")]
        public bool SyntaxHelp { get; set; }

        [Option('n', "node", Required = false, Separator = ',',
            HelpText = "Name(s) or UID(s) of node(s) to filter results by")]
        public IEnumerable<string> Node { get; set; }

        [Option('b', "breachwatch", Required = false, Default = false,
            HelpText = "Display a BreachWatch security report (ignored if BreachWatch is not active)")]
        public bool BreachWatch { get; set; }

        [Option("show-updated", Required = false, Default = false,
            HelpText = "Calculate current security audit scores for each vault and display locally (preview)")]
        public bool ShowUpdated { get; set; }

        [Option('s', "save", Required = false, Default = false,
            HelpText = "Similar to --show-updated, but also pushes updated scores to Keeper")]
        public bool Save { get; set; }

        [Option("score-type", Required = false, Default = "default",
            HelpText = "Define how users' security scores are calculated: strong_passwords, default")]
        public string ScoreType { get; set; }

        [Option("attempt-fix", Required = false, Default = false,
            HelpText = "Hard sync for vaults with invalid security-data (resets scores until vaults recalculate)")]
        public bool AttemptFix { get; set; }

        [Option('f', "force", Required = false, Default = false,
            HelpText = "Skip confirmation prompts (non-interactive mode)")]
        public bool Force { get; set; }
    }

    [Verb("breachwatch-report", HelpText = "Run a BreachWatch security report for all users in your enterprise")]
    internal class BreachWatchReportOptions
    {
        [Option("format", Required = false, Default = "table",
            HelpText = "Output format: table, json, csv")]
        public string Format { get; set; }

        [Option('o', "output", Required = false,
            HelpText = "Output to the given filename")]
        public string Output { get; set; }
    }

    [DataContract]
    internal class DecryptedReportJson
    {
        [DataMember(Name = "securityAuditStats")]
        public SecurityAuditStatsJson SecurityAuditStats { get; set; }

        [DataMember(Name = "bwStats")]
        public BreachWatchStatsJson BwStats { get; set; }

        [DataMember(Name = "weak_record_passwords")]
        public int WeakRecordPasswords { get; set; }

        [DataMember(Name = "fair_record_passwords")]
        public int FairRecordPasswords { get; set; }

        [DataMember(Name = "medium_record_passwords")]
        public int MediumRecordPasswords { get; set; }

        [DataMember(Name = "strong_record_passwords")]
        public int StrongRecordPasswords { get; set; }

        [DataMember(Name = "total_record_passwords")]
        public int TotalRecordPasswords { get; set; }
    }

    [DataContract]
    internal class SecurityAuditStatsJson
    {
        [DataMember(Name = "weak_record_passwords")]
        public int WeakRecordPasswords { get; set; }

        [DataMember(Name = "fair_record_passwords")]
        public int FairRecordPasswords { get; set; }

        [DataMember(Name = "medium_record_passwords")]
        public int MediumRecordPasswords { get; set; }

        [DataMember(Name = "strong_record_passwords")]
        public int StrongRecordPasswords { get; set; }

        [DataMember(Name = "total_record_passwords")]
        public int TotalRecordPasswords { get; set; }
    }

    [DataContract]
    internal class BreachWatchStatsJson
    {
        [DataMember(Name = "passed_records")]
        public int PassedRecords { get; set; }

        [DataMember(Name = "at_risk_records")]
        public int AtRiskRecords { get; set; }

        [DataMember(Name = "ignored_records")]
        public int IgnoredRecords { get; set; }
    }

    internal static class SecurityAuditReportCommandExtensions
    {
        public static async Task SecurityAuditReportCommand(this IEnterpriseContext context,
            SecurityAuditReportOptions options, InputManager inputManager)
        {
            if (options.SyntaxHelp)
            {
                DisplaySyntaxHelp();
                return;
            }

            if (context.EnterpriseData == null)
            {
                Console.WriteLine("Enterprise data is not available, use an admin account to use this command");
                return;
            }

            var treeKey = context.Enterprise?.TreeKey;
            if (treeKey == null || treeKey.Length == 0)
            {
                Console.WriteLine("Error: Enterprise tree key is not available. Ensure enterprise data is loaded.");
                return;
            }

            var ecKey = context.EnterprisePrivateKey;

            var nodeFilter = ResolveNodeFilter(context.EnterpriseData, options.Node);
            if (nodeFilter == null && options.Node != null && options.Node.Any())
                return;

            var useStrongPasswordsScoring = string.Equals(options.ScoreType, "strong_passwords",
                StringComparison.OrdinalIgnoreCase);
            var showBreachWatch = options.BreachWatch;
            var attemptFix = options.AttemptFix;

            var showUpdated = options.ShowUpdated || options.Save;
            var saveReport = options.Save;
            RsaPrivateKey rsaKey = null;
            if (context.Enterprise.RsaPrivateKey != null && context.Enterprise.RsaPrivateKey.Length > 0)
            {
                try { rsaKey = CryptoUtils.LoadRsaPrivateKey(context.Enterprise.RsaPrivateKey); }
                catch { }
            }

            var rows = new List<Dictionary<string, object>>();
            var invalidUsers = new List<long>();
            var updatedSecurityReports = new List<SecurityReport>();
            int saveBuildFailures = 0;
            long fromPage = 0;
            bool complete = false;
            long asOfRevision = 0;
            bool hasErrors = false;

            while (!complete)
            {
                var rq = new SecurityReportRequest { FromPage = fromPage };
                var rs = await context.Enterprise.Auth
                    .ExecuteAuthRest<SecurityReportRequest, SecurityReportResponse>(
                        "enterprise/get_security_report_data", rq);

                asOfRevision = rs.AsOfRevision;

                try
                {
                    if (rsaKey == null && rs.EnterprisePrivateKey != null && !rs.EnterprisePrivateKey.IsEmpty)
                    {
                        var keyData = CryptoUtils.DecryptAesV2(rs.EnterprisePrivateKey.ToByteArray(), treeKey);
                        rsaKey = CryptoUtils.LoadRsaPrivateKey(keyData);
                    }
                    if (ecKey == null && rs.EnterpriseEccPrivateKey != null && !rs.EnterpriseEccPrivateKey.IsEmpty)
                    {
                        var keyData = CryptoUtils.DecryptAesV2(rs.EnterpriseEccPrivateKey.ToByteArray(), treeKey);
                        ecKey = CryptoUtils.LoadEcPrivateKey(keyData);
                    }
                }
                catch
                { }

                foreach (var sr in rs.SecurityReport)
                {
                    if (!context.EnterpriseData.TryGetUserById(sr.EnterpriseUserId, out var user))
                        continue;

                    if (nodeFilter != null && !nodeFilter.Contains(user.ParentNodeId))
                        continue;

                    var email = user.Email ?? sr.EnterpriseUserId.ToString();
                    var name = user.DisplayName ?? email;
                    var nodePath = EnterpriseExtensions.GetNodePath(context.EnterpriseData, user.ParentNodeId);
                    var twofaOn = sr.TwoFactor != "two_factor_disabled" && !string.IsNullOrEmpty(sr.TwoFactor);

                    var row = new Dictionary<string, object>
                    {
                        ["name"] = name,
                        ["email"] = email,
                        ["sync_pending"] = "",
                        ["node"] = nodePath,
                        ["reused"] = sr.NumberOfReusedPassword,
                        ["twoFactorChannel"] = twofaOn ? "On" : "Off"
                    };

                    Dictionary<string, int> data;
                    if (sr.EncryptedReportData != null && sr.EncryptedReportData.Length > 0)
                    {
                        byte[] decryptedBytes;
                        try
                        {
                            decryptedBytes = CryptoUtils.DecryptAesV2(
                                sr.EncryptedReportData.ToByteArray(), treeKey);
                        }
                        catch
                        {
                            invalidUsers.Add(sr.EnterpriseUserId);
                            continue;
                        }

                        try
                        {
                            var json = Encoding.UTF8.GetString(decryptedBytes);
                            data = FlattenReportData(json, sr.NumberOfReusedPassword);
                        }
                        catch
                        {
                            invalidUsers.Add(sr.EnterpriseUserId);
                            continue;
                        }
                    }
                    else
                    {
                        data = new Dictionary<string, int>
                        {
                            ["weak_record_passwords"] = 0, ["fair_record_passwords"] = 0,
                            ["medium_record_passwords"] = 0, ["strong_record_passwords"] = 0,
                            ["total_record_passwords"] = 0, ["unique_record_passwords"] = 0,
                            ["passed_records"] = 0, ["at_risk_records"] = 0, ["ignored_records"] = 0
                        };
                    }

                   
                    if (showUpdated && sr.SecurityReportIncrementalData.Count > 0)
                    {
                        bool incrementalUpdateFailed = false;
                        data = ApplyIncrementalUpdates(data, sr, rsaKey, ecKey, ref incrementalUpdateFailed);
                        if (incrementalUpdateFailed)
                        {
                            hasErrors = true;
                        }
                        else
                        {
                            var total2 = data.TryGetValue("total_record_passwords", out var tv) ? tv : 0;
                            data["unique_record_passwords"] = total2 - sr.NumberOfReusedPassword;
                        }
                    }

                    row["weak"] = data.TryGetValue("weak_record_passwords", out var wv) ? wv : 0;
                    row["fair"] = data.TryGetValue("fair_record_passwords", out var fv) ? fv : 0;
                    row["medium"] = data.TryGetValue("medium_record_passwords", out var mv) ? mv : 0;
                    row["strong"] = data.TryGetValue("strong_record_passwords", out var sv) ? sv : 0;
                    row["total"] = data.TryGetValue("total_record_passwords", out var tv2) ? tv2 : 0;
                    row["unique"] = data.TryGetValue("unique_record_passwords", out var uv) ? uv : 0;
                    row["passed"] = data.TryGetValue("passed_records", out var pv) ? pv : 0;
                    row["at_risk"] = data.TryGetValue("at_risk_records", out var arv) ? arv : 0;
                    row["ignored"] = data.TryGetValue("ignored_records", out var igv) ? igv : 0;

                    var strong = (int)row["strong"];
                    var total = (int)row["total"];
                    var unique = (int)row["unique"];

                    if (unique < 0 && total > 0 && attemptFix)
                    {
                        invalidUsers.Add(sr.EnterpriseUserId);
                        continue;
                    }

                    if (total == 0 && (int)row["reused"] != 0)
                    {
                        row["sync_pending"] = "Yes";
                    }

                    double score;
                    int displayScore;
                    if (useStrongPasswordsScoring)
                    {
                        score = GetStrongByTotal(total, strong);
                        displayScore = (int)(100 * score);
                    }
                    else
                    {
                        score = GetSecurityScore(total, strong, unique, twofaOn);
                        displayScore = (int)(100 * Math.Round(score, 2));
                    }
                    row["securityScore"] = displayScore;

                    rows.Add(row);

                    if (saveReport && !hasErrors)
                    {
                        try
                        {
                            var updatedSr = new SecurityReport();
                            updatedSr.Revision = asOfRevision;
                            updatedSr.EnterpriseUserId = sr.EnterpriseUserId;
                            var reportJson = FormatReportData(data);
                            var jsonBytes = Encoding.UTF8.GetBytes(reportJson);
                            updatedSr.EncryptedReportData = ByteString.CopyFrom(
                                CryptoUtils.EncryptAesV2(jsonBytes, treeKey));
                            updatedSecurityReports.Add(updatedSr);
                        }
                        catch
                        {
                            saveBuildFailures++;
                        }
                    }
                }

                complete = rs.Complete;
                fromPage = rs.ToPage + 1;
            }

            if (invalidUsers.Count > 0)
                Console.WriteLine($"Decryption failed for {invalidUsers.Count} user(s). Successfully decrypted: {rows.Count}.");
            else
                Console.WriteLine($"All {rows.Count} user record(s) decrypted successfully.");

            if (attemptFix && invalidUsers.Count > 0)
            {
                bool doFix = options.Force;
                if (!doFix)
                {
                    Console.WriteLine($"\n{invalidUsers.Count} user(s) have invalid security data.");
                    Console.Write("Do you want to reset their security data? (y/n): ");
                    doFix = IsConfirmed(await inputManager.ReadLine());
                    if (!doFix) Console.WriteLine("Skipping security data reset.");
                }

                if (doFix)
                {
                    await ClearSecurityData(context, invalidUsers,
                        global::Enterprise.ClearSecurityDataType.ForceClientResendSecurityData);
                }
            }

            if (saveReport && saveBuildFailures > 0)
            {
                Console.WriteLine($"Unable to prepare {saveBuildFailures} updated security report(s). Save skipped.");
            }
            else if (saveReport && hasErrors)
            {
                Console.WriteLine("Updated security scores were not saved because some incremental security data could not be processed.");
            }
            else if (saveReport && updatedSecurityReports.Count > 0)
            {
                bool doSave = options.Force;
                if (!doSave)
                {
                    Console.Write("\nPush updated security scores to Keeper? (y/n): ");
                    doSave = IsConfirmed(await inputManager.ReadLine());
                    if (!doSave) Console.WriteLine("Save cancelled.");
                }

                if (doSave)
                {
                    try
                    {
                        var saveRq = new SecurityReportSaveRequest();
                        saveRq.SecurityReport.AddRange(updatedSecurityReports);
                        await context.Enterprise.Auth.ExecuteAuthRest(
                            "enterprise/save_summary_security_report", saveRq);
                        Console.WriteLine("Security scores pushed to Keeper.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error saving security reports: {ex.Message}");
                    }
                }
            }

            rows.Sort((a, b) => string.Compare(
                a["email"]?.ToString(), b["email"]?.ToString(), StringComparison.OrdinalIgnoreCase));

            OutputReport(options, rows, showBreachWatch);
        }

        private static readonly string[] SecurityScoreKeys =
        {
            "weak_record_passwords", "fair_record_passwords", "medium_record_passwords",
            "strong_record_passwords", "total_record_passwords", "unique_record_passwords"
        };

        private static readonly string[] BreachWatchScoreKeys =
        {
            "passed_records", "at_risk_records", "ignored_records"
        };

        private static Dictionary<string, int> FlattenReportData(string json, int numReusedPws)
        {
            var parsed = JsonUtils.ParseJson<DecryptedReportJson>(Encoding.UTF8.GetBytes(json));
            var secStats = parsed?.SecurityAuditStats;
            var bwStats = parsed?.BwStats;
            bool hasSecStats = secStats != null;

            int GetVal(
                Func<DecryptedReportJson, int> fromTop,
                Func<SecurityAuditStatsJson, int> fromSec,
                Func<BreachWatchStatsJson, int> fromBw)
            {
                var topVal = parsed != null ? fromTop(parsed) : 0;
                if (topVal != 0) return topVal;
                if (secStats != null)
                {
                    var secVal = fromSec(secStats);
                    if (secVal != 0) return secVal;
                }
                if (bwStats != null && fromBw != null)
                    return fromBw(bwStats);
                return 0;
            }

            var weak = GetVal(d => d.WeakRecordPasswords, s => s.WeakRecordPasswords, null);
            var fair = GetVal(d => d.FairRecordPasswords, s => s.FairRecordPasswords, null);
            var medium = GetVal(d => d.MediumRecordPasswords, s => s.MediumRecordPasswords, null);
            var strong = GetVal(d => d.StrongRecordPasswords, s => s.StrongRecordPasswords, null);
            var total = GetVal(d => d.TotalRecordPasswords, s => s.TotalRecordPasswords, null);
            var unique = total - numReusedPws;
            var passed = bwStats?.PassedRecords ?? 0;
            var atRisk = bwStats?.AtRiskRecords ?? 0;
            var ignored = bwStats?.IgnoredRecords ?? 0;

            if (!hasSecStats)
                medium = total - weak - strong;

            return new Dictionary<string, int>
            {
                ["weak_record_passwords"] = weak,
                ["fair_record_passwords"] = fair,
                ["medium_record_passwords"] = medium,
                ["strong_record_passwords"] = strong,
                ["total_record_passwords"] = total,
                ["unique_record_passwords"] = unique,
                ["passed_records"] = passed,
                ["at_risk_records"] = atRisk,
                ["ignored_records"] = ignored
            };
        }

        private static Dictionary<string, int> ApplyIncrementalUpdates(
            Dictionary<string, int> data,
            SecurityReport sr,
            RsaPrivateKey rsaKey,
            EcPrivateKey ecKey,
            ref bool hasErrors)
        {
            var updatedData = new Dictionary<string, int>(data);
            foreach (var incData in sr.SecurityReportIncrementalData)
            {
                var oldData = DecryptSecurityData(incData.OldSecurityData, incData.OldDataEncryptionType, rsaKey, ecKey);
                var currData = DecryptSecurityData(incData.CurrentSecurityData, incData.CurrentDataEncryptionType, rsaKey, ecKey);

                if ((oldData != null && !oldData.ContainsKey("strength")) ||
                    (currData != null && !currData.ContainsKey("strength")))
                {
                    hasErrors = true;
                    break;
                }

                if (oldData != null)
                {
                    var deltas = GetScoreDeltas(oldData, -1);
                    ApplyScoreDeltas(updatedData, deltas);
                }
                if (currData != null)
                {
                    var deltas = GetScoreDeltas(currData, 1);
                    ApplyScoreDeltas(updatedData, deltas);
                }
            }

            return hasErrors ? data : updatedData;
        }

        private static Dictionary<string, object> DecryptSecurityData(
            ByteString secData,
            global::Enterprise.EncryptedKeyType keyType,
            RsaPrivateKey rsaKey,
            EcPrivateKey ecKey)
        {
            if (secData == null || secData.IsEmpty) return null;
            var dataBytes = secData.ToByteArray();

            byte[] decryptedBytes;
            try
            {
                if (keyType == global::Enterprise.EncryptedKeyType.KtEncryptedByPublicKeyEcc)
                {
                    if (ecKey == null) return null;
                    decryptedBytes = CryptoUtils.DecryptEc(dataBytes, ecKey);
                }
                else
                {
                    if (rsaKey == null) return null;
                    decryptedBytes = CryptoUtils.DecryptRsa(dataBytes, rsaKey);
                }
            }
            catch
            {
                return null;
            }

            try
            {
                return JsonUtils.ParseJson<Dictionary<string, object>>(decryptedBytes);
            }
            catch
            {
                return null;
            }
        }

        private static string GetStrengthCategory(int score)
        {
            if (score >= 4) return "strong";
            if (score == 2) return "fair";
            if (score <= 1) return "weak";
            return "medium";
        }

        private static Dictionary<string, int> GetScoreDeltas(Dictionary<string, object> recSecData, int delta)
        {
            var deltas = new Dictionary<string, int>();
            foreach (var k in SecurityScoreKeys) deltas[k] = 0;
            foreach (var k in BreachWatchScoreKeys) deltas[k] = 0;

            int pwStrength = 0;
            if (recSecData.TryGetValue("strength", out var strengthObj))
                int.TryParse(strengthObj?.ToString(), out pwStrength);

            var secKey = GetStrengthCategory(pwStrength) + "_record_passwords";
            if (deltas.ContainsKey(secKey))
                deltas[secKey] = delta;
            deltas["total_record_passwords"] = delta;

            int bwResult = 0;
            if (recSecData.TryGetValue("bw_result", out var bwObj))
                int.TryParse(bwObj?.ToString(), out bwResult);

            var bwKey = bwResult == 2 ? "at_risk_records"
                : bwResult == 1 ? "passed_records"
                : "ignored_records";
            deltas[bwKey] = delta;

            return deltas;
        }

        private static void ApplyScoreDeltas(Dictionary<string, int> data, Dictionary<string, int> deltas)
        {
            foreach (var kvp in deltas)
            {
                if (data.ContainsKey(kvp.Key))
                    data[kvp.Key] += kvp.Value;
                else
                    data[kvp.Key] = kvp.Value;
            }
        }

        private static string FormatReportData(Dictionary<string, int> data)
        {
            var secStats = new Dictionary<string, int>();
            foreach (var k in SecurityScoreKeys)
                secStats[k] = data.TryGetValue(k, out var v) ? v : 0;

            var bwStats = new Dictionary<string, int>();
            foreach (var k in BreachWatchScoreKeys)
                bwStats[k] = data.TryGetValue(k, out var v) ? v : 0;

            var report = new Dictionary<string, object>
            {
                ["securityAuditStats"] = secStats,
                ["bwStats"] = bwStats
            };

            return Encoding.UTF8.GetString(JsonUtils.DumpJson(report, false));
        }

        private static double GetStrongByTotal(int total, int strong)
        {
            return total == 0 ? 0 : (double)strong / total;
        }

        private static double GetSecurityScore(int total, int strong, int unique, bool twofaOn)
        {
            var strongByTotal = GetStrongByTotal(total, strong);
            var uniqueByTotal = total == 0 ? 0.0 : (double)unique / total;
            var twoFactorOnVal = twofaOn ? 1.0 : 0.0;
            const double masterPasswordStrength = 1.0;
            return (strongByTotal + uniqueByTotal + masterPasswordStrength + twoFactorOnVal) / 4.0;
        }

        private static HashSet<long> ResolveNodeFilter(EnterpriseData enterpriseData, IEnumerable<string> nodeInputs)
        {
            if (nodeInputs == null || !nodeInputs.Any())
                return null;

            var nodeIds = new HashSet<long>();
            foreach (var input in nodeInputs)
            {
                var trimmed = input?.Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;

                EnterpriseNode node;
                try
                {
                    node = enterpriseData.ResolveNodeName(trimmed);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return null;
                }

                foreach (var childNode in EnterpriseExtensions.CollectNodeAndDescendants(enterpriseData, node))
                {
                    nodeIds.Add(childNode.Id);
                }
            }

            return nodeIds;
        }

        private static async Task ClearSecurityData(IEnterpriseContext context, List<long> userIds,
            global::Enterprise.ClearSecurityDataType clearType)
        {
            const int chunkSize = 999;
            for (int offset = 0; offset < userIds.Count; offset += chunkSize)
            {
                var count = Math.Min(chunkSize, userIds.Count - offset);
                var request = new global::Enterprise.ClearSecurityDataRequest();
                request.EnterpriseUserId.AddRange(userIds.GetRange(offset, count));
                request.Type = clearType;
                await context.Enterprise.Auth.ExecuteAuthRest("enterprise/clear_security_data", request);
            }

            Console.WriteLine($"Security data cleared for {userIds.Count} user(s).");
        }

        private static bool IsConfirmed(string response)
        {
            var trimmed = response?.Trim();
            return string.Equals(trimmed, "y", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(trimmed, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private static void OutputReport(SecurityAuditReportOptions options,
            List<Dictionary<string, object>> rows, bool showBreachWatch)
        {
            var format = (options.Format ?? "table").ToLowerInvariant();

            string[] fields;
            string[] displayHeaders;

            if (showBreachWatch)
            {
                fields = new[] { "email", "name", "sync_pending", "at_risk", "passed", "ignored" };
                displayHeaders = new[] { "Email", "Name", "Sync Pending", "At Risk", "Passed", "Ignored" };
            }
            else
            {
                fields = new[] { "email", "name", "sync_pending", "weak", "fair", "medium", "strong",
                    "reused", "unique", "securityScore", "twoFactorChannel", "node" };
                displayHeaders = new[] { "Email", "Name", "Sync Pending", "Weak", "Fair", "Medium", "Strong",
                    "Reused", "Unique", "Security Score", "2FA", "Node" };
            }

            var title = $"Security Audit Report{(showBreachWatch ? " (BreachWatch)" : "")}";

            TextWriter writer;
            bool shouldDispose = false;

            if (!string.IsNullOrEmpty(options.Output))
            {
                writer = new StreamWriter(options.Output);
                shouldDispose = true;
            }
            else
            {
                writer = Console.Out;
            }

            try
            {
                switch (format)
                {
                    case "json":
                        var jsonData = rows.Select(row =>
                        {
                            var dict = new Dictionary<string, object>();
                            foreach (var field in fields)
                                dict[field] = row.TryGetValue(field, out var v) ? v : "";
                            return dict;
                        }).ToList();
                        var jsonBytes = JsonUtils.DumpJson(jsonData, true);
                        writer.WriteLine(Encoding.UTF8.GetString(jsonBytes));
                        break;

                    case "csv":
                        writer.WriteLine(string.Join(",", displayHeaders.Select(EscapeCsv)));
                        foreach (var row in rows)
                        {
                            var vals = fields.Select(f => row.TryGetValue(f, out var v) ? v : "");
                            writer.WriteLine(string.Join(",", vals.Select(EscapeCsv)));
                        }
                        break;

                    default:
                        Console.WriteLine($"\n{title}");
                        var tab = new Tabulate(displayHeaders.Length) { DumpRowNo = true };
                        tab.AddHeader(displayHeaders);
                        foreach (var row in rows)
                        {
                            var vals = fields.Select(f => row.TryGetValue(f, out var v) ? v : "").ToArray();
                            tab.AddRow(vals);
                        }
                        if (writer != Console.Out)
                        {
                            var originalOut = Console.Out;
                            Console.SetOut(writer);
                            try { tab.Dump(); }
                            finally { Console.SetOut(originalOut); }
                        }
                        else
                        {
                            tab.Dump();
                        }
                        break;
                }
            }
            finally
            {
                if (shouldDispose)
                {
                    writer.Dispose();
                    Console.WriteLine($"Output written to {options.Output}");
                }
            }
        }

        private static string EscapeCsv(object val)
        {
            var s = val?.ToString() ?? "";
            if (s.Contains(",") || s.Contains("\"") || s.Contains("\n") || s.Contains("\r"))
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        private static void DisplaySyntaxHelp()
        {
            Console.WriteLine(@"
Security Audit Report Command Syntax Description:

Column Name       Description
  email             e-mail address
  name              user display name
  sync_pending      whether security data sync is pending
  weak              number of records whose password strength is in the weak category
  fair              number of records whose password strength is in the fair category
  medium            number of records whose password strength is in the medium category
  strong            number of records whose password strength is in the strong category
  reused            number of reused passwords
  unique            number of unique passwords
  securityScore     security score (0-100)
  twoFactorChannel  2FA - On/Off
  node              enterprise node path

BreachWatch Columns (with -b flag):
  at_risk           number of at-risk records
  passed            number of passed records
  ignored           number of ignored records

Switches:
  --format <{table,json,csv}>    format of the report
  --output <FILENAME>            output to the given filename
  --syntax-help                  display description of each column in the report
  -n, --node <name|UID>          name(s) or UID(s) of node(s) to filter results by
  -b, --breachwatch              display a BreachWatch security report (ignored if BreachWatch is not active)
  --show-updated                 calculate current security audit scores for each vault and display locally (preview)
  -s, --save                     similar to --show-updated, but also pushes updated scores to Keeper
  --score-type <type>            define how security scores are calculated: strong_passwords, default
  --attempt-fix                  hard sync for vaults with invalid security-data
  -f, --force                    skip confirmation prompts (non-interactive mode)

Examples:
  security-audit-report
  security-audit-report --format json --output security_score.json
  security-audit-report -b
  security-audit-report -s
  security-audit-report --score-type=strong_passwords --save
");
        }

        public static async Task BreachWatchReportCommand(this IEnterpriseContext context,
            BreachWatchReportOptions options, InputManager inputManager)
        {
            ValidateBreachWatchReporting(context);

            var sarOptions = new SecurityAuditReportOptions
            {
                Format = options.Format,
                Output = options.Output,
                BreachWatch = true,
                Save = true,
                Force = true
            };

            await context.SecurityAuditReportCommand(sarOptions, inputManager);
        }

        private static void ValidateBreachWatchReporting(IEnterpriseContext context)
        {
            if (!UserHasRunReportsPrivilege(context))
            {
                throw new Exception(
                    "You do not have the required privilege to run a BreachWatch report");
            }

            if (!IsAddonEnabled(context, "enterprise_breach_watch"))
            {
                throw new Exception(
                    "BreachWatch is not enabled for this enterprise.");
            }
        }

        private static bool UserHasRunReportsPrivilege(IEnterpriseContext context)
        {
            if (context is McEnterpriseContext)
                return true;

            if (context.EnterpriseData == null)
                return false;

            var username = context.Enterprise.Auth.Username;
            if (!context.EnterpriseData.TryGetUserByEmail(username, out var currentUser))
                return false;

            if (context.RoleManagement == null)
                return false;

            var userRoleIds = context.RoleManagement.GetRolesForUser(currentUser.Id).ToHashSet();
            return context.RoleManagement.GetManagedNodes()
                .Where(mn => userRoleIds.Contains(mn.RoleId))
                .SelectMany(mn => context.RoleManagement
                    .GetPrivilegesForRoleAndNode(mn.RoleId, mn.ManagedNodeId))
                .Any(rp => string.Equals(rp.PrivilegeType, "RUN_REPORTS",
                    StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsAddonEnabled(IEnterpriseContext context, string addonName)
        {
            var license = context.EnterpriseData.EnterpriseLicense;
            if (license == null)
                return false;

            if (string.Equals(license.LicenseStatus, "business_trial",
                    StringComparison.OrdinalIgnoreCase))
                return true;

            return license.AddOns.Any(a =>
                string.Equals(a.Name, addonName, StringComparison.OrdinalIgnoreCase)
                && (a.Enabled || a.IncludedInProduct));
        }
    }
}
