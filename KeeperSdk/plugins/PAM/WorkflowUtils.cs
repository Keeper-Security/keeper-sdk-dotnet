using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Google.Protobuf;
using GraphSync;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Workflow;
using DayOfWeek = Workflow.DayOfWeek;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Helpers for PAM workflow configuration via the Keeper Router.
  /// </summary>
  public static class WorkflowUtils
  {
    private const string CreateWorkflowConfigPath = "create_workflow_config";
    private const string ReadWorkflowConfigPath = "read_workflow_config";
    private const string UpdateWorkflowConfigPath = "update_workflow_config";
    private const string DeleteWorkflowConfigPath = "delete_workflow_config";
    private const string AddWorkflowApproversPath = "add_workflow_approvers";
    private const string DeleteWorkflowApproversPath = "delete_workflow_approvers";
    private const string GetApprovalRequestsPath = "get_approval_requests";
    private const string GetWorkflowStatePath = "get_workflow_state";
    private const string GetUserAccessStatePath = "get_user_access_state";
    private const string ApproveOrDenyWorkflowAccessPath = "approve_or_deny_workflow_access";
    private const string RequestWorkflowAccessPath = "request_workflow_access";
    private const string RequestEscalationPath = "request_escalation";
    private const string StartWorkflowPath = "start_workflow";
    private const string EndWorkflowPath = "end_workflow";
    private const string ForceCheckinPath = "force_checkin";
    private const string AllowConfigureWorkflowSettings = "allow_configure_workflow_settings";

    private static readonly Regex ProtoDumpRe = new Regex(
      @"\s*(?:type|value|name|stage|conditions|flowUid|resource)\s*:\s*(?:""[^""]*""|\S+)\s*",
      RegexOptions.Compiled);
    private static readonly Regex ResponseCodeRe = new Regex(
      @"\s*[Rr]esponse\s+code:\s*\S+\s*$",
      RegexOptions.Compiled);

    private static readonly Dictionary<string, long> DurationMultipliers = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
    {
      ["d"] = 86_400_000L,
      ["h"] = 3_600_000L,
      ["m"] = 60_000L,
    };

    private static readonly Dictionary<DayOfWeek, string> DayNameMap =
      new Dictionary<DayOfWeek, string>
      {
        [DayOfWeek.Monday] = "Monday",
        [DayOfWeek.Tuesday] = "Tuesday",
        [DayOfWeek.Wednesday] = "Wednesday",
        [DayOfWeek.Thursday] = "Thursday",
        [DayOfWeek.Friday] = "Friday",
        [DayOfWeek.Saturday] = "Saturday",
        [DayOfWeek.Sunday] = "Sunday",
      };

    private static readonly Dictionary<string, DayOfWeek> DayParseMap = BuildDayParseMap();

    private static Dictionary<string, DayOfWeek> BuildDayParseMap()
    {
      var map = new Dictionary<string, DayOfWeek>(StringComparer.OrdinalIgnoreCase);
      foreach (var pair in DayNameMap)
      {
        map[pair.Value] = pair.Key;
        if (pair.Value.Length >= 3)
        {
          map[pair.Value.Substring(0, 3)] = pair.Key;
        }
      }

      return map;
    }

    public static bool CanManageWorkflowSettings(IAuthentication auth)
    {
      if (auth?.AuthContext?.Enforcements == null)
      {
        return false;
      }

      if (!auth.AuthContext.Enforcements.TryGetValue(AllowConfigureWorkflowSettings, out var value))
      {
        return false;
      }

      if (value is bool b)
      {
        return b;
      }

      if (value != null && bool.TryParse(value.ToString(), out var parsed))
      {
        return parsed;
      }

      return false;
    }

    public static GraphSyncRef RecordRef(byte[] recordUidBytes, string recordName = null)
    {
      if (recordUidBytes == null || recordUidBytes.Length == 0)
      {
        throw new ArgumentException("Record UID bytes are required", nameof(recordUidBytes));
      }

      var refMsg = new GraphSyncRef
      {
        Type = RefType.RftRec,
        Value = ByteString.CopyFrom(recordUidBytes),
      };
      if (!string.IsNullOrEmpty(recordName))
      {
        refMsg.Name = recordName;
      }

      return refMsg;
    }

    public static GraphSyncRef RecordRef(string recordUid, string recordName = null)
    {
      if (string.IsNullOrWhiteSpace(recordUid))
      {
        throw new ArgumentException("Record UID is required", nameof(recordUid));
      }

      return RecordRef(recordUid.Base64UrlDecode(), recordName);
    }

    public static GraphSyncRef WorkflowRef(byte[] flowUidBytes)
    {
      if (flowUidBytes == null || flowUidBytes.Length == 0)
      {
        throw new ArgumentException("Flow UID bytes are required", nameof(flowUidBytes));
      }

      return new GraphSyncRef
      {
        Type = RefType.RftWorkflow,
        Value = ByteString.CopyFrom(flowUidBytes),
      };
    }

    public static GraphSyncRef WorkflowRef(string flowUid)
    {
      if (string.IsNullOrWhiteSpace(flowUid))
      {
        throw new ArgumentException("Flow UID is required", nameof(flowUid));
      }

      return WorkflowRef(flowUid.Base64UrlDecode());
    }

    public static long ParseDuration(string durationStr)
    {
      if (string.IsNullOrWhiteSpace(durationStr))
      {
        throw new ArgumentException(
          "Invalid duration format. Use a positive value like \"2h\", \"30m\", \"1d\", or bare minutes (e.g. \"90\")");
      }

      var normalized = durationStr.Trim().ToLowerInvariant();
      foreach (var pair in DurationMultipliers)
      {
        if (!normalized.EndsWith(pair.Key, StringComparison.Ordinal))
        {
          continue;
        }

        var numberPart = normalized.Substring(0, normalized.Length - pair.Key.Length);
        if (!int.TryParse(numberPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) || value <= 0)
        {
          throw new ArgumentException(
            $"Invalid duration format: {durationStr}. Use a positive value like \"2h\", \"30m\", \"1d\", or bare minutes (e.g. \"90\")");
        }

        return value * pair.Value;
      }

      if (!int.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes) || minutes <= 0)
      {
        throw new ArgumentException(
          $"Invalid duration format: {durationStr}. Use a positive value like \"2h\", \"30m\", \"1d\", or bare minutes (e.g. \"90\")");
      }

      return minutes * 60_000L;
    }

    public static string FormatDuration(long milliseconds)
    {
      if (milliseconds <= 0)
      {
        return "0 seconds";
      }

      var seconds = milliseconds / 1000;
      var days = seconds / 86_400;
      seconds %= 86_400;
      var hours = seconds / 3_600;
      seconds %= 3_600;
      var minutes = seconds / 60;
      seconds %= 60;

      var parts = new List<string>();
      AppendDurationPart(parts, days, "day");
      AppendDurationPart(parts, hours, "hour");
      AppendDurationPart(parts, minutes, "minute");
      if (parts.Count == 0 || seconds > 0)
      {
        parts.Add(seconds == 1 ? "1 second" : $"{seconds} seconds");
      }

      return string.Join(" ", parts);
    }

    private static void AppendDurationPart(List<string> parts, long value, string unit)
    {
      if (value <= 0)
      {
        return;
      }

      parts.Add(value == 1 ? $"1 {unit}" : $"{value} {unit}s");
    }

    public static string FormatDayName(DayOfWeek day)
    {
      return DayNameMap.TryGetValue(day, out var name) ? name : day.ToString();
    }

    public static string FormatStage(WorkflowStatus status)
    {
      if (status == null)
      {
        return "Unknown";
      }

      if (status.Stage == WorkflowStage.WsReadyToStart)
      {
        if (status.Conditions.Count > 0)
        {
          var hasBlocking = status.Conditions.Any(c =>
            c == AccessCondition.AcTime || c == AccessCondition.AcApproval);
          return hasBlocking ? "Waiting" : "Ready to Start";
        }

        if (status.StartedOn == 0 && status.ApprovedBy.Count == 0)
        {
          return "Needs Action";
        }

        // Approved-but-not-started, or StartedOn != 0 while stage is still WS_READY_TO_START.
        return "Ready to Start";
      }

      switch (status.Stage)
      {
        case WorkflowStage.WsStarted:
          return "Started";
        case WorkflowStage.WsNeedsAction:
          return "Needs Action";
        case WorkflowStage.WsWaiting:
          return "Waiting";
        default:
          return $"Unknown ({status.Stage})";
      }
    }

    public static string FormatCondition(AccessCondition condition)
    {
      switch (condition)
      {
        case AccessCondition.AcApproval:
          return "Approval Required";
        case AccessCondition.AcCheckin:
          return "Check-in Required";
        case AccessCondition.AcMfa:
          return "MFA Required";
        case AccessCondition.AcTime:
          return "Time Restriction";
        case AccessCondition.AcReason:
          return "Reason Required";
        case AccessCondition.AcTicket:
          return "Ticket Required";
        default:
          return $"Unknown ({condition})";
      }
    }

    public static string FormatConditions(IEnumerable<AccessCondition> conditions)
    {
      if (conditions == null)
      {
        return string.Empty;
      }

      return string.Join(", ", conditions.Select(FormatCondition));
    }

    public static Dictionary<string, object> FormatTemporalFilter(TemporalAccessFilter filter)
    {
      if (filter == null)
      {
        return null;
      }

      var result = new Dictionary<string, object>();
      if (filter.AllowedDays.Count > 0)
      {
        result["allowed_days"] = filter.AllowedDays.Select(FormatDayName).ToList();
      }

      if (filter.TimeRanges.Count > 0)
      {
        var ranges = new List<string>();
        foreach (var tr in filter.TimeRanges)
        {
          var startH = Math.DivRem(tr.StartTime, 100, out var startM);
          var endH = Math.DivRem(tr.EndTime, 100, out var endM);
          ranges.Add($"{startH:D2}:{startM:D2}-{endH:D2}:{endM:D2}");
        }

        result["time_ranges"] = ranges;
      }

      if (!string.IsNullOrEmpty(filter.TimeZone))
      {
        result["timezone"] = filter.TimeZone;
      }

      return result.Count > 0 ? result : null;
    }

    public static TemporalAccessFilter BuildTemporalFilter(string allowedDaysStr, string timeRangeStr)
    {
      return BuildTemporalFilter(allowedDaysStr, timeRangeStr, existing: null);
    }

    public static TemporalAccessFilter BuildTemporalFilter(
      string allowedDaysStr,
      string timeRangeStr,
      TemporalAccessFilter existing)
    {
      var hasDays = !string.IsNullOrWhiteSpace(allowedDaysStr);
      var hasRange = !string.IsNullOrWhiteSpace(timeRangeStr);
      if (!hasDays && !hasRange)
      {
        return null;
      }

      var temporal = existing?.Clone() ?? new TemporalAccessFilter();

      if (hasDays)
      {
        temporal.AllowedDays.Clear();
        foreach (var token in allowedDaysStr.Split(','))
        {
          var dayToken = token.Trim();
          if (string.IsNullOrEmpty(dayToken))
          {
            continue;
          }

          if (!DayParseMap.TryGetValue(dayToken, out var dayEnum))
          {
            throw new ArgumentException(
              $"Invalid day: \"{dayToken}\". Valid: mon, tue, wed, thu, fri, sat, sun");
          }

          temporal.AllowedDays.Add(dayEnum);
        }
      }

      if (hasRange)
      {
        var dash = timeRangeStr.IndexOf('-');
        if (dash < 0)
        {
          throw new ArgumentException(
            "Time range must be in HH:MM-HH:MM format (e.g., \"09:00-17:00\")");
        }

        var startStr = timeRangeStr.Substring(0, dash).Trim();
        var endStr = timeRangeStr.Substring(dash + 1).Trim();
        var startHhmm = ParseTimeToHhmm(startStr);
        var endHhmm = ParseTimeToHhmm(endStr);
        if (startHhmm >= endHhmm)
        {
          throw new ArgumentException(
            $"End time must be after start time (got \"{startStr}-{endStr}\"). "
            + "Same-day ranges only; overnight windows must be split "
            + "(e.g. 22:00-23:59 and 00:00-06:00).");
        }

        temporal.TimeRanges.Clear();
        temporal.TimeRanges.Add(new TimeOfDayRange
        {
          StartTime = startHhmm,
          EndTime = endHhmm,
        });
      }

      if (string.IsNullOrEmpty(temporal.TimeZone))
      {
        temporal.TimeZone = GetLocalIanaTimezone();
      }

      return temporal;
    }

    public static string SanitizeRouterError(Exception error)
    {
      if (error == null)
      {
        return "Unknown error";
      }

      var msg = error.Message ?? string.Empty;
      msg = ResponseCodeRe.Replace(msg, string.Empty);
      msg = ProtoDumpRe.Replace(msg, string.Empty);
      msg = Regex.Replace(msg, @"\s+", " ").Trim();
      return string.IsNullOrEmpty(msg) ? "Unknown error" : msg;
    }

    public static async Task<WorkflowConfig> ReadWorkflowConfigAsync(
      IAuthentication auth,
      string recordUid,
      string recordName = null)
    {
      var refMsg = RecordRef(recordUid, recordName);
      var config = await auth.ExecuteRouter<WorkflowConfig>(ReadWorkflowConfigPath, refMsg);

      if (config == null
          || (config.Parameters == null && config.Approvers.Count == 0 && config.CreatedOn == 0))
      {
        return null;
      }

      return config;
    }

    public static async Task CreateWorkflowConfigAsync(IAuthentication auth, WorkflowParameters parameters)
    {
      if (parameters == null)
      {
        throw new ArgumentNullException(nameof(parameters));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(CreateWorkflowConfigPath, parameters, null);
    }

    public static async Task UpdateWorkflowConfigAsync(IAuthentication auth, WorkflowParameters parameters)
    {
      if (parameters == null)
      {
        throw new ArgumentNullException(nameof(parameters));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(UpdateWorkflowConfigPath, parameters, null);
    }

    public static async Task DeleteWorkflowConfigAsync(
      IAuthentication auth,
      string recordUid,
      string recordName = null)
    {
      var refMsg = RecordRef(recordUid, recordName);
      await auth.ExecuteRouter<IMessage, IMessage>(DeleteWorkflowConfigPath, refMsg, null);
    }

    public static async Task AddWorkflowApproversAsync(
      IAuthentication auth,
      string recordUid,
      string recordName,
      IEnumerable<string> users = null,
      IEnumerable<string> teamUids = null,
      bool isEscalation = false,
      long escalationAfterMs = 0)
    {
      var config = BuildApproverConfig(recordUid, recordName, users, teamUids, isEscalation, escalationAfterMs);
      if (config.Approvers.Count == 0)
      {
        return;
      }

      await auth.ExecuteRouter<IMessage, IMessage>(AddWorkflowApproversPath, config, null);
    }

    public static async Task DeleteWorkflowApproversAsync(
      IAuthentication auth,
      string recordUid,
      string recordName,
      IEnumerable<string> users = null,
      IEnumerable<string> teamUids = null)
    {
      var config = BuildApproverConfig(recordUid, recordName, users, teamUids);
      if (config.Approvers.Count == 0)
      {
        return;
      }

      await auth.ExecuteRouter<IMessage, IMessage>(DeleteWorkflowApproversPath, config, null);
    }

    public static async Task<ApprovalRequests> GetApprovalRequestsAsync(IAuthentication auth)
    {
      return await auth.ExecuteRouter<ApprovalRequests>(GetApprovalRequestsPath);
    }

    public static async Task<WorkflowState> GetWorkflowStateByFlowAsync(
      IAuthentication auth,
      ByteString flowUid)
    {
      if (flowUid == null || flowUid.IsEmpty)
      {
        throw new ArgumentException("Flow UID is required", nameof(flowUid));
      }

      var request = new WorkflowState { FlowUid = flowUid };
      return await auth.ExecuteRouter<WorkflowState>(GetWorkflowStatePath, request);
    }

    public static async Task ApproveWorkflowAccessAsync(IAuthentication auth, byte[] flowUidBytes)
    {
      await ApproveOrDenyWorkflowAccessAsync(auth, flowUidBytes, deny: false, denialReasonEncrypted: null);
    }

    public static async Task DenyWorkflowAccessAsync(
      IAuthentication auth,
      byte[] flowUidBytes,
      ByteString denialReasonEncrypted = null)
    {
      await ApproveOrDenyWorkflowAccessAsync(auth, flowUidBytes, deny: true, denialReasonEncrypted);
    }

    public static async Task ApproveOrDenyWorkflowAccessAsync(
      IAuthentication auth,
      byte[] flowUidBytes,
      bool deny,
      ByteString denialReasonEncrypted = null)
    {
      if (flowUidBytes == null || flowUidBytes.Length == 0)
      {
        throw new ArgumentException("Flow UID is required", nameof(flowUidBytes));
      }

      var approval = new WorkflowApprovalOrDenial
      {
        FlowUid = ByteString.CopyFrom(flowUidBytes),
        Deny = deny,
      };
      if (denialReasonEncrypted != null && !denialReasonEncrypted.IsEmpty)
      {
        approval.DenialReason = denialReasonEncrypted;
      }

      await auth.ExecuteRouter<IMessage, IMessage>(ApproveOrDenyWorkflowAccessPath, approval, null);
    }

    public static async Task<WorkflowState> GetWorkflowStateByRecordAsync(
      IAuthentication auth,
      string recordUid,
      string recordName = null)
    {
      var request = new WorkflowState
      {
        Resource = RecordRef(recordUid, recordName),
      };
      return await auth.ExecuteRouter<WorkflowState>(GetWorkflowStatePath, request);
    }

    public static async Task<UserAccessState> GetUserAccessStateAsync(IAuthentication auth)
    {
      return await auth.ExecuteRouter<UserAccessState>(GetUserAccessStatePath);
    }

    public static async Task RequestWorkflowAccessAsync(
      IAuthentication auth,
      string recordUid,
      string recordName,
      byte[] recordKey,
      string reason = null,
      string ticket = null)
    {
      var needsEncrypted = !string.IsNullOrEmpty(reason) || !string.IsNullOrEmpty(ticket);
      if (needsEncrypted && (recordKey == null || recordKey.Length == 0))
      {
        throw new InvalidOperationException(
          "Record key not available — cannot encrypt reason/ticket. " +
          "You do not have sufficient access to this record to send encrypted parameters.");
      }

      var accessRequest = new WorkflowAccessRequest
      {
        Resource = RecordRef(recordUid, recordName),
      };
      if (!string.IsNullOrEmpty(reason))
      {
        accessRequest.Reason = ByteString.CopyFrom(
          CryptoUtils.EncryptAesV2(System.Text.Encoding.UTF8.GetBytes(reason), recordKey));
      }

      if (!string.IsNullOrEmpty(ticket))
      {
        accessRequest.Ticket = ByteString.CopyFrom(
          CryptoUtils.EncryptAesV2(System.Text.Encoding.UTF8.GetBytes(ticket), recordKey));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(RequestWorkflowAccessPath, accessRequest, null);
    }

    public static async Task RequestEscalationAsync(
      IAuthentication auth,
      string recordUid,
      string recordName = null)
    {
      var state = new WorkflowState
      {
        Resource = RecordRef(recordUid, recordName),
      };
      await auth.ExecuteRouter<IMessage, IMessage>(RequestEscalationPath, state, null);
    }

    public static async Task StartWorkflowAsync(IAuthentication auth, WorkflowState state)
    {
      if (state == null)
      {
        throw new ArgumentNullException(nameof(state));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(StartWorkflowPath, state, null);
    }

    public static async Task EndWorkflowAsync(IAuthentication auth, GraphSyncRef flowOrResourceRef)
    {
      if (flowOrResourceRef == null)
      {
        throw new ArgumentNullException(nameof(flowOrResourceRef));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(EndWorkflowPath, flowOrResourceRef, null);
    }

    public static async Task ForceCheckinAsync(IAuthentication auth, GraphSyncRef flowOrResourceRef)
    {
      if (flowOrResourceRef == null)
      {
        throw new ArgumentNullException(nameof(flowOrResourceRef));
      }

      await auth.ExecuteRouter<IMessage, IMessage>(ForceCheckinPath, flowOrResourceRef, null);
    }

    public static async Task<ByteString> TryEncryptDenialReasonAsync(
      IAuthentication auth,
      byte[] flowUidBytes,
      string reason)
    {
      if (auth == null || flowUidBytes == null || string.IsNullOrEmpty(reason))
      {
        return null;
      }

      try
      {
        var response = await GetApprovalRequestsAsync(auth);
        if (response?.Workflows == null || response.Workflows.Count == 0)
        {
          return null;
        }

        string requesterEmail = null;
        foreach (var wf in response.Workflows)
        {
          if (!FlowUidEquals(wf.FlowUid, flowUidBytes))
          {
            continue;
          }

          requesterEmail = !string.IsNullOrEmpty(wf.User) ? wf.User : null;
          break;
        }

        if (string.IsNullOrEmpty(requesterEmail) || requesterEmail.StartsWith("User ID ", StringComparison.Ordinal))
        {
          return null;
        }

        await auth.LoadUsersKeys(new[] { requesterEmail });
        if (!auth.TryGetUserKeys(requesterEmail, out var keys) || keys == null)
        {
          return null;
        }

        var reasonBytes = System.Text.Encoding.UTF8.GetBytes(reason);
        if (keys.EcPublicKey != null && keys.EcPublicKey.Length > 0)
        {
          var ecPk = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
          return ByteString.CopyFrom(CryptoUtils.EncryptEc(reasonBytes, ecPk));
        }

        if (keys.RsaPublicKey != null && keys.RsaPublicKey.Length > 0)
        {
          var rsaPk = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
          return ByteString.CopyFrom(CryptoUtils.EncryptRsa(reasonBytes, rsaPk));
        }
      }
      catch (Exception ex)
      {
        Trace.TraceWarning($"TryEncryptDenialReasonAsync failed: {ex}");
        return null;
      }

      return null;
    }

    public static async Task<bool> IsWorkflowExemptAsync(
      IAuthentication auth,
      KeeperSecurity.Vault.KeeperRecord record,
      IEnumerable<string> userTeamUids = null)
    {
      if (record == null)
      {
        return false;
      }

      if (record.Owner)
      {
        return true;
      }

      try
      {
        var config = await ReadWorkflowConfigAsync(auth, record.Uid, record.Title);
        if (config?.Approvers == null || config.Approvers.Count == 0)
        {
          return false;
        }

        var currentUser = auth?.Username ?? string.Empty;
        var teamSet = new HashSet<string>(userTeamUids ?? Array.Empty<string>(), StringComparer.Ordinal);
        foreach (var approver in config.Approvers)
        {
          if (approver.HasUser
              && string.Equals(approver.User, currentUser, StringComparison.OrdinalIgnoreCase))
          {
            return true;
          }

          if (approver.HasTeamUid)
          {
            var teamUid = approver.TeamUid.ToByteArray().Base64UrlEncode();
            if (teamSet.Contains(teamUid))
            {
              return true;
            }
          }
        }
      }
      catch (Exception ex)
      {
        Trace.TraceWarning(
          $"IsWorkflowExemptAsync failed for record {record.Uid}: {ex.Message}. " +
          "Treating user as not exempt.");
        Console.Error.WriteLine(
          "Warning: could not verify workflow exemption; continuing with the normal request flow.");
        return false;
      }

      return false;
    }

    public static async Task<IList<WorkflowProcess>> FilterPendingApprovalsAsync(
      IAuthentication auth,
      IEnumerable<WorkflowProcess> workflows,
      string currentUsername)
    {
      var unique = new List<WorkflowProcess>();
      var seen = new HashSet<string>(StringComparer.Ordinal);
      foreach (var wf in workflows ?? Array.Empty<WorkflowProcess>())
      {
        if (wf?.FlowUid == null || wf.FlowUid.IsEmpty)
        {
          continue;
        }

        var flowKey = wf.FlowUid.ToByteArray().Base64UrlEncode();
        if (!seen.Add(flowKey))
        {
          continue;
        }

        if (!string.IsNullOrEmpty(currentUsername)
            && string.Equals(wf.User, currentUsername, StringComparison.OrdinalIgnoreCase))
        {
          continue;
        }

        unique.Add(wf);
      }

      // Match Python Commander: check approval state one flow at a time (sequential).
      var pending = new List<WorkflowProcess>();
      foreach (var wf in unique)
      {
        if (!await IsAlreadyApprovedByUserAsync(auth, wf, currentUsername).ConfigureAwait(false))
        {
          pending.Add(wf);
        }
      }

      return pending;
    }

    public static async Task<bool> IsAlreadyApprovedByUserAsync(
      IAuthentication auth,
      WorkflowProcess process,
      string currentUsername)
    {
      if (auth == null || process == null || string.IsNullOrEmpty(currentUsername))
      {
        return false;
      }

      try
      {
        var state = await GetWorkflowStateByFlowAsync(auth, process.FlowUid).ConfigureAwait(false);
        if (state?.Status?.ApprovedBy == null || state.Status.ApprovedBy.Count == 0)
        {
          return false;
        }

        return state.Status.ApprovedBy.Any(a =>
          string.Equals(a.User, currentUsername, StringComparison.OrdinalIgnoreCase));
      }
      catch (Exception ex)
      {
        Trace.TraceWarning($"IsAlreadyApprovedByUserAsync failed: {ex}");
        return false;
      }
    }

    public static ByteString ExtractWorkflowParameter(WorkflowProcess process, string key)
    {
      if (process?.WorkflowParameters == null || string.IsNullOrEmpty(key))
      {
        return null;
      }

      foreach (var parameter in process.WorkflowParameters)
      {
        if (string.Equals(parameter.Key, key, StringComparison.Ordinal))
        {
          return parameter.Data;
        }
      }

      return null;
    }

    public static string DecryptWorkflowParameter(byte[] recordKey, ByteString encryptedBytes)
    {
      if (encryptedBytes == null || encryptedBytes.IsEmpty)
      {
        return null;
      }

      if (recordKey == null || recordKey.Length == 0)
      {
        return "No permission to view. Only users with record access can view this information.";
      }

      try
      {
        var plain = CryptoUtils.DecryptAesV2(encryptedBytes.ToByteArray(), recordKey);
        return System.Text.Encoding.UTF8.GetString(plain);
      }
      catch (Exception ex)
      {
        Trace.TraceWarning($"DecryptWorkflowParameter failed: {ex}");
        return "Unable to decrypt";
      }
    }

    private static WorkflowConfig BuildApproverConfig(
      string recordUid,
      string recordName,
      IEnumerable<string> users,
      IEnumerable<string> teamUids,
      bool isEscalation = false,
      long escalationAfterMs = 0)
    {
      var config = new WorkflowConfig
      {
        Parameters = new WorkflowParameters
        {
          Resource = RecordRef(recordUid, recordName),
        },
      };

      foreach (var userEmail in users ?? Array.Empty<string>())
      {
        if (string.IsNullOrWhiteSpace(userEmail))
        {
          continue;
        }

        var approver = new WorkflowApprover
        {
          User = userEmail.Trim(),
          Escalation = isEscalation,
        };
        if (escalationAfterMs > 0)
        {
          approver.EscalationAfterMs = escalationAfterMs;
        }

        config.Approvers.Add(approver);
      }

      foreach (var teamUid in teamUids ?? Array.Empty<string>())
      {
        if (string.IsNullOrWhiteSpace(teamUid))
        {
          continue;
        }

        var approver = new WorkflowApprover
        {
          TeamUid = ByteString.CopyFrom(teamUid.Trim().Base64UrlDecode()),
          Escalation = isEscalation,
        };
        if (escalationAfterMs > 0)
        {
          approver.EscalationAfterMs = escalationAfterMs;
        }

        config.Approvers.Add(approver);
      }

      return config;
    }

    private static bool FlowUidEquals(ByteString flowUid, byte[] flowUidBytes)
    {
      if (flowUid == null || flowUid.IsEmpty || flowUidBytes == null || flowUidBytes.Length == 0)
      {
        return false;
      }

      var span = flowUid.Span;
      return span.Length == flowUidBytes.Length && span.SequenceEqual(flowUidBytes);
    }

    private static int ParseTimeToHhmm(string timeStr)
    {
      try
      {
        var parts = timeStr.Split(':');
        var h = int.Parse(parts[0], CultureInfo.InvariantCulture);
        var m = parts.Length > 1 ? int.Parse(parts[1], CultureInfo.InvariantCulture) : 0;
        if (h < 0 || h > 23 || m < 0 || m > 59)
        {
          throw new ArgumentException();
        }

        return h * 100 + m;
      }
      catch (Exception ex) when (ex is FormatException || ex is OverflowException
                                 || ex is IndexOutOfRangeException || ex is ArgumentException)
      {
        throw new ArgumentException($"Invalid time format: \"{timeStr}\". Use HH:MM (e.g., \"09:00\")");
      }
    }

    private static string GetLocalIanaTimezone()
    {
      var tz = TryNormalizeIanaTimezone(Environment.GetEnvironmentVariable("TZ"));
      if (tz != null)
      {
        return tz;
      }

#if NET8_0_OR_GREATER
      if (TimeZoneInfo.TryConvertWindowsIdToIanaId(TimeZoneInfo.Local.Id, out var iana)
          && TryNormalizeIanaTimezone(iana) != null)
      {
        return iana;
      }
#endif

      var localId = TimeZoneInfo.Local.Id;
      var localIana = TryNormalizeIanaTimezone(localId);
      if (localIana != null)
      {
        return localIana;
      }

      if (WindowsToIana.TryGetValue(localId, out var mapped))
      {
        var mappedIana = TryNormalizeIanaTimezone(mapped);
        if (mappedIana != null)
        {
          return mappedIana;
        }
      }

      throw new InvalidOperationException(
        "Could not detect local IANA timezone. Set the TZ environment variable " +
        "(e.g., TZ=America/New_York or TZ=Asia/Kolkata).");
    }

    /// <summary>
    /// Returns a canonical IANA timezone id, or null if the value is empty, a TZ path, or not IANA-shaped.
    /// </summary>
    private static string TryNormalizeIanaTimezone(string tz)
    {
      if (string.IsNullOrWhiteSpace(tz))
      {
        return null;
      }

      tz = tz.Trim();
      if (tz[0] == ':')
      {
        tz = tz.Substring(1).Trim();
      }

      if (string.IsNullOrEmpty(tz))
      {
        return null;
      }

      if (string.Equals(tz, "UTC", StringComparison.OrdinalIgnoreCase)
          || string.Equals(tz, "GMT", StringComparison.OrdinalIgnoreCase))
      {
        return tz.ToUpperInvariant();
      }

      if (tz[0] == '/' || tz[0] == '\\'
          || tz.IndexOf('\\') >= 0
          || tz.IndexOf("..", StringComparison.Ordinal) >= 0
          || tz.IndexOf("zoneinfo", StringComparison.OrdinalIgnoreCase) >= 0)
      {
        return null;
      }

      var slash = tz.IndexOf('/');
      if (slash <= 0 || slash == tz.Length - 1)
      {
        return null;
      }

      for (var i = 0; i < tz.Length; i++)
      {
        var c = tz[i];
        if (c == '/' || c == '_' || c == '-' || c == '+' || char.IsLetterOrDigit(c))
        {
          continue;
        }

        return null;
      }

      var parts = tz.Split('/');
      if (parts.Length < 2)
      {
        return null;
      }

      foreach (var part in parts)
      {
        if (string.IsNullOrEmpty(part))
        {
          return null;
        }
      }

#if NET8_0_OR_GREATER
      try
      {
        TimeZoneInfo.FindSystemTimeZoneById(tz);
      }
      catch (TimeZoneNotFoundException)
      {
        // Well-formed IANA ids are still accepted for TZ overrides on hosts
        // that do not ship that zone; path-shaped values were already rejected.
      }
      catch (InvalidTimeZoneException)
      {
        return null;
      }
#endif

      return tz;
    }

    private static readonly Dictionary<string, string> WindowsToIana =
      new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
      {
        ["UTC"] = "Etc/UTC",
        ["GMT Standard Time"] = "Europe/London",
        ["Greenwich Standard Time"] = "Etc/GMT",
        ["Hawaiian Standard Time"] = "Pacific/Honolulu",
        ["Alaskan Standard Time"] = "America/Anchorage",
        ["Pacific Standard Time"] = "America/Los_Angeles",
        ["Pacific Standard Time (Mexico)"] = "America/Tijuana",
        ["US Mountain Standard Time"] = "America/Phoenix",
        ["Mountain Standard Time"] = "America/Denver",
        ["Mountain Standard Time (Mexico)"] = "America/Mazatlan",
        ["Central Standard Time"] = "America/Chicago",
        ["Central Standard Time (Mexico)"] = "America/Mexico_City",
        ["Canada Central Standard Time"] = "America/Regina",
        ["Eastern Standard Time"] = "America/New_York",
        ["Eastern Standard Time (Mexico)"] = "America/Cancun",
        ["US Eastern Standard Time"] = "America/Indiana/Indianapolis",
        ["Atlantic Standard Time"] = "America/Halifax",
        ["Newfoundland Standard Time"] = "America/St_Johns",
        ["SA Pacific Standard Time"] = "America/Bogota",
        ["SA Western Standard Time"] = "America/La_Paz",
        ["SA Eastern Standard Time"] = "America/Cayenne",
        ["Pacific SA Standard Time"] = "America/Santiago",
        ["E. South America Standard Time"] = "America/Sao_Paulo",
        ["Argentina Standard Time"] = "America/Argentina/Buenos_Aires",
        ["Venezuela Standard Time"] = "America/Caracas",
        ["Paraguay Standard Time"] = "America/Asuncion",
        ["Central Brazilian Standard Time"] = "America/Cuiaba",
        ["Greenland Standard Time"] = "America/Nuuk",
        ["Montevideo Standard Time"] = "America/Montevideo",
        ["Azores Standard Time"] = "Atlantic/Azores",
        ["Cape Verde Standard Time"] = "Atlantic/Cape_Verde",
        ["Morocco Standard Time"] = "Africa/Casablanca",
        ["W. Europe Standard Time"] = "Europe/Berlin",
        ["Romance Standard Time"] = "Europe/Paris",
        ["Central Europe Standard Time"] = "Europe/Budapest",
        ["Central European Standard Time"] = "Europe/Warsaw",
        ["W. Central Africa Standard Time"] = "Africa/Lagos",
        ["GTB Standard Time"] = "Europe/Bucharest",
        ["FLE Standard Time"] = "Europe/Kyiv",
        ["E. Europe Standard Time"] = "Europe/Chisinau",
        ["Turkey Standard Time"] = "Europe/Istanbul",
        ["Russian Standard Time"] = "Europe/Moscow",
        ["South Africa Standard Time"] = "Africa/Johannesburg",
        ["Egypt Standard Time"] = "Africa/Cairo",
        ["Libya Standard Time"] = "Africa/Tripoli",
        ["Israel Standard Time"] = "Asia/Jerusalem",
        ["Jordan Standard Time"] = "Asia/Amman",
        ["Middle East Standard Time"] = "Asia/Beirut",
        ["Syria Standard Time"] = "Asia/Damascus",
        ["Arabic Standard Time"] = "Asia/Baghdad",
        ["Arab Standard Time"] = "Asia/Riyadh",
        ["Arabian Standard Time"] = "Asia/Dubai",
        ["Iran Standard Time"] = "Asia/Tehran",
        ["Afghanistan Standard Time"] = "Asia/Kabul",
        ["Pakistan Standard Time"] = "Asia/Karachi",
        ["India Standard Time"] = "Asia/Kolkata",
        ["Sri Lanka Standard Time"] = "Asia/Colombo",
        ["Nepal Standard Time"] = "Asia/Kathmandu",
        ["Bangladesh Standard Time"] = "Asia/Dhaka",
        ["Myanmar Standard Time"] = "Asia/Yangon",
        ["SE Asia Standard Time"] = "Asia/Bangkok",
        ["China Standard Time"] = "Asia/Shanghai",
        ["Singapore Standard Time"] = "Asia/Singapore",
        ["Taipei Standard Time"] = "Asia/Taipei",
        ["Tokyo Standard Time"] = "Asia/Tokyo",
        ["Korea Standard Time"] = "Asia/Seoul",
        ["Ekaterinburg Standard Time"] = "Asia/Yekaterinburg",
        ["Azerbaijan Standard Time"] = "Asia/Baku",
        ["Georgian Standard Time"] = "Asia/Tbilisi",
        ["Caucasus Standard Time"] = "Asia/Yerevan",
        ["Mauritius Standard Time"] = "Indian/Mauritius",
        ["Ulaanbaatar Standard Time"] = "Asia/Ulaanbaatar",
        ["Yakutsk Standard Time"] = "Asia/Yakutsk",
        ["Vladivostok Standard Time"] = "Asia/Vladivostok",
        ["Magadan Standard Time"] = "Asia/Magadan",
        ["Dateline Standard Time"] = "Etc/GMT+12",
        ["Aleutian Standard Time"] = "America/Adak",
        ["W. Australia Standard Time"] = "Australia/Perth",
        ["Cen. Australia Standard Time"] = "Australia/Adelaide",
        ["AUS Central Standard Time"] = "Australia/Darwin",
        ["E. Australia Standard Time"] = "Australia/Brisbane",
        ["AUS Eastern Standard Time"] = "Australia/Sydney",
        ["Tasmania Standard Time"] = "Australia/Hobart",
        ["West Pacific Standard Time"] = "Pacific/Port_Moresby",
        ["Central Pacific Standard Time"] = "Pacific/Guadalcanal",
        ["New Zealand Standard Time"] = "Pacific/Auckland",
        ["Fiji Standard Time"] = "Pacific/Fiji",
        ["Tonga Standard Time"] = "Pacific/Tongatapu",
      };
  }
}
