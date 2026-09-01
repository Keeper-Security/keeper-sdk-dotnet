using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Workflow;
using ZeroDep;

namespace Commander.PAM
{
  internal class PamWorkflowCommand : PamCommandBase
  {
    private static readonly HashSet<string> AdminVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
      "create", "c",
      "update", "u",
      "delete", "d",
      "add-approver", "aa",
      "remove-approver", "ra",
    };

    private static readonly string AvailableCommands =
      "create, read, update, delete, add-approver, remove-approver, pending, approve, " +
      "deny, request, start, end, state, my-access";

    public PamWorkflowCommand(IEnterpriseContext context) : base(context)
    {
    }

    public async Task ExecuteAsync(PamWorkflowOptions options)
    {
      if (options == null)
      {
        throw new ArgumentNullException(nameof(options),
          $"Invalid pam-workflow command arguments. Available commands: {AvailableCommands}");
      }

      try
      {
        var command = string.IsNullOrEmpty(options.Command) ? string.Empty : options.Command.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(command))
        {
          throw new InvalidOperationException($"Missing subcommand. Available: {AvailableCommands}");
        }

        if (!string.IsNullOrEmpty(options.Format)
            && !string.Equals(options.Format, "table", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
        {
          throw new InvalidOperationException("Output format must be table or json");
        }

        if (AdminVerbs.Contains(command) && !WorkflowUtils.CanManageWorkflowSettings(Context.Enterprise.Auth))
        {
          PrintError(
            options.IsFormatOutputJson,
            "permission_denied",
            "You do not have permission to manage workflow settings. " +
            $"The '{command}' command requires the 'Can manage workflow settings' enforcement policy. " +
            "Contact your Keeper administrator to enable this for your role.");
          return;
        }

        switch (command)
        {
          case "create":
          case "c":
            await CreateWorkflowAsync(options);
            break;
          case "read":
          case "r":
            await ReadWorkflowAsync(options);
            break;
          case "update":
          case "u":
            await UpdateWorkflowAsync(options);
            break;
          case "delete":
          case "d":
            await DeleteWorkflowAsync(options);
            break;
          case "add-approver":
          case "aa":
            await AddApproverAsync(options);
            break;
          case "remove-approver":
          case "ra":
            await RemoveApproverAsync(options);
            break;
          case "pending":
          case "p":
            await PendingApprovalsAsync(options);
            break;
          case "approve":
          case "a":
            await ApproveAsync(options);
            break;
          case "deny":
          case "dn":
            await DenyAsync(options);
            break;
          case "request":
          case "rq":
            await RequestAsync(options);
            break;
          case "start":
          case "s":
            await StartAsync(options);
            break;
          case "end":
          case "e":
            await EndAsync(options);
            break;
          case "state":
          case "st":
            await StateAsync(options);
            break;
          case "my-access":
          case "ma":
            await MyAccessAsync(options);
            break;
          default:
            throw new InvalidOperationException($"Unsupported command. Available: {AvailableCommands}");
        }
      }
      catch (Exception ex) when (options.IsFormatOutputJson)
      {
        PrintError(true, "error", ex.Message);
      }
    }

    private async Task CreateWorkflowAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for create");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record);

      var auth = Context.Enterprise.Auth;
      WorkflowConfig existing = null;
      try
      {
        existing = await WorkflowUtils.ReadWorkflowConfigAsync(auth, record.Uid, record.Title);
      }
      catch (Exception ex)
      {
        Trace.TraceWarning($"Pre-check read_workflow_config failed: {ex}");
        Console.Error.WriteLine(
          "Warning: could not verify existing workflow config before create; " +
          "continuing, and the server will reject duplicates if one already exists.");
        existing = null;
      }

      if (existing != null)
      {
        throw new InvalidOperationException(
          $"Workflow already configured for \"{record.Title}\" ({record.Uid}).\n" +
          $"  Modify it:           pam-workflow update {record.Uid} ...\n" +
          $"  Inspect it:          pam-workflow read {record.Uid}\n" +
          $"  Remove and recreate: pam-workflow delete {record.Uid} && " +
          $"pam-workflow create {record.Uid} ...");
      }

      var approvals = options.ApprovalsNeeded ?? 1;
      if (approvals < 0)
      {
        throw new InvalidOperationException("Approvals needed must be 0 or greater");
      }

      var approvers = ResolveUserEmails(options);

      if (approvals > 0 && approvers.Count == 0)
      {
        throw new InvalidOperationException(
          "Could not resolve user/approver. At least one valid --approver/--user email is required when --approvals-needed > 0. " +
          "Pass --approver <email> for each approver, or use --approvals-needed 0 " +
          "for a workflow that does not need approval.");
      }

      if (approvers.Count > 0 && approvals == 0 && !options.IsFormatOutputJson)
      {
        Console.WriteLine(
          "Warning: --approver(s) supplied but --approvals-needed is 0 - approvers will " +
          "be recorded but no approval will ever be required.");
      }

      long accessLength;
      try
      {
        accessLength = WorkflowUtils.ConvertToMilliseconds(
          string.IsNullOrWhiteSpace(options.Duration) ? "1d" : options.Duration);
      }
      catch (ArgumentException ex)
      {
        throw new InvalidOperationException(ex.Message);
      }

      TemporalAccessFilter temporalFilter = null;
      try
      {
        temporalFilter = WorkflowUtils.BuildTemporalFilter(options.AllowedDays, options.TimeRange);
      }
      catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
      {
        throw new InvalidOperationException(ex.Message);
      }

      var parameters = new WorkflowParameters
      {
        Resource = WorkflowUtils.CreateRecordRef(record.Uid, record.Title),
        ApprovalsNeeded = approvals,
        CheckoutNeeded = options.Checkout ?? false,
        StartAccessOnApproval = options.StartOnApproval ?? false,
        RequireReason = options.RequireReason ?? false,
        RequireTicket = options.RequireTicket ?? false,
        RequireMFA = options.RequireMfa ?? false,
        AccessLength = accessLength,
      };
      if (temporalFilter != null)
      {
        parameters.AllowedTimes = temporalFilter;
      }

      try
      {
        await WorkflowUtils.CreateWorkflowConfigAsync(auth, parameters);
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to create workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }

      var approversAdded = new List<string>();
      if (approvers.Count > 0)
      {
        try
        {
          await WorkflowUtils.AddWorkflowApproversAsync(auth, record.Uid, record.Title, approvers);
          approversAdded.AddRange(approvers);
        }
        catch (Exception ex)
        {
          if (!options.IsFormatOutputJson)
          {
            Console.WriteLine();
            Console.WriteLine(
              $"Workflow created, but failed to add approvers: {WorkflowUtils.SanitizeRouterError(ex)}");
            Console.WriteLine(
              $"Run: pam-workflow add-approver {record.Uid} " +
              string.Join(" ", approvers.Select(u => $"--user {u}")));
          }
        }
      }

      if (options.IsFormatOutputJson)
      {
        var result = new Dictionary<string, object>
        {
          ["status"] = approvers.Count > 0 && approversAdded.Count != approvers.Count
            ? "partial"
            : "success",
          ["record_uid"] = record.Uid,
          ["record_name"] = record.Title,
          ["workflow_config"] = new Dictionary<string, object>
          {
            ["approvals_needed"] = parameters.ApprovalsNeeded,
            ["checkout_needed"] = parameters.CheckoutNeeded,
            ["require_reason"] = parameters.RequireReason,
            ["require_ticket"] = parameters.RequireTicket,
            ["require_mfa"] = parameters.RequireMFA,
            ["access_duration"] = WorkflowUtils.FormatDuration(parameters.AccessLength),
          },
          ["approvers"] = approversAdded,
        };
        if (approvers.Count > 0 && approversAdded.Count != approvers.Count)
        {
          result["warning"] = "Workflow created, but failed to add approvers";
        }

        Console.WriteLine(Json.WriteFormatted(result));
      }
      else
      {
        Console.WriteLine();
        Console.WriteLine("Workflow created successfully");
        Console.WriteLine();
        Console.WriteLine($"Record: {record.Title} ({record.Uid})");
        Console.WriteLine($"Approvals needed: {parameters.ApprovalsNeeded}");
        Console.WriteLine($"Check-in/out: {(parameters.CheckoutNeeded ? "Yes" : "No")}");
        Console.WriteLine($"Duration: {WorkflowUtils.FormatDuration(parameters.AccessLength)}");
        if (parameters.RequireReason)
        {
          Console.WriteLine("Requires reason: Yes");
        }

        if (parameters.RequireTicket)
        {
          Console.WriteLine("Requires ticket: Yes");
        }

        if (parameters.RequireMFA)
        {
          Console.WriteLine("Requires MFA: Yes");
        }

        if (approversAdded.Count > 0)
        {
          Console.WriteLine($"Approvers: {string.Join(", ", approversAdded)}");
        }
        else if (parameters.ApprovalsNeeded > 0)
        {
          Console.WriteLine();
          Console.WriteLine(
            $"Note: Add approvers with: pam-workflow add-approver {record.Uid} --user <email>");
        }

        Console.WriteLine();
      }
    }

    private async Task ReadWorkflowAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for read");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      try
      {
        var response = await WorkflowUtils.ReadWorkflowConfigAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);

        if (response == null)
        {
          if (options.IsFormatOutputJson)
          {
            Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
            {
              ["status"] = "no_workflow",
              ["message"] = "No workflow configured",
            }));
          }
          else
          {
            Console.WriteLine();
            Console.WriteLine("No workflow configured for this record");
            Console.WriteLine();
            Console.WriteLine($"Record: {record.Title} ({record.Uid})");
            Console.WriteLine();
            Console.WriteLine("To create a workflow, run:");
            Console.WriteLine($"  pam-workflow create {record.Uid}");
            Console.WriteLine();
          }

          return;
        }

        if (options.IsFormatOutputJson)
        {
          PrintReadJson(response, record.Uid);
        }
        else
        {
          PrintReadTable(response, record.Uid);
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to read workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task UpdateWorkflowAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for update");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      try
      {
        var currentConfig = await WorkflowUtils.ReadWorkflowConfigAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);
        if (currentConfig?.Parameters == null)
        {
          throw new InvalidOperationException(
            "No workflow found for record. Create one first with \"pam-workflow create\"");
        }

        var parameters = currentConfig.Parameters.Clone();
        var updatesProvided = false;

        if (options.ApprovalsNeeded.HasValue)
        {
          if (options.ApprovalsNeeded.Value < 0)
          {
            throw new InvalidOperationException("Approvals needed must be 0 or greater");
          }

          parameters.ApprovalsNeeded = options.ApprovalsNeeded.Value;
          updatesProvided = true;
        }

        if (options.Checkout.HasValue)
        {
          parameters.CheckoutNeeded = options.Checkout.Value;
          updatesProvided = true;
        }

        if (options.StartOnApproval.HasValue)
        {
          parameters.StartAccessOnApproval = options.StartOnApproval.Value;
          updatesProvided = true;
        }

        if (options.RequireReason.HasValue)
        {
          parameters.RequireReason = options.RequireReason.Value;
          updatesProvided = true;
        }

        if (options.RequireTicket.HasValue)
        {
          parameters.RequireTicket = options.RequireTicket.Value;
          updatesProvided = true;
        }

        if (options.RequireMfa.HasValue)
        {
          parameters.RequireMFA = options.RequireMfa.Value;
          updatesProvided = true;
        }

        if (!string.IsNullOrWhiteSpace(options.Duration))
        {
          try
          {
            parameters.AccessLength = WorkflowUtils.ConvertToMilliseconds(options.Duration);
          }
          catch (ArgumentException ex)
          {
            throw new InvalidOperationException(ex.Message);
          }

          updatesProvided = true;
        }

        TemporalAccessFilter temporalFilter;
        try
        {
          temporalFilter = WorkflowUtils.BuildTemporalFilter(
            options.AllowedDays, options.TimeRange, currentConfig.Parameters?.AllowedTimes);
        }
        catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
        {
          throw new InvalidOperationException(ex.Message);
        }

        if (temporalFilter != null)
        {
          parameters.AllowedTimes = temporalFilter;
          updatesProvided = true;
        }

        if (!updatesProvided)
        {
          throw new InvalidOperationException(
            "No updates provided. Specify at least one option to update " +
            "(e.g., --approvals-needed, --duration)");
        }

        await WorkflowUtils.UpdateWorkflowConfigAsync(Context.Enterprise.Auth, parameters);

        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow updated successfully");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to update workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task DeleteWorkflowAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for delete");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      WorkflowConfig existing;
      try
      {
        existing = await WorkflowUtils.ReadWorkflowConfigAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to read workflow before delete: {WorkflowUtils.SanitizeRouterError(ex)}");
      }

      if (existing == null)
      {
        throw new InvalidOperationException(
          $"No workflow configured for \"{record.Title}\" ({record.Uid}). Nothing to delete.");
      }

      try
      {
        await WorkflowUtils.DeleteWorkflowConfigAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);

        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow deleted successfully");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to delete workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task AddApproverAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for add-approver");
      }

      var users = ResolveUserEmails(options);
      var teams = ResolveTeamInputs(options);
      if (users.Count == 0 && teams.Count == 0)
      {
        throw new InvalidOperationException("Must specify at least one --user/--approver or --team. Users or teams not resolved.");
      }

      if (!string.IsNullOrWhiteSpace(options.EscalationAfter) && !options.Escalation)
      {
        throw new InvalidOperationException("--escalation-after requires --escalation flag");
      }

      long escalationAfterMs = 0;
      if (!string.IsNullOrWhiteSpace(options.EscalationAfter))
      {
        try
        {
          escalationAfterMs = WorkflowUtils.ConvertToMilliseconds(options.EscalationAfter);
        }
        catch (ArgumentException ex)
        {
          throw new InvalidOperationException(ex.Message);
        }
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      var teamUids = teams.Select(ResolveTeamUid).ToList();
      var isEscalation = options.Escalation || options.Escalate;
      try
      {
        await WorkflowUtils.AddWorkflowApproversAsync(
          Context.Enterprise.Auth,
          record.Uid,
          record.Title,
          users,
          teamUids,
          isEscalation,
          escalationAfterMs);

        var total = users.Count + teamUids.Count;
        if (options.IsFormatOutputJson)
        {
          var result = new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["approvers_added"] = total,
            ["escalation"] = isEscalation,
          };
          if (escalationAfterMs > 0)
          {
            result["escalation_after"] = WorkflowUtils.FormatDuration(escalationAfterMs);
          }

          Console.WriteLine(Json.WriteFormatted(result));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Approvers added successfully");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine($"Added {total} approver(s)");
          if (isEscalation)
          {
            var escInfo = escalationAfterMs > 0
              ? $" (after {WorkflowUtils.FormatDuration(escalationAfterMs)})"
              : string.Empty;
            Console.WriteLine($"Type: Escalation approver{escInfo}");
          }

          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to add approvers: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task RemoveApproverAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for remove-approver");
      }

      var users = ResolveUserEmails(options);
      var teams = ResolveTeamInputs(options);
      if (users.Count == 0 && teams.Count == 0)
      {
        throw new InvalidOperationException("Must specify at least one --user/--approver or --team. Users or teams not resolved.");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      var teamUids = teams.Select(ResolveTeamUid).ToList();
      try
      {
        await WorkflowUtils.DeleteWorkflowApproversAsync(
          Context.Enterprise.Auth,
          record.Uid,
          record.Title,
          users,
          teamUids);

        var total = users.Count + teamUids.Count;
        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["approvers_removed"] = total,
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Approvers removed successfully");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine($"Removed {total} approver(s)");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to remove approvers: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task PendingApprovalsAsync(PamWorkflowOptions options)
    {
      try
      {
        var response = await WorkflowUtils.GetApprovalRequestsAsync(Context.Enterprise.Auth);
        if (response == null || response.Workflows.Count == 0)
        {
          PrintNoPending(options.IsFormatOutputJson, "No approval requests");
          return;
        }

        var pending = await WorkflowUtils.FilterPendingApprovalsAsync(
          Context.Enterprise.Auth,
          response.Workflows,
          Context.Enterprise.Auth?.Username);

        if (pending.Count == 0)
        {
          PrintNoPending(options.IsFormatOutputJson, "No pending approval requests");
          return;
        }

        if (options.IsFormatOutputJson)
        {
          PrintPendingJson(pending);
        }
        else
        {
          PrintPendingTable(pending);
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to get approval requests: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task ApproveAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Flow UID is required for approve");
      }

      var flowUid = options.Record.Trim();
      var flowUidBytes = DecodeRequiredFlowUidBytes(flowUid);

      try
      {
        await WorkflowUtils.ApproveWorkflowAccessAsync(Context.Enterprise.Auth, flowUidBytes);

        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["flow_uid"] = flowUid,
            ["action"] = "approved",
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Access request approved");
          Console.WriteLine();
          Console.WriteLine($"Flow UID: {flowUid}");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to approve request: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task DenyAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Flow UID is required for deny");
      }

      var flowUid = options.Record.Trim();
      var flowUidBytes = DecodeRequiredFlowUidBytes(flowUid);

      var reason = options.Reason?.Trim() ?? string.Empty;
      ByteString denialReasonEncrypted = null;
      if (!string.IsNullOrEmpty(reason))
      {
        denialReasonEncrypted = await WorkflowUtils.TryEncryptDenialReasonAsync(
          Context.Enterprise.Auth, flowUidBytes, reason);
        if (denialReasonEncrypted == null)
        {
          if (!options.IsFormatOutputJson)
          {
            Console.WriteLine(
              "Warning: Could not encrypt denial reason for the requester — reason will not be attached. " +
              "The denial itself will still be sent.");
          }

          reason = string.Empty;
        }
      }

      try
      {
        await WorkflowUtils.DenyWorkflowAccessAsync(
          Context.Enterprise.Auth, flowUidBytes, denialReasonEncrypted);

        if (options.IsFormatOutputJson)
        {
          var result = new Dictionary<string, object>
          {
            ["status"] = "success",
            ["flow_uid"] = flowUid,
            ["action"] = "denied",
          };
          if (!string.IsNullOrEmpty(reason))
          {
            result["reason"] = reason;
          }

          Console.WriteLine(Json.WriteFormatted(result));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Access request denied");
          Console.WriteLine();
          Console.WriteLine($"Flow UID: {flowUid}");
          if (!string.IsNullOrEmpty(reason))
          {
            Console.WriteLine($"Reason: {reason}");
          }

          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to deny request: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task RequestAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for request");
      }

      var cancel = options.Cancel;
      var escalate = options.Escalate || options.Escalation;
      if (cancel && escalate)
      {
        throw new InvalidOperationException("--cancel and --escalate cannot be used together");
      }

      if (cancel && (!string.IsNullOrWhiteSpace(options.Reason) || !string.IsNullOrWhiteSpace(options.Ticket)))
      {
        throw new InvalidOperationException("--cancel cannot be used with --reason or --ticket");
      }

      if (cancel)
      {
        await CancelRequestAsync(options);
        return;
      }

      if (escalate)
      {
        await EscalateRequestAsync(options);
        return;
      }

      await SubmitRequestAsync(options);
    }

    private async Task SubmitRequestAsync(PamWorkflowOptions options)
    {
      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record);

      if (await IsExemptAsync(record))
      {
        PrintExempt(options.IsFormatOutputJson);
        return;
      }

      var reason = options.Reason?.Trim() ?? string.Empty;
      var ticket = options.Ticket?.Trim() ?? string.Empty;
      try
      {
        await WorkflowUtils.RequestWorkflowAccessAsync(
          Context.Enterprise.Auth,
          record.Uid,
          record.Title,
          record.RecordKey,
          reason,
          ticket);

        if (options.IsFormatOutputJson)
        {
          var result = new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["message"] = "Access request sent to approvers",
          };
          if (!string.IsNullOrEmpty(reason))
          {
            result["reason"] = reason;
          }

          if (!string.IsNullOrEmpty(ticket))
          {
            result["ticket"] = ticket;
          }

          Console.WriteLine(Json.WriteFormatted(result));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Access request sent");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          if (!string.IsNullOrEmpty(reason))
          {
            Console.WriteLine($"Reason: {reason}");
          }

          if (!string.IsNullOrEmpty(ticket))
          {
            Console.WriteLine($"Ticket: {ticket}");
          }

          Console.WriteLine();
          Console.WriteLine("Approvers have been notified.");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to request access: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task EscalateRequestAsync(PamWorkflowOptions options)
    {
      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      if (await IsExemptAsync(record))
      {
        PrintExempt(options.IsFormatOutputJson);
        return;
      }

      try
      {
        await WorkflowUtils.RequestEscalationAsync(Context.Enterprise.Auth, record.Uid, record.Title);
        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["action"] = "escalated",
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Request escalated");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine();
          Console.WriteLine("Escalation approvers have been notified.");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to escalate request: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task CancelRequestAsync(PamWorkflowOptions options)
    {
      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      try
      {
        var workflowState = await WorkflowUtils.GetWorkflowStateByRecordAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);
        if (workflowState == null || workflowState.FlowUid.IsEmpty)
        {
          throw new InvalidOperationException("No active workflow request found for this record.");
        }

        await WorkflowUtils.EndWorkflowAsync(
          Context.Enterprise.Auth,
          WorkflowUtils.WorkflowRef(workflowState.FlowUid.ToByteArray()));

        var flowUidStr = workflowState.FlowUid.ToByteArray().Base64UrlEncode();
        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["flow_uid"] = flowUidStr,
            ["action"] = "cancelled",
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow request cancelled");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine($"Flow UID: {flowUidStr}");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to cancel request: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task StartAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID/name or Flow UID is required for start");
      }

      var uid = options.Record.Trim();
      var vault = RequireVault();
      var record = TryResolveRecordAllowMissing(vault, uid);

      var state = new WorkflowState();
      if (record != null)
      {
        state.Resource = WorkflowUtils.CreateRecordRef(record.Uid, record.Title);
      }
      else
      {
        var uidBytes = DecodeRecordOrFlowUidBytes(uid);
        state.FlowUid = ByteString.CopyFrom(uidBytes);
        state.Resource = WorkflowUtils.WorkflowRef(uidBytes);
      }

      try
      {
        await WorkflowUtils.StartWorkflowAsync(Context.Enterprise.Auth, state);
        if (options.IsFormatOutputJson)
        {
          var result = new Dictionary<string, object>
          {
            ["status"] = "success",
            ["action"] = "checked_out",
          };
          if (record != null)
          {
            result["record_uid"] = record.Uid;
            result["record_name"] = record.Title;
          }
          else
          {
            result["flow_uid"] = uid;
          }

          Console.WriteLine(Json.WriteFormatted(result));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow started (checked out)");
          Console.WriteLine();
          if (record != null)
          {
            Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          }
          else
          {
            Console.WriteLine($"Flow UID: {uid}");
          }

          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to start workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task EndAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID/name or Flow UID is required for end");
      }

      if (options.Force)
      {
        await ForceCheckinAsync(options);
        return;
      }

      var uid = options.Record.Trim();
      var vault = RequireVault();
      var record = TryResolveRecordAllowMissing(vault, uid);
      if (record != null)
      {
        await EndByRecordAsync(record, options);
      }
      else
      {
        await EndByFlowUidAsync(uid, options);
      }
    }

    private async Task ForceCheckinAsync(PamWorkflowOptions options)
    {
      var uid = options.Record.Trim();
      var vault = RequireVault();
      var record = TryResolveRecordAllowMissing(vault, uid);
      GraphSync.GraphSyncRef refMsg;
      string label;
      if (record != null)
      {
        refMsg = WorkflowUtils.CreateRecordRef(record.Uid, record.Title);
        label = $"Record: {record.Title} ({record.Uid})";
      }
      else
      {
        var uidBytes = DecodeRecordOrFlowUidBytes(uid);
        refMsg = WorkflowUtils.WorkflowRef(uidBytes);
        label = $"Flow UID: {uid}";
      }

      try
      {
        await WorkflowUtils.ForceCheckinAsync(Context.Enterprise.Auth, refMsg);
        if (options.IsFormatOutputJson)
        {
          var result = new Dictionary<string, object>
          {
            ["status"] = "success",
            ["action"] = "force_checkin",
          };
          if (record != null)
          {
            result["record_uid"] = record.Uid;
            result["record_name"] = record.Title;
          }
          else
          {
            result["flow_uid"] = uid;
          }

          Console.WriteLine(Json.WriteFormatted(result));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Record force checked in");
          Console.WriteLine();
          Console.WriteLine(label);
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to force check-in: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task EndByRecordAsync(TypedRecord record, PamWorkflowOptions options)
    {
      try
      {
        var workflowState = await WorkflowUtils.GetWorkflowStateByRecordAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);
        if (workflowState == null || workflowState.FlowUid.IsEmpty)
        {
          throw new InvalidOperationException(
            "No active workflow found for this record. " +
            "The workflow may have already ended or never started.");
        }

        await WorkflowUtils.EndWorkflowAsync(
          Context.Enterprise.Auth,
          WorkflowUtils.WorkflowRef(workflowState.FlowUid.ToByteArray()));

        var flowUidStr = workflowState.FlowUid.ToByteArray().Base64UrlEncode();
        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["flow_uid"] = flowUidStr,
            ["record_uid"] = record.Uid,
            ["record_name"] = record.Title,
            ["action"] = "ended",
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow ended (checked in)");
          Console.WriteLine();
          Console.WriteLine($"Record: {record.Title} ({record.Uid})");
          Console.WriteLine($"Flow UID: {flowUidStr}");
          Console.WriteLine();
          Console.WriteLine("Credentials may have been rotated.");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to end workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task EndByFlowUidAsync(string uid, PamWorkflowOptions options)
    {
      var uidBytes = DecodeRecordOrFlowUidBytes(uid);

      try
      {
        await WorkflowUtils.EndWorkflowAsync(Context.Enterprise.Auth, WorkflowUtils.WorkflowRef(uidBytes));
        if (options.IsFormatOutputJson)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["status"] = "success",
            ["flow_uid"] = uid,
            ["action"] = "ended",
          }));
        }
        else
        {
          Console.WriteLine();
          Console.WriteLine("Workflow ended (checked in)");
          Console.WriteLine();
          Console.WriteLine($"Flow UID: {uid}");
          Console.WriteLine();
          Console.WriteLine("Credentials may have been rotated.");
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to end workflow: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task StateAsync(PamWorkflowOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new InvalidOperationException("Record UID or name is required for state");
      }

      var vault = RequireVault();
      var record = ResolveWorkflowRecord(vault, options.Record, validateWorkflowType: false);

      if (await IsExemptAsync(record))
      {
        PrintExempt(options.IsFormatOutputJson);
        return;
      }

      try
      {
        var response = await WorkflowUtils.GetWorkflowStateByRecordAsync(
          Context.Enterprise.Auth, record.Uid, record.Title);
        if (response == null)
        {
          if (options.IsFormatOutputJson)
          {
            Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
            {
              ["status"] = "no_workflow",
              ["message"] = "No workflow found",
            }));
          }
          else
          {
            Console.WriteLine();
            Console.WriteLine("No workflow found for this record");
            Console.WriteLine();
          }

          return;
        }

        if (options.IsFormatOutputJson)
        {
          PrintStateJson(response);
        }
        else
        {
          PrintStateTable(response);
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to get workflow state: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private async Task MyAccessAsync(PamWorkflowOptions options)
    {
      try
      {
        var response = await WorkflowUtils.GetUserAccessStateAsync(Context.Enterprise.Auth);
        if (response == null || response.Workflows.Count == 0)
        {
          if (options.IsFormatOutputJson)
          {
            Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
            {
              ["workflows"] = Array.Empty<object>(),
            }));
          }
          else
          {
            Console.WriteLine();
            Console.WriteLine("No active workflows");
            Console.WriteLine();
          }

          return;
        }

        if (options.IsFormatOutputJson)
        {
          var workflows = response.Workflows.Select(BuildStateJson).ToList();
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
          {
            ["workflows"] = workflows,
          }));
        }
        else
        {
          var tab = new Tabulate(8);
          tab.AddHeader(
            "Stage", "Record Name", "Record UID", "Flow UID",
            "Checked Out By", "Approved By", "Started", "Expires");
          foreach (var wf in response.Workflows)
          {
            var st = wf.Status ?? new WorkflowStatus();
            var approvedBy = string.Join("\n", st.ApprovedBy.Select(a =>
              !string.IsNullOrEmpty(a.User) ? a.User : ResolveUserDisplay(a.UserId)));
            tab.AddRow(
              WorkflowUtils.FormatStage(st),
              ResolveResourceName(wf.Resource),
              wf.Resource?.Value != null && !wf.Resource.Value.IsEmpty
                ? wf.Resource.Value.ToByteArray().Base64UrlEncode()
                : string.Empty,
              !wf.FlowUid.IsEmpty ? wf.FlowUid.ToByteArray().Base64UrlEncode() : string.Empty,
              st.CheckedOutBy ?? string.Empty,
              approvedBy,
              FormatTs(st.StartedOn),
              FormatTs(st.ExpiresOn));
          }

          Console.WriteLine();
          tab.Dump();
          Console.WriteLine();
        }
      }
      catch (InvalidOperationException)
      {
        throw;
      }
      catch (Exception ex)
      {
        throw new InvalidOperationException(
          $"Failed to get user access state: {WorkflowUtils.SanitizeRouterError(ex)}");
      }
    }

    private void PrintStateJson(WorkflowState response)
    {
      Console.WriteLine(Json.WriteFormatted(BuildStateJson(response)));
    }

    private Dictionary<string, object> BuildStateJson(WorkflowState response)
    {
      var st = response.Status ?? new WorkflowStatus();
      return new Dictionary<string, object>
      {
        ["flow_uid"] = !response.FlowUid.IsEmpty
          ? response.FlowUid.ToByteArray().Base64UrlEncode()
          : null,
        ["record_uid"] = response.Resource?.Value != null && !response.Resource.Value.IsEmpty
          ? response.Resource.Value.ToByteArray().Base64UrlEncode()
          : null,
        ["record_name"] = ResolveResourceName(response.Resource),
        ["stage"] = WorkflowUtils.FormatStage(st),
        ["conditions"] = st.Conditions.Select(c => WorkflowUtils.FormatCondition(c)).ToList(),
        ["escalated"] = st.Escalated,
        ["checked_out_by"] = string.IsNullOrEmpty(st.CheckedOutBy) ? null : st.CheckedOutBy,
        ["can_force_checkin"] = st.CanForceCheckIn,
        ["started_on"] = st.StartedOn > 0 ? st.StartedOn : null,
        ["expires_on"] = st.ExpiresOn > 0 ? st.ExpiresOn : null,
        ["approved_by"] = st.ApprovedBy.Select(a => new Dictionary<string, object>
        {
          ["user"] = !string.IsNullOrEmpty(a.User) ? a.User : ResolveUserDisplay(a.UserId),
          ["approved_on"] = a.ApprovedOn > 0 ? a.ApprovedOn : null,
        }).ToList(),
      };
    }

    private void PrintStateTable(WorkflowState response)
    {
      var st = response.Status ?? new WorkflowStatus();
      Console.WriteLine();
      Console.WriteLine("Workflow State");
      Console.WriteLine();
      Console.WriteLine($"Record: {FormatResourceLabel(response.Resource)}");
      if (!response.FlowUid.IsEmpty)
      {
        Console.WriteLine($"Flow UID: {response.FlowUid.ToByteArray().Base64UrlEncode()}");
      }

      Console.WriteLine($"Stage: {WorkflowUtils.FormatStage(st)}");
      if (st.Conditions.Count > 0)
      {
        Console.WriteLine($"Conditions: {WorkflowUtils.FormatConditions(st.Conditions)}");
      }

      if (!string.IsNullOrEmpty(st.CheckedOutBy))
      {
        Console.WriteLine($"Checked out by: {st.CheckedOutBy}");
      }

      if (st.CanForceCheckIn)
      {
        Console.WriteLine("Force check-in: Available");
      }

      if (st.Escalated)
      {
        Console.WriteLine("Escalated: Yes");
      }

      if (st.StartedOn > 0)
      {
        Console.WriteLine($"Started: {FormatTs(st.StartedOn)}");
      }

      if (st.ExpiresOn > 0)
      {
        Console.WriteLine($"Expires: {FormatTs(st.ExpiresOn)}");
      }

      if (st.ApprovedBy.Count > 0)
      {
        Console.WriteLine("Approved by:");
        foreach (var a in st.ApprovedBy)
        {
          var name = !string.IsNullOrEmpty(a.User) ? a.User : ResolveUserDisplay(a.UserId);
          var suffix = a.ApprovedOn > 0 ? $" at {FormatTs(a.ApprovedOn)}" : string.Empty;
          Console.WriteLine($"  - {name}{suffix}");
        }
      }

      Console.WriteLine();
    }

    private static string FormatTs(long tsMs)
    {
      return tsMs > 0
        ? DateTimeOffset.FromUnixTimeMilliseconds(tsMs).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
        : string.Empty;
    }

    private string FormatResourceLabel(GraphSync.GraphSyncRef resource)
    {
      if (resource == null)
      {
        return "Unknown";
      }

      var uid = resource.Value != null && !resource.Value.IsEmpty
        ? resource.Value.ToByteArray().Base64UrlEncode()
        : string.Empty;
      var name = ResolveResourceName(resource);
      if (!string.IsNullOrEmpty(name) && name != uid)
      {
        return $"{name} ({uid})";
      }

      return string.IsNullOrEmpty(uid) ? "Unknown" : uid;
    }

    private async Task<bool> IsExemptAsync(TypedRecord record)
    {
      var teamUids = Context.GetVault()?.Teams?.Select(t => t.TeamUid) ?? Enumerable.Empty<string>();
      return await WorkflowUtils.IsWorkflowExemptAsync(Context.Enterprise.Auth, record, teamUids);
    }

    private static void PrintError(bool json, string status, string message)
    {
      if (json)
      {
        Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
        {
          ["status"] = status,
          ["message"] = message,
        }));
        return;
      }

      Console.WriteLine();
      Console.WriteLine(message);
      Console.WriteLine();
    }

    private static void PrintExempt(bool json)
    {
      if (json)
      {
        Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
        {
          ["status"] = "exempt",
          ["message"] = "Workflow not required",
        }));
      }
      else
      {
        Console.WriteLine();
        Console.WriteLine("You are exempt from workflow restrictions on this record.");
        Console.WriteLine("As a record owner or approver, you can access this resource directly.");
        Console.WriteLine();
      }
    }

    private TypedRecord TryResolveRecordAllowMissing(VaultOnline vault, string identifier)
    {
      if (vault.TryGetKeeperRecord(identifier, out var byUid) && byUid is TypedRecord typedByUid)
      {
        return typedByUid;
      }

      var matches = vault.KeeperRecords
        .OfType<TypedRecord>()
        .Where(x => string.Equals(x.Title, identifier, StringComparison.OrdinalIgnoreCase))
        .ToList();
      if (matches.Count > 1)
      {
        throw new InvalidOperationException($"Record name '{identifier}' is not unique. Use record UID.");
      }

      return matches.Count == 1 ? matches[0] : null;
    }

    private const int KeeperUidByteLength = 16;

    private static byte[] DecodeKeeperUidBytes(string uid, string errorMessage)
    {
      var uidBytes = uid?.Trim().Base64UrlDecode();
      if (uidBytes == null || uidBytes.Length != KeeperUidByteLength)
      {
        throw new InvalidOperationException(errorMessage);
      }

      return uidBytes;
    }

    private static byte[] DecodeRecordOrFlowUidBytes(string uid)
    {
      return DecodeKeeperUidBytes(
        uid,
        $"\"{uid}\" is not a known record or a valid flow UID");
    }

    private static byte[] DecodeRequiredFlowUidBytes(string uid)
    {
      return DecodeKeeperUidBytes(uid, $"Invalid flow UID: \"{uid}\"");
    }

    private static void PrintNoPending(bool json, string message)
    {
      if (json)
      {
        Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
        {
          ["requests"] = Array.Empty<object>(),
        }));
      }
      else
      {
        Console.WriteLine();
        Console.WriteLine(message);
        Console.WriteLine();
      }
    }

    private void PrintPendingJson(IEnumerable<WorkflowProcess> workflows)
    {
      var vault = Context.GetVault();
      var requests = new List<Dictionary<string, object>>();
      foreach (var wf in workflows)
      {
        var recordUid = wf.Resource?.Value != null && !wf.Resource.Value.IsEmpty
          ? wf.Resource.Value.ToByteArray().Base64UrlEncode()
          : string.Empty;
        var recordKey = TryGetRecordKey(vault, recordUid);
        var duration = wf.ExpiresOn > 0 && wf.StartedOn > 0
          ? WorkflowUtils.FormatDuration(wf.ExpiresOn - wf.StartedOn)
          : null;

        requests.Add(new Dictionary<string, object>
        {
          ["flow_uid"] = wf.FlowUid.ToByteArray().Base64UrlEncode(),
          ["requested_by"] = ResolveRequestedBy(wf),
          ["record_uid"] = recordUid,
          ["record_name"] = ResolveResourceName(wf.Resource),
          ["started_on"] = wf.StartedOn > 0 ? wf.StartedOn : null,
          ["expires_on"] = wf.ExpiresOn > 0 ? wf.ExpiresOn : null,
          ["escalated"] = wf.Escalated,
          ["duration"] = duration,
          ["reason"] = WorkflowUtils.DecryptWorkflowParameter(
            recordKey, WorkflowUtils.ExtractWorkflowParameter(wf, "reason")),
          ["ticket"] = WorkflowUtils.DecryptWorkflowParameter(
            recordKey, WorkflowUtils.ExtractWorkflowParameter(wf, "ticket")),
        });
      }

      Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object> { ["requests"] = requests }));
    }

    private void PrintPendingTable(IEnumerable<WorkflowProcess> workflows)
    {
      var vault = Context.GetVault();
      var tab = new Tabulate(9);
      tab.AddHeader(
        "Record Name", "Record UID", "Flow UID", "Requested By",
        "Reason", "Ticket", "Started", "Expires", "Duration");

      foreach (var wf in workflows)
      {
        var recordUid = wf.Resource?.Value != null && !wf.Resource.Value.IsEmpty
          ? wf.Resource.Value.ToByteArray().Base64UrlEncode()
          : string.Empty;
        var recordKey = TryGetRecordKey(vault, recordUid);
        var reason = WorkflowUtils.DecryptWorkflowParameter(
          recordKey, WorkflowUtils.ExtractWorkflowParameter(wf, "reason")) ?? string.Empty;
        var ticket = WorkflowUtils.DecryptWorkflowParameter(
          recordKey, WorkflowUtils.ExtractWorkflowParameter(wf, "ticket")) ?? string.Empty;
        var started = wf.StartedOn > 0
          ? DateTimeOffset.FromUnixTimeMilliseconds(wf.StartedOn).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
          : string.Empty;
        var expires = wf.ExpiresOn > 0
          ? DateTimeOffset.FromUnixTimeMilliseconds(wf.ExpiresOn).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
          : string.Empty;
        var duration = wf.ExpiresOn > 0 && wf.StartedOn > 0
          ? WorkflowUtils.FormatDuration(wf.ExpiresOn - wf.StartedOn)
          : string.Empty;

        tab.AddRow(
          ResolveResourceName(wf.Resource),
          recordUid,
          wf.FlowUid.ToByteArray().Base64UrlEncode(),
          ResolveRequestedBy(wf),
          reason,
          ticket,
          started,
          expires,
          duration);
      }

      Console.WriteLine();
      tab.Dump();
      Console.WriteLine();
    }

    private static byte[] TryGetRecordKey(VaultOnline vault, string recordUid)
    {
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return null;
      }

      return vault.TryGetKeeperRecord(recordUid, out var record) ? record.RecordKey : null;
    }

    private string ResolveRequestedBy(WorkflowProcess wf)
    {
      if (!string.IsNullOrEmpty(wf.User))
      {
        return wf.User;
      }

      return ResolveUserDisplay(wf.UserId);
    }

    private static List<string> ResolveUserEmails(PamWorkflowOptions options)
    {
      return (options.Users ?? Enumerable.Empty<string>())
        .Concat(options.Approvers ?? Enumerable.Empty<string>())
        .Where(a => !string.IsNullOrWhiteSpace(a))
        .Select(a => a.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
    }

    private static List<string> ResolveTeamInputs(PamWorkflowOptions options)
    {
      return (options.Teams ?? Array.Empty<string>())
        .Where(t => !string.IsNullOrWhiteSpace(t))
        .Select(t => t.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
    }

    private string ResolveTeamUid(string teamInput)
    {
      var enterpriseData = Context.EnterpriseData;
      if (enterpriseData != null)
      {
        if (enterpriseData.TryGetTeam(teamInput, out _))
        {
          return teamInput;
        }

        var byName = enterpriseData.Teams.FirstOrDefault(t =>
          string.Equals(t.Name, teamInput, StringComparison.OrdinalIgnoreCase));
        if (byName != null)
        {
          return byName.Uid;
        }
      }

      var vault = Context.GetVault();
      if (vault?.Teams != null)
      {
        var vaultTeam = vault.Teams.FirstOrDefault(t =>
          string.Equals(t.TeamUid, teamInput, StringComparison.Ordinal)
          || string.Equals(t.Name, teamInput, StringComparison.OrdinalIgnoreCase));
        if (vaultTeam != null)
        {
          return vaultTeam.TeamUid;
        }
      }

      throw new InvalidOperationException(
        $"Team \"{teamInput}\" not found. Use a valid team UID or team name.");
    }

    private void PrintReadJson(WorkflowConfig response, string recordUid)
    {
      var parameters = response.Parameters ?? new WorkflowParameters();
      var result = new Dictionary<string, object>
      {
        ["record_uid"] = recordUid,
        ["record_name"] = ResolveResourceName(parameters.Resource),
        ["parameters"] = new Dictionary<string, object>
        {
          ["approvals_needed"] = parameters.ApprovalsNeeded,
          ["checkout_needed"] = parameters.CheckoutNeeded,
          ["start_access_on_approval"] = parameters.StartAccessOnApproval,
          ["require_reason"] = parameters.RequireReason,
          ["require_ticket"] = parameters.RequireTicket,
          ["require_mfa"] = parameters.RequireMFA,
          ["access_duration"] = WorkflowUtils.FormatDuration(parameters.AccessLength),
          ["allowed_times"] = WorkflowUtils.FormatTemporalFilter(parameters.AllowedTimes),
        },
        ["approvers"] = BuildApproverJsonList(response),
      };
      Console.WriteLine(Json.WriteFormatted(result));
    }

    private void PrintReadTable(WorkflowConfig response, string recordUid)
    {
      var parameters = response.Parameters ?? new WorkflowParameters();
      Console.WriteLine();
      Console.WriteLine("Workflow Configuration");
      Console.WriteLine();
      Console.WriteLine($"Record: {ResolveResourceName(parameters.Resource)}");
      Console.WriteLine($"Record UID: {recordUid}");

      if (response.CreatedOn > 0)
      {
        var created = DateTimeOffset.FromUnixTimeMilliseconds(response.CreatedOn).LocalDateTime;
        Console.WriteLine($"Created: {created:yyyy-MM-dd HH:mm:ss}");
      }

      Console.WriteLine();
      Console.WriteLine("Access Parameters:");
      Console.WriteLine($"  Approvals needed: {parameters.ApprovalsNeeded}");
      Console.WriteLine($"  Check-in/out required: {(parameters.CheckoutNeeded ? "Yes" : "No")}");
      Console.WriteLine($"  Access duration: {WorkflowUtils.FormatDuration(parameters.AccessLength)}");
      Console.WriteLine(
        $"  Timer starts: {(parameters.StartAccessOnApproval ? "On approval" : "On check-out")}");

      Console.WriteLine();
      Console.WriteLine("Requirements:");
      Console.WriteLine($"  Reason required: {(parameters.RequireReason ? "Yes" : "No")}");
      Console.WriteLine($"  Ticket required: {(parameters.RequireTicket ? "Yes" : "No")}");
      Console.WriteLine($"  MFA required: {(parameters.RequireMFA ? "Yes" : "No")}");

      if (parameters.AllowedTimes != null)
      {
        var at = parameters.AllowedTimes;
        Console.WriteLine();
        Console.WriteLine("Allowed Times:");
        if (at.AllowedDays.Count > 0)
        {
          Console.WriteLine($"  Days: {string.Join(", ", at.AllowedDays.Select(WorkflowUtils.FormatDayName))}");
        }

        foreach (var tr in at.TimeRanges)
        {
          var startH = Math.DivRem(tr.StartTime, 100, out var startM);
          var endH = Math.DivRem(tr.EndTime, 100, out var endM);
          Console.WriteLine($"  Time: {startH:D2}:{startM:D2} - {endH:D2}:{endM:D2}");
        }

        if (!string.IsNullOrEmpty(at.TimeZone))
        {
          Console.WriteLine($"  Timezone: {at.TimeZone}");
        }
      }

      if (response.Approvers.Count > 0)
      {
        Console.WriteLine();
        Console.WriteLine($"Approvers ({response.Approvers.Count}):");
        var idx = 1;
        foreach (var approver in response.Approvers)
        {
          var escLabel = string.Empty;
          if (approver.Escalation)
          {
            escLabel = " (Escalation";
            if (approver.EscalationAfterMs > 0)
            {
              escLabel += $" after {WorkflowUtils.FormatDuration(approver.EscalationAfterMs)}";
            }

            escLabel += ")";
          }

          if (approver.HasUser)
          {
            Console.WriteLine($"  {idx}. User: {approver.User}{escLabel}");
          }
          else if (approver.HasUserId)
          {
            Console.WriteLine($"  {idx}. User: {ResolveUserDisplay(approver.UserId)}{escLabel}");
          }
          else if (approver.HasTeamUid)
          {
            var teamUid = approver.TeamUid.ToByteArray().Base64UrlEncode();
            var teamName = ResolveTeamName(teamUid);
            var teamDisplay = !string.IsNullOrEmpty(teamName) ? $"{teamName} ({teamUid})" : teamUid;
            Console.WriteLine($"  {idx}. Team: {teamDisplay}{escLabel}");
          }
          else
          {
            Console.WriteLine($"  {idx}. Approver{escLabel}");
          }

          idx++;
        }
      }
      else
      {
        Console.WriteLine();
        Console.WriteLine("No approvers configured");
        Console.WriteLine($"Add approvers with: pam-workflow add-approver {recordUid} --user <email>");
      }

      Console.WriteLine();
    }

    private List<Dictionary<string, object>> BuildApproverJsonList(WorkflowConfig response)
    {
      var approvers = new List<Dictionary<string, object>>();
      foreach (var approver in response.Approvers)
      {
        var info = new Dictionary<string, object>
        {
          ["escalation"] = approver.Escalation,
        };
        if (approver.EscalationAfterMs > 0)
        {
          info["escalation_after"] = WorkflowUtils.FormatDuration(approver.EscalationAfterMs);
        }

        if (approver.HasUser)
        {
          info["type"] = "user";
          info["email"] = approver.User;
        }
        else if (approver.HasUserId)
        {
          info["type"] = "user_id";
          info["user_id"] = approver.UserId;
        }
        else if (approver.HasTeamUid)
        {
          info["type"] = "team";
          info["team_uid"] = approver.TeamUid.ToByteArray().Base64UrlEncode();
        }

        approvers.Add(info);
      }

      return approvers;
    }

    private string ResolveResourceName(GraphSync.GraphSyncRef resource)
    {
      if (resource == null)
      {
        return string.Empty;
      }

      if (!string.IsNullOrEmpty(resource.Name))
      {
        return resource.Name;
      }

      if (resource.Value != null && !resource.Value.IsEmpty)
      {
        var uid = resource.Value.ToByteArray().Base64UrlEncode();
        var vault = Context.GetVault();
        if (vault != null && vault.TryGetKeeperRecord(uid, out var record))
        {
          return record.Title ?? uid;
        }

        // Approver may not have direct vault access to the record (not shared with them yet).
        // Nested Share Folder sync still exposes title/type metadata without requiring full record decrypt.
        if (vault != null && vault.TryGetKeeperNSFRecord(uid, out var nsfRecord)
            && !string.IsNullOrEmpty(nsfRecord.Title))
        {
          return nsfRecord.Title;
        }

        return string.Empty;
      }

      return string.Empty;
    }

    private string ResolveUserDisplay(long userId)
    {
      var enterpriseData = Context.EnterpriseData;
      if (enterpriseData != null && enterpriseData.TryGetUserById(userId, out var user)
          && !string.IsNullOrEmpty(user.Email))
      {
        return user.Email;
      }

      return string.Empty;
    }

    private string ResolveTeamName(string teamUid)
    {
      var enterpriseData = Context.EnterpriseData;
      if (enterpriseData != null && enterpriseData.TryGetTeam(teamUid, out var team)
          && !string.IsNullOrEmpty(team.Name))
      {
        return team.Name;
      }

      return string.Empty;
    }

    private VaultOnline RequireVault()
    {
      var vault = Context.GetVault();
      if (vault == null)
      {
        throw new VaultException("Vault is not initialized. Login to initialize the vault.");
      }

      return vault;
    }

    private TypedRecord ResolveWorkflowRecord(
      VaultOnline vault,
      string identifier,
      bool validateWorkflowType = true)
    {
      TypedRecord record = null;
      if (vault.TryGetKeeperRecord(identifier, out var byUid) && byUid is TypedRecord typedByUid)
      {
        record = typedByUid;
      }
      else
      {
        var matches = vault.KeeperRecords
          .OfType<TypedRecord>()
          .Where(x => string.Equals(x.Title, identifier, StringComparison.OrdinalIgnoreCase))
          .ToList();
        if (matches.Count > 1)
        {
          throw new InvalidOperationException($"Record name '{identifier}' is not unique. Use record UID.");
        }

        if (matches.Count == 1)
        {
          record = matches[0];
        }
      }

      if (record == null)
      {
        throw new InvalidOperationException($"Record \"{identifier}\" not found");
      }

      if (validateWorkflowType)
      {
        var recordType = record.TypeName ?? "unknown";
        if (!PamRecordTypes.Workflow.Contains(recordType))
        {
          var supported = string.Join(", ", PamRecordTypes.Workflow.OrderBy(x => x, StringComparer.Ordinal));
          throw new InvalidOperationException(
            $"Record \"{record.Title}\" is of type \"{recordType}\" which does not support workflows.\n" +
            $"Supported record types: {supported}");
        }
      }

      return record;
    }
  }

  internal class PamWorkflowOptions
  {
    [Value(0, Required = false,
      HelpText = "Command: create, read, update, delete, add-approver, remove-approver, pending, approve, deny, request, start, end, state, my-access")]
    public string Command { get; set; }

    [Value(1, Required = false, HelpText = "Record UID/name, or Flow UID (approve/deny/start/end)")]
    public string Record { get; set; }

    [Option('n', "approvals-needed", Required = false,
      HelpText = "Number of approvals required (create default: 1)")]
    public int? ApprovalsNeeded { get; set; }

    [Option("checkout", Required = false,
      HelpText = "Enable/disable check-in/check-out (create: flag; update: true/false)")]
    public bool? Checkout { get; set; }

    [Option("start-on-approval", Required = false,
      HelpText = "Start access timer when approved vs checked out (create: flag; update: true/false)")]
    public bool? StartOnApproval { get; set; }

    [Option("require-reason", Required = false,
      HelpText = "Require reason for access (create: flag; update: true/false)")]
    public bool? RequireReason { get; set; }

    [Option("require-ticket", Required = false,
      HelpText = "Require ticket number (create: flag; update: true/false)")]
    public bool? RequireTicket { get; set; }

    [Option("require-mfa", Required = false,
      HelpText = "Require MFA verification (create: flag; update: true/false)")]
    public bool? RequireMfa { get; set; }

    [Option('d', "duration", Required = false,
      HelpText = "Access duration (e.g., \"2h\", \"30m\", \"1d\"; bare number = minutes). Create default: 1d")]
    public string Duration { get; set; }

    [Option("allowed-days", Required = false,
      HelpText = "Comma-separated allowed days (e.g., \"mon,tue,wed,thu,fri\")")]
    public string AllowedDays { get; set; }

    [Option("time-range", Required = false,
      HelpText = "Same-day allowed time window in HH:MM-HH:MM format (e.g., \"09:00-17:00\"); end must be after start")]
    public string TimeRange { get; set; }

    [Option('u', "user", Required = false,
      HelpText = "User email for create/add-approver/remove-approver. Pass multiple times.")]
    public IList<string> Users { get; set; }

    [Option("approver", Required = false,
      HelpText = "User email approver for create (alias of --user). Pass multiple times.")]
    public IList<string> Approvers { get; set; }

    [Option('t', "team", Required = false,
      HelpText = "Team name or UID for add-approver/remove-approver. Pass multiple times.")]
    public IList<string> Teams { get; set; }

    [Option('e', "escalation", Required = false,
      HelpText = "Mark as escalation approver (add-approver). On request, -e aliases --escalate.")]
    public bool Escalation { get; set; }

    [Option("escalation-after", Required = false,
      HelpText = "Time before escalating (e.g., \"30m\", \"1h\"; bare number = minutes). Requires --escalation")]
    public string EscalationAfter { get; set; }

    [Option('r', "reason", Required = false,
      HelpText = "Reason for access request or denial (request/deny)")]
    public string Reason { get; set; }

    [Option("ticket", Required = false,
      HelpText = "External ticket/reference number (request)")]
    public string Ticket { get; set; }

    [Option("escalate", Required = false,
      HelpText = "Escalate a pending request (request). -e is accepted as an alias on request.")]
    public bool Escalate { get; set; }

    [Option('c', "cancel", Required = false,
      HelpText = "Cancel a pending or active workflow request (request)")]
    public bool Cancel { get; set; }

    [Option('f', "force", Required = false,
      HelpText = "Force check-in another user's session (end)")]
    public bool Force { get; set; }

    [Option("format", Required = false, Default = "table", HelpText = "Output format: table, json")]
    public string Format { get; set; }

    internal bool IsFormatOutputJson => string.Equals(Format, "json", StringComparison.OrdinalIgnoreCase);

    internal static IList<string> NormalizeTriBoolTokens(IList<string> tokens)
    {
      var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
      {
        "--checkout",
        "--start-on-approval",
        "--require-reason",
        "--require-ticket",
        "--require-mfa",
      };

      var result = new List<string>();
      for (var i = 0; i < tokens.Count; i++)
      {
        var token = tokens[i];
        result.Add(token);
        if (token.IndexOf('=') >= 0 || !names.Contains(token))
        {
          continue;
        }

        var next = i + 1 < tokens.Count ? tokens[i + 1] : null;
        if (!IsTriBoolValue(next))
        {
          result.Add("true");
        }
      }

      return result;
    }

    /// <summary>
    /// Ensures positional values that start with '-' (such as base64url UIDs)
    /// are treated as values rather than command-line options.
    /// Options stay before "--" so flags after a dash UID are still parsed.
    /// </summary>
    internal static IList<string> FixDashPrefixedPositionals(IList<string> tokens)
    {
      if (tokens == null || tokens.Count == 0)
      {
        return tokens;
      }

      foreach (var token in tokens)
      {
        if (token == "--")
        {
          return tokens;
        }
      }

      var knownOpts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
      {
        "-n", "--approvals-needed",
        "--checkout",
        "--start-on-approval",
        "--require-reason",
        "--require-ticket",
        "--require-mfa",
        "-d", "--duration",
        "--allowed-days",
        "--time-range",
        "-u", "--user",
        "--approver",
        "-t", "--team",
        "-e", "--escalation",
        "--escalation-after",
        "-r", "--reason",
        "--ticket",
        "--escalate",
        "-c", "--cancel",
        "-f", "--force",
        "--format",
        "-h", "--help",
        "--version",
      };
      var consumesValue = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
      {
        "-n", "--approvals-needed",
        "--checkout",
        "--start-on-approval",
        "--require-reason",
        "--require-ticket",
        "--require-mfa",
        "-d", "--duration",
        "--allowed-days",
        "--time-range",
        "-u", "--user",
        "--approver",
        "-t", "--team",
        "--escalation-after",
        "-r", "--reason",
        "--ticket",
        "--format",
      };

      var positionals = new List<string>();
      var options = new List<string>();
      var dashPositionals = new List<string>();
      var skipNext = false;
      for (var i = 0; i < tokens.Count; i++)
      {
        var token = tokens[i];
        if (skipNext)
        {
          options.Add(token);
          skipNext = false;
          continue;
        }

        var optName = GetOptionName(token);
        if (knownOpts.Contains(optName))
        {
          options.Add(token);
          if (consumesValue.Contains(optName) && token.IndexOf('=') < 0)
          {
            skipNext = true;
          }

          continue;
        }

        if (token.StartsWith("--", StringComparison.Ordinal))
        {
          options.Add(token);
          if (token.IndexOf('=') < 0)
          {
            skipNext = true;
          }

          continue;
        }

        if (token.StartsWith("-", StringComparison.Ordinal) && token != "-")
        {
          dashPositionals.Add(token);
        }
        else
        {
          positionals.Add(token);
        }
      }

      if (dashPositionals.Count == 0)
      {
        return tokens;
      }

      var result = new List<string>(positionals.Count + options.Count + dashPositionals.Count + 1);
      result.AddRange(positionals);
      result.AddRange(options);
      result.Add("--");
      result.AddRange(dashPositionals);
      return result;
    }

    private static string GetOptionName(string token)
    {
      if (string.IsNullOrEmpty(token) || !token.StartsWith("--", StringComparison.Ordinal))
      {
        return token;
      }

      var eq = token.IndexOf('=');
      return eq >= 0 ? token.Substring(0, eq) : token;
    }

    private static bool IsTriBoolValue(string value)
    {
      return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
             || string.Equals(value, "false", StringComparison.OrdinalIgnoreCase);
    }
  }

  internal sealed class PamWorkflowParseableCommand : ParseableCommandMeta<PamWorkflowOptions>, ICommand
  {
    public Func<PamWorkflowOptions, Task> Action { get; set; }

    public Task ExecuteCommand(string args)
    {
      var tokens = PamWorkflowOptions.FixDashPrefixedPositionals(
        PamWorkflowOptions.NormalizeTriBoolTokens(args.TokenizeArguments().ToList()));
      var parsed = CommandExtensions.DefaultParser.ParseArguments<PamWorkflowOptions>(tokens);
      PamWorkflowOptions options = null;
      parsed.WithParsed(o => { options = o; });
      if (options == null)
      {
        parsed.WithNotParsed(errors =>
        {
          foreach (var error in errors)
          {
            if (error.Tag != ErrorType.HelpRequestedError
                && error.Tag != ErrorType.VersionRequestedError)
            {
              Console.Error.WriteLine(error);
            }
          }
        });
        return Task.CompletedTask;
      }

      return Action?.Invoke(options) ?? Task.CompletedTask;
    }
  }
}
