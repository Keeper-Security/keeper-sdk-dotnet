using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;
using RouterProto = Router;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// PAM gateway actions (on-demand rotate, job status).
  /// </summary>
  public static class ActionUtils
  {
    private const string GetConfigurationControllerEndpoint = "pam/get_configuration_controller";
    private const string SendControllerMessagePath = "send_controller_message";
    private const int DefaultGatewayTimeoutMs = 15000;
    private const int KeeperUidByteLength = 16;

    internal static readonly Regex Base64UrlTokenPattern = new(
      @"^[A-Za-z0-9_\-+/=]+$",
      RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Schedules an on-demand rotation for a single record or all pamUser records in matching shared folders.
    /// </summary>
    public static async Task<PamRotateResult> RotateAsync(VaultOnline vault, PamRotateOptions options)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (options == null)
      {
        throw new ArgumentNullException(nameof(options));
      }

      var recordUid = options.RecordUid?.Trim() ?? string.Empty;
      var folder = options.Folder?.Trim() ?? string.Empty;
      if (string.IsNullOrEmpty(recordUid) && string.IsNullOrEmpty(folder))
      {
        throw new PamActionException("Either --record-uid/-r or --folder/-f is required.");
      }

      if (string.IsNullOrEmpty(folder))
      {
        return new PamRotateResult
        {
          RecordResult = await RotateRecordAsync(vault, recordUid),
        };
      }

      return new PamRotateResult
      {
        FolderResult = await RotateFolderAsync(vault, folder, options.DryRun),
      };
    }

    /// <summary>
    /// Schedules an on-demand rotation for one vault record through its PAM gateway.
    /// </summary>
    public static async Task<PamGatewayActionResult> RotateRecordAsync(VaultOnline vault, string recordUid)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (string.IsNullOrWhiteSpace(recordUid))
      {
        throw new PamActionException("Record UID is required.");
      }

      var auth = vault.Auth ?? throw new PamActionException("Authentication is required.");
      
      EnsureRotationAllowed(vault.Auth?.AuthContext);

      if (!vault.TryGetKeeperRecord(recordUid.Trim(), out var keeperRecord) || keeperRecord is not TypedRecord record)
      {
        record = ResolveNsfRotateRecord(vault, recordUid.Trim());
        if (record == null)
        {
          throw new PamActionException($"Record [{recordUid}] is not available.");
        }
      }

      RouterProto.RouterRotationInfo rotationInfo;
      try
      {
        rotationInfo = await RotationUtils.GetRotationInfoAsync(auth, record.Uid);
      }
      catch (Exception ex)
      {
        throw new PamActionException($"Failed to get rotation info for record [{record.Uid}].", ex);
      }

      var pwdComplexity = ResolvePasswordComplexity(rotationInfo, record);

      var configUid = FindConfigUidFromLocalVault(vault, record.Uid);
      if (string.IsNullOrEmpty(configUid))
      {
        if (rotationInfo.ConfigurationUid == null || rotationInfo.ConfigurationUid.IsEmpty)
        {
          throw new PamActionException($"PAM Configuration is not available for record [{record.Uid}].");
        }

        configUid = rotationInfo.ConfigurationUid.ToByteArray().Base64UrlEncode();
      }

      string resourceUid = null;
      if (rotationInfo.ResourceUid != null && !rotationInfo.ResourceUid.IsEmpty)
      {
        resourceUid = rotationInfo.ResourceUid.ToByteArray().Base64UrlEncode();
      }

      if (string.IsNullOrEmpty(resourceUid) && !IsNoopRecord(record))
      {
        throw new PamActionException(
          $"Resource UID not found for record [{record.Uid}]. Configure it with \"pam rotation user {record.Uid} --resource RESOURCE_UID\".");
      }

      var gatewayUid = await ResolveGatewayUidAsync(auth, vault, configUid);

      var conversationId = CryptoUtils.GenerateUid();
      var inputs = new Dictionary<string, string>
      {
        ["recordUid"] = record.Uid,
        ["configurationUid"] = configUid,
        ["pwdComplexity"] = pwdComplexity,
      };
      if (!string.IsNullOrEmpty(resourceUid))
      {
        inputs["resourceRef"] = resourceUid;
      }

      var actionJson = BuildGatewayActionJson(
        action: "rotate",
        isScheduled: true,
        conversationId: conversationId,
        gatewayDestination: gatewayUid,
        inputs: inputs);

      var result = await SendActionToGatewayAsync(
        auth,
        actionJson,
        PamProto.ControllerMessageType.CmtRotate,
        gatewayUid,
        conversationId);

      result.GatewayUid = gatewayUid;
      return result;
    }

    /// <summary>
    /// Gets the status of a previously scheduled PAM gateway job.
    /// </summary>
    public static async Task<PamGatewayActionResult> GetJobInfoAsync(
      IAuthentication auth,
      string jobId,
      string gatewayUid = null)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (string.IsNullOrWhiteSpace(jobId))
      {
        throw new PamActionException("Job id is required.");
      }

      var normalizedJobId = RequireBase64UrlUid(jobId, "Job id");
      string normalizedGatewayUid = null;
      if (!string.IsNullOrWhiteSpace(gatewayUid))
      {
        normalizedGatewayUid = RequireBase64UrlUid(gatewayUid, "Gateway UID");
      }

      var conversationId = CryptoUtils.GenerateUid();
      var actionJson = BuildGatewayActionJson(
        action: "job-info",
        isScheduled: false,
        conversationId: conversationId,
        gatewayDestination: null,
        inputs: new Dictionary<string, string>
        {
          ["jobId"] = normalizedJobId,
        });

      var result = await SendActionToGatewayAsync(
        auth,
        actionJson,
        PamProto.ControllerMessageType.CmtGeneral,
        normalizedGatewayUid,
        conversationId);

      result.GatewayUid = normalizedGatewayUid;
      return result;
    }

    /// <summary>
    /// Rotates all pamUser records in shared folders matching UID or title pattern.
    /// </summary>
    public static async Task<PamRotateFolderResult> RotateFolderAsync(VaultOnline vault, string folder, bool dryRun)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      EnsureRotationAllowed(vault.Auth?.AuthContext);

      var folderUids = ResolveSharedFolders(vault, folder);
      var recordUids = new List<string>();

      foreach (var folderUid in folderUids)
      {
        if (vault.TryGetFolder(folderUid, out var node))
        {
          foreach (var ruid in node.Records)
          {
            if (!vault.TryGetKeeperRecord(ruid, out var rec) || rec is not TypedRecord typed)
            {
              continue;
            }

            if (string.Equals(typed.TypeName, "pamUser", StringComparison.OrdinalIgnoreCase)
                && !recordUids.Contains(ruid, StringComparer.Ordinal))
            {
              recordUids.Add(ruid);
            }
          }
        }
        else if (vault.TryGetKeeperNSFFolder(folderUid, out var nsfNode))
        {
          foreach (var ruid in nsfNode.Records)
          {
            if (!vault.TryGetKeeperNSFRecord(ruid, out var nsfRec)
                || !PamVaultHelpers.IsNsfFolderRotateRecord(nsfRec)
                || recordUids.Contains(ruid, StringComparer.Ordinal))
            {
              continue;
            }

            recordUids.Add(ruid);
          }
        }
      }

      var folderResult = new PamRotateFolderResult
      {
        FolderCount = folderUids.Count,
        RecordCount = recordUids.Count,
        DryRun = dryRun,
        RecordUids = recordUids,
      };

      if (dryRun)
      {
        return folderResult;
      }

      foreach (var ruid in recordUids)
      {
        var delaySec = 0;
        while (true)
        {
          try
          {
            var one = await RotateRecordAsync(vault, ruid);
            folderResult.Results.Add(one);
            break;
          }
          catch (Exception ex) when (ex.IsThrottleError())
          {
            delaySec = (delaySec + 10) % 100;
            Debug.WriteLine($"PAM rotate folder: record {ruid} throttled, retry in {1 + delaySec}s");
            await Task.Delay(TimeSpan.FromSeconds(1 + delaySec));
          }
          catch (Exception ex)
          {
            folderResult.Errors.Add(new PamRotateRecordError
            {
              RecordUid = ruid,
              Message = ex.Message,
            });
            Debug.WriteLine($"PAM rotate folder: record {ruid} skipped: {ex}");
            break;
          }
        }
      }

      return folderResult;
    }

    private static List<string> ResolveSharedFolders(VaultOnline vault, string folder)
    {
      var folders = new List<string>();
      if (vault.TryGetFolder(folder, out var byUid)
          && (byUid.FolderType == FolderType.SharedFolder || byUid.FolderType == FolderType.SharedFolderFolder))
      {
        folders.Add(byUid.FolderUid);
        return folders;
      }

      Regex pattern;
      try
      {
        pattern = new Regex(folder, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
      }
      catch (ArgumentException)
      {
        pattern = new Regex(Regex.Escape(folder), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
      }

      foreach (var node in vault.Folders)
      {
        if (node.FolderType != FolderType.SharedFolder && node.FolderType != FolderType.SharedFolderFolder)
        {
          continue;
        }

        if (!string.IsNullOrEmpty(node.Name) && pattern.IsMatch(node.Name))
        {
          folders.Add(node.FolderUid);
        }
      }

      if (vault.TryGetKeeperNSFFolder(folder, out var nsfByUid))
      {
        folders.Add(nsfByUid.FolderUid);
      }

      foreach (var node in vault.KeeperNSFFolderNodes)
      {
        if (!string.IsNullOrEmpty(node.Name) && pattern.IsMatch(node.Name))
        {
          folders.Add(node.FolderUid);
        }
      }

      return folders.Distinct(StringComparer.Ordinal).ToList();
    }

    private static async Task<string> ResolveGatewayUidAsync(IAuthentication auth, VaultOnline vault, string configUid)
    {
      var normalizedConfigUid = RequireBase64UrlUid(configUid, "Configuration UID");
      try
      {
        var rq = new PamProto.PAMGenericUidRequest
        {
          Uid = ByteString.CopyFrom(normalizedConfigUid.Base64UrlDecode()),
        };
        var controller = await auth.ExecuteAuthRest<PamProto.PAMGenericUidRequest, PamProto.PAMController>(
            GetConfigurationControllerEndpoint,
            rq);

        if (controller?.ControllerUid != null && !controller.ControllerUid.IsEmpty)
        {
          return controller.ControllerUid.ToByteArray().Base64UrlEncode();
        }
      }
      catch (Exception ex)
      {
        Debug.WriteLine($"PAM get_configuration_controller failed, trying local pamResources: {ex.Message}");
      }

      if (vault.TryGetKeeperRecord(normalizedConfigUid, out var configRecord)
          && configRecord is TypedRecord typed
          && TryGetPamResources(typed, out var resources)
          && !string.IsNullOrEmpty(resources.ControllerUid))
      {
        return resources.ControllerUid;
      }

      throw new PamActionException($"Gateway UID not found for configuration {normalizedConfigUid}.");
    }

    private static string ResolvePasswordComplexity(RouterProto.RouterRotationInfo rotationInfo, TypedRecord record)
    {
      return ResolvePasswordComplexity(rotationInfo, record.RecordKey);
    }

    private static string ResolvePasswordComplexity(RouterProto.RouterRotationInfo rotationInfo, byte[] recordKey)
    {
      if (!string.IsNullOrEmpty(rotationInfo?.PwdComplexity))
      {
        return rotationInfo.PwdComplexity;
      }

      // Same defaults when PwdComplexity is empty.
      var rules = new PasswordGenerationOptions
      {
        Length = 20,
        Upper = 1,
        Lower = 1,
        Digit = 1,
        Special = 1,
      };
      return RotationUtils.EncryptPasswordComplexity(rules, recordKey).Base64UrlEncode();
    }

    private static TypedRecord ResolveNsfRotateRecord(VaultOnline vault, string identifier)
    {
      if (PamVaultHelpers.TryGetNsfRecord(vault, identifier, out var byUid))
      {
        return PamVaultHelpers.ToTypedRecord(byUid);
      }

      var byTitle = PamVaultHelpers.ResolveNsfRecordByTitle(vault, identifier, allowedTypes: null);
      if (byTitle == null)
      {
        return null;
      }

      return PamVaultHelpers.ToTypedRecord(byTitle);
    }

    private static string FindConfigUidFromLocalVault(VaultOnline vault, string recordUid)
    {
      foreach (var config in PamVaultHelpers.GetConfigurationRecords(vault).Values)
      {
        if (!TryGetPamResources(config, out var resources) || resources.ResourceRef == null)
        {
          continue;
        }

        if (resources.ResourceRef.Any(r => string.Equals(r, recordUid, StringComparison.Ordinal)))
        {
          return config.Uid;
        }
      }

      return null;
    }

    private static bool TryGetPamResources(TypedRecord record, out FieldPamResources resources)
    {
      resources = null;
      if (record == null || !record.FindTypedField("pamResources", null, out var field))
      {
        return false;
      }

      if (field is TypedField<FieldPamResources> typed && typed.Values.Count > 0)
      {
        resources = typed.Values[0];
        return resources != null;
      }

      if (field.ObjectValue is FieldPamResources pam)
      {
        resources = pam;
        return true;
      }

      return false;
    }

    private static bool IsNoopRecord(TypedRecord record)
    {
      if (!record.FindTypedField("text", "NOOP", out var field))
        return false;

      return PamVaultHelpers.IsNoopFieldValue(field.GetValueAt(0)?.ToString());
    }

    // Block only when allow_rotate_credentials is explicitly false.
    // If the key is missing, allow it because .NET handles these settings differently.
    private static void EnsureRotationAllowed(IAuthContext authContext)
    {
      if (authContext?.Enforcements == null || authContext.Enforcements.Count == 0)
      {
        return;
      }

      if (!authContext.Enforcements.TryGetValue("allow_rotate_credentials", out var value) || value == null)
      {
        return;
      }

      if (value is bool allowed)
      {
        if (!allowed)
        {
          throw new PamRotationNotAllowedException();
        }

        return;
      }

      if (value is string s && bool.TryParse(s, out var parsed) && !parsed)
      {
        throw new PamRotationNotAllowedException();
      }
    }

    // Builds gateway action JSON via DataContract serializer (correct escaping for all control chars).
    private static byte[] BuildGatewayActionJson(
      string action,
      bool isScheduled,
      string conversationId,
      string gatewayDestination,
      Dictionary<string, string> inputs)
    {
      Dictionary<string, string> cleanInputs = null;
      if (inputs != null)
      {
        cleanInputs = new Dictionary<string, string>();
        foreach (var pair in inputs)
        {
          if (pair.Value == null)
          {
            continue;
          }

          cleanInputs[pair.Key] = pair.Value;
        }
      }

      var payload = new GatewayActionRequestDto
      {
        Action = action,
        IsScheduled = isScheduled,
        GatewayDestination = string.IsNullOrEmpty(gatewayDestination) ? null : gatewayDestination,
        ConversationId = conversationId,
        Inputs = cleanInputs ?? new Dictionary<string, string>(),
      };

      return JsonUtils.DumpJson(payload, indent: false);
    }

    private static async Task<PamGatewayActionResult> SendActionToGatewayAsync(
      IAuthentication auth,
      byte[] actionJson,
      PamProto.ControllerMessageType messageType,
      string destinationGatewayUid,
      string conversationId)
    {
      PamProto.PAMOnlineControllers online;
      try
      {
        online = await RouterUtils.GetConnectedGatewaysAsync(auth);
      }
      catch (Exception ex)
      {
        throw new PamRouterException("Looks like router is down.", ex);
      }

      var connected = RouterUtils.GetConnectedGatewayUids(online);
      if (connected.Count == 0)
      {
        throw new PamActionException("No running or connected Gateways in your enterprise.");
      }

      byte[] destinationBytes;
      string destinationUidStr;
      if (!string.IsNullOrEmpty(destinationGatewayUid))
      {
        destinationBytes = RequireBase64UrlUidBytes(destinationGatewayUid, "Gateway UID");
        if (!connected.Any(uid => uid.SequenceEqual(destinationBytes)))
        {
          throw new PamActionException("This Gateway currently is not online.");
        }

        destinationUidStr = destinationGatewayUid.Trim();
      }
      else if (connected.Count == 1)
      {
        destinationBytes = connected[0];
        destinationUidStr = destinationBytes.Base64UrlEncode();
      }
      else
      {
        throw new PamActionException(
          "There are more than one Gateways running. Specify a gateway (for example with job-info --gateway).");
      }

      var messageUid = RequireBase64UrlUidBytes(conversationId, "Conversation id");
      var rq = new RouterProto.RouterControllerMessage
      {
        MessageType = messageType,
        MessageUid = ByteString.CopyFrom(messageUid),
        ControllerUid = ByteString.CopyFrom(destinationBytes),
        StreamResponse = false,
        Payload = ByteString.CopyFrom(actionJson),
        Timeout = DefaultGatewayTimeoutMs,
      };

      PamProto.ControllerResponse controllerResponse;
      try
      {
        controllerResponse = await auth.ExecuteRouter<PamProto.ControllerResponse>(
          SendControllerMessagePath,
          rq);
      }
      catch (Exception ex)
      {
        throw new PamActionException($"Failed to send action to gateway: {ex.Message}", ex);
      }

      var result = new PamGatewayActionResult
      {
        ConversationId = conversationId,
        GatewayUid = destinationUidStr,
        IsOk = true,
      };

      if (string.IsNullOrEmpty(controllerResponse.Payload))
      {
        return result;
      }

      ApplyGatewayResponse(result, controllerResponse.Payload);
      return result;
    }

    // Unwraps gateway envelope and fills result flags / job-info fields.
    private static void ApplyGatewayResponse(PamGatewayActionResult result, string controllerPayload)
    {
      result.RawPayloadJson = controllerPayload;
      var dto = ParseGatewayActionResponse(controllerPayload);
      if (dto == null)
      {
        return;
      }

      result.IsOk = dto.IsOk;
      result.IsScheduled = dto.IsScheduled;
      if (!string.IsNullOrEmpty(dto.ConversationId))
      {
        result.ConversationId = dto.ConversationId;
      }

      if (dto.Data != null)
      {
        result.JobInfo = new PamJobInfoDetails
        {
          Status = !string.IsNullOrEmpty(dto.Data.Reason) ? dto.Data.Reason : dto.Data.Status,
          Duration = dto.Data.ExecutionDuration,
          ResponseMessage = dto.Data.ExecResponseValue?.Message,
          ExecutionException = dto.Data.ExecException,
        };
      }

      try
      {
        result.Payload = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(controllerPayload));
        if (result.Payload != null
            && TryGetString(result.Payload, "payload", out var nested)
            && !string.IsNullOrEmpty(nested)
            && !result.Payload.ContainsKey("is_ok")
            && !result.Payload.ContainsKey("isOk"))
        {
          result.Payload = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(nested));
          result.RawPayloadJson = nested;
        }
        else if ((dto.Data != null || dto.IsScheduled || dto.IsOk)
                 && !string.IsNullOrEmpty(dto.NestedPayload))
        {
          result.RawPayloadJson = dto.NestedPayload;
        }
      }
      catch (Exception ex)
      {
        Debug.WriteLine($"PAM gateway response dictionary parse failed: {ex.Message}");
      }
    }

    private static GatewayActionResponseDto ParseGatewayActionResponse(string controllerPayload)
    {
      if (string.IsNullOrEmpty(controllerPayload))
      {
        return null;
      }

      GatewayActionResponseDto outer;
      try
      {
        outer = JsonUtils.ParseJson<GatewayActionResponseDto>(Encoding.UTF8.GetBytes(controllerPayload));
      }
      catch (Exception ex)
      {
        Debug.WriteLine($"PAM gateway response DTO parse failed: {ex.Message}");
        return null;
      }

      if (outer == null)
      {
        return null;
      }

      // Envelope: nested payload is a JSON string with is_ok / is_scheduled / data.
      if (!string.IsNullOrEmpty(outer.NestedPayload)
          && !outer.IsOk
          && !outer.IsScheduled
          && outer.Data == null)
      {
        try
        {
          var inner = JsonUtils.ParseJson<GatewayActionResponseDto>(Encoding.UTF8.GetBytes(outer.NestedPayload));
          if (inner != null)
          {
            return inner;
          }
        }
        catch (Exception ex)
        {
          Debug.WriteLine($"PAM gateway nested payload parse failed: {ex.Message}");
          return outer;
        }
      }

      return outer;
    }

    /// <summary>
    /// Validates a Keeper UID/job ID as Base64/Base64URL that decodes to 16 bytes.
    /// </summary>
    private static string RequireBase64UrlUid(string value, string fieldName)
    {
      RequireBase64UrlUidBytes(value, fieldName);
      return value.Trim();
    }

    private static byte[] RequireBase64UrlUidBytes(string value, string fieldName)
    {
      if (string.IsNullOrWhiteSpace(value))
      {
        throw new PamActionException($"{fieldName} is required.");
      }

      var trimmed = value.Trim();
      if (!Base64UrlTokenPattern.IsMatch(trimmed))
      {
        throw new PamActionException(
           $"{fieldName} is invalid. Expected a base64/base64url Keeper UID " + "(letters, digits, '-', '_', optional '+', '/', '=').");
      }

      var bytes = trimmed.Base64UrlDecode();
      if (bytes == null || bytes.Length != KeeperUidByteLength)
      {
        throw new PamActionException(
          $"{fieldName} is not a valid base64url UID (expected {KeeperUidByteLength} decoded bytes).");
      }

      return bytes;
    }

    private static bool TryGetString(Dictionary<string, object> dict, string key, out string value)
    {
      value = null;
      if (dict == null || !dict.TryGetValue(key, out var obj) || obj == null)
      {
        return false;
      }

      value = obj.ToString();
      return !string.IsNullOrEmpty(value);
    }
  }
}
