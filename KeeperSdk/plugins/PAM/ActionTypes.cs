using System.Collections.Generic;
using System.Runtime.Serialization;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Result of scheduling or querying a PAM gateway action.
  /// </summary>
  public class PamGatewayActionResult
  {
    /// <summary>
    /// Conversation / job id returned by the gateway.
    /// </summary>
    public string ConversationId { get; set; }

    /// <summary>
    /// Gateway that handled the action.
    /// </summary>
    public string GatewayUid { get; set; }

    /// <summary>
    /// True when the gateway accepted this as a scheduled job.
    /// </summary>
    public bool IsScheduled { get; set; }

    /// <summary>
    /// True when the gateway reported success.
    /// </summary>
    public bool IsOk { get; set; }

    /// <summary>
    /// Raw JSON payload from the gateway controller.
    /// </summary>
    public string RawPayloadJson { get; set; }

    /// <summary>
    /// Parsed payload dictionary for callers that need structured fields.
    /// </summary>
    public Dictionary<string, object> Payload { get; set; }

    /// <summary>
    /// Job-status details when the response includes job info.
    /// </summary>
    public PamJobInfoDetails JobInfo { get; set; }
  }

  /// <summary>
  /// Options for on-demand PAM credential rotation.
  /// </summary>
  public class PamRotateOptions
  {
    /// <summary>
    /// Single record UID to rotate. Ignored when <see cref="Folder"/> is set.
    /// </summary>
    public string RecordUid { get; set; }

    /// <summary>
    /// Shared folder UID or title pattern. Rotates all pamUser records in matching folders.
    /// </summary>
    public string Folder { get; set; }

    /// <summary>
    /// When true with <see cref="Folder"/>, only report selection counts and do not rotate.
    /// </summary>
    public bool DryRun { get; set; }
  }

  /// <summary>
  /// Discriminated result of <see cref="ActionUtils.RotateAsync"/>.
  /// Exactly one of <see cref="RecordResult"/> or <see cref="FolderResult"/> is set.
  /// </summary>
  public class PamRotateResult
  {
    /// <summary>
    /// Gateway result when rotating a single record.
    /// </summary>
    public PamGatewayActionResult RecordResult { get; set; }

    /// <summary>
    /// Folder-mode rotate summary when using a folder selector.
    /// </summary>
    public PamRotateFolderResult FolderResult { get; set; }

    /// <summary>
    /// True when the rotate ran (or dry-ran) in folder mode.
    /// </summary>
    public bool IsFolderMode => FolderResult != null;
  }

  /// <summary>
  /// Summary of a folder-mode rotate selection or run.
  /// </summary>
  public class PamRotateFolderResult
  {
    /// <summary>
    /// Number of shared folders matched by the folder selector.
    /// </summary>
    public int FolderCount { get; set; }

    /// <summary>
    /// Number of pamUser records selected for rotation.
    /// </summary>
    public int RecordCount { get; set; }

    /// <summary>
    /// True when selection was reported without scheduling rotates.
    /// </summary>
    public bool DryRun { get; set; }

    /// <summary>
    /// UIDs of pamUser records selected in folder mode.
    /// </summary>
    public IList<string> RecordUids { get; set; } = new List<string>();

    /// <summary>
    /// Per-record gateway results from a live folder rotate.
    /// </summary>
    public IList<PamGatewayActionResult> Results { get; set; } = new List<PamGatewayActionResult>();

    /// <summary>
    /// Per-record failures skipped during folder bulk rotate.
    /// </summary>
    public IList<PamRotateRecordError> Errors { get; set; } = new List<PamRotateRecordError>();
  }

  /// <summary>
  /// Per-record failure during folder bulk rotate.
  /// </summary>
  public class PamRotateRecordError
  {
    /// <summary>
    /// UID of the record that failed.
    /// </summary>
    public string RecordUid { get; set; }

    /// <summary>
    /// Error message for that record.
    /// </summary>
    public string Message { get; set; }
  }

  /// <summary>
  /// Parsed job-info fields for CLI display.
  /// </summary>
  public class PamJobInfoDetails
  {
    /// <summary>
    /// Job status or reason from the gateway.
    /// </summary>
    public string Status { get; set; }

    /// <summary>
    /// Reported execution duration of the job.
    /// </summary>
    public string Duration { get; set; }

    /// <summary>
    /// Success / response message from the job payload.
    /// </summary>
    public string ResponseMessage { get; set; }

    /// <summary>
    /// Exception text when the gateway job failed.
    /// </summary>
    public string ExecutionException { get; set; }
  }

  // Wire DTOs for gateway JSON (snake_case / camelCase variants).
  [DataContract]
  internal class GatewayActionResponseDto
  {
    [DataMember(Name = "is_ok")]
    public bool? IsOkSnake { get; set; }

    [DataMember(Name = "isOk")]
    public bool? IsOkCamel { get; set; }

    [DataMember(Name = "is_scheduled")]
    public bool? IsScheduledSnake { get; set; }

    [DataMember(Name = "isScheduled")]
    public bool? IsScheduledCamel { get; set; }

    [DataMember(Name = "conversation_id")]
    public string ConversationIdSnake { get; set; }

    [DataMember(Name = "conversationId")]
    public string ConversationIdCamel { get; set; }

    [DataMember(Name = "data")]
    public GatewayJobInfoDataDto Data { get; set; }

    [DataMember(Name = "payload")]
    public string NestedPayload { get; set; }

    public bool IsOk => IsOkSnake == true || IsOkCamel == true;
    public bool IsScheduled => IsScheduledSnake == true || IsScheduledCamel == true;
    public string ConversationId => !string.IsNullOrEmpty(ConversationIdSnake) ? ConversationIdSnake : ConversationIdCamel;
  }

  [DataContract]
  internal class GatewayJobInfoDataDto
  {
    [DataMember(Name = "status")]
    public string Status { get; set; }

    [DataMember(Name = "reason")]
    public string Reason { get; set; }

    [DataMember(Name = "executionDuration")]
    public string ExecutionDuration { get; set; }

    [DataMember(Name = "execException")]
    public string ExecException { get; set; }

    [DataMember(Name = "execResponseValue")]
    public GatewayExecResponseDto ExecResponseValue { get; set; }
  }

  [DataContract]
  internal class GatewayExecResponseDto
  {
    [DataMember(Name = "message")]
    public string Message { get; set; }
  }
}
