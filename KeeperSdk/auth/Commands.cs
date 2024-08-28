using System.Collections.Generic;
using System.Runtime.Serialization;

namespace KeeperSecurity.Commands
{
    [DataContract]
    public class KeeperApiCommand
    {
        public KeeperApiCommand(string command)
        {
            this.command = command;
        }

        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;

        [DataMember(Name = "locale", EmitDefaultValue = false)]
        public string locale = "en_US";

        [DataMember(Name = "client_version", EmitDefaultValue = false)]
        public string clientVersion;
    }

    [DataContract]
    public class KeeperApiResponse
    {
        [DataMember(Name = "result", EmitDefaultValue = false)]
        public string result;

        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string resultCode;

        [DataMember(Name = "message", EmitDefaultValue = false)]
        public string message;

        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;

        public bool IsSuccess => result == "success";
    }

    [DataContract]
    public class KeeperApiErrorResponse
    {
        [DataMember(Name = "path")]
        public string Path { get; set; }

        [DataMember(Name = "error")]
        public string Error { get; set; }

        [DataMember(Name = "message")]
        public string Message { get; set; }

        [DataMember(Name = "additional_info")]
        public string AdditionalInfo { get; set; }

        [DataMember(Name = "location")]
        public string Location { get; set; }

        [DataMember(Name = "key_id")]
        public int KeyId { get; set; }

        [DataMember(Name = "region_host")]
        public string RegionHost { get; set; }
    }

    public interface IPasswordRules
    {
        string PasswordRulesIntro { get; }
        PasswordRule[] PasswordRules { get; }
    }

    [DataContract]
    public class PasswordRequirements: IPasswordRules
    {
        [DataMember(Name = "password_rules_intro", EmitDefaultValue = false)]
        public string PasswordRulesIntro { get; set; }

        [DataMember(Name = "password_rules", EmitDefaultValue = false)]
        public PasswordRule[] PasswordRules { get; set; }
    }

    [DataContract]
    public class PasswordRule
    {
        [DataMember(Name = "match")]
        public bool match;

        [DataMember(Name = "pattern")]
        public string pattern;

        [DataMember(Name = "description")]
        public string description;

        [DataMember(Name = "rule_type")]
        public string ruleType;
    }

    [DataContract]
    public class AuthenticatedCommand : KeeperApiCommand
    {
        public AuthenticatedCommand(string command) : base(command)
        {
        }

        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        public string deviceId;

        [DataMember(Name = "session_token", EmitDefaultValue = false)]
        public string sessionToken;

        [DataMember(Name = "username", EmitDefaultValue = false)]
        public string username;
    }

    [DataContract]
    public class SetClientKeyCommand : AuthenticatedCommand
    {
        public SetClientKeyCommand() : base("set_client_key")
        {
        }

        [DataMember(Name = "client_key")]
        public string clientKey;
    }

    [DataContract]
    public class SetClientKeyResponse : KeeperApiResponse
    {
        [DataMember(Name = "client_key")]
        public string clientKey;
    }

    [DataContract]
    public class GetPushInfoCommand : AuthenticatedCommand
    {
        public GetPushInfoCommand() : base("get_push_info")
        {
        }

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;
    }

    [DataContract]
    public class GetPushInfoResponse : KeeperApiResponse
    {
        [DataMember(Name = "url")]
        public string url;
    }

    [DataContract]
    public class ExecuteCommand : AuthenticatedCommand
    {
        public ExecuteCommand() : base("execute") { }

        [DataMember(Name = "requests", EmitDefaultValue = false)]
        public ICollection<KeeperApiCommand> Requests { get; set; }
    }

    [DataContract]
    public class ExecuteResponse : KeeperApiResponse
    {
        [DataMember(Name = "results")]
        public IList<KeeperApiResponse> Results { get; set; }
    }

    [DataContract]
    public class AuditEventInput
    {
        [DataMember(Name = "record_uid", EmitDefaultValue = false)]
        public string RecordUid { get; set; }

        [DataMember(Name = "attachment_id", EmitDefaultValue = false)]
        public string AttachmentId { get; set; }
    }

    [DataContract]
    public class AuditEventItem
    {
        [DataMember(Name = "audit_event_type", EmitDefaultValue = false)]
        public string AuditEventType { get; set; }

        [DataMember(Name = "inputs", EmitDefaultValue = false)]
        public AuditEventInput Inputs { get; set; }

        [DataMember(Name = "event_time", EmitDefaultValue = false)]
        public long? EventTime { get; set; }
        
    }

    [DataContract]
    public class AuditEventLoggingCommand : AuthenticatedCommand
    {
        public AuditEventLoggingCommand() : base("audit_event_client_logging") { }

        [DataMember(Name = "item_logs", EmitDefaultValue = false)]
        public AuditEventItem[] ItemLogs { get; set; }
    }

    [DataContract]
    public class AuditEventLoggingResponse : KeeperApiResponse
    {
        [DataMember(Name = "ignored", EmitDefaultValue = false)]
        public AuditEventItem[] Ignored { get; set; }
    }

}

