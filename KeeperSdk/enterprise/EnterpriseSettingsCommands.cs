using System.Runtime.Serialization;
using KeeperSecurity.Commands;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Enterprise audit alert filter entry (API returns this shape under AuditAlertFilter).
    /// </summary>
    [DataContract]
    public class AuditAlertFilterEntry
    {
        [DataMember(Name = "id")]
        public int Id { get; set; }

        [DataMember(Name = "alertUid")]
        public int AlertUid { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "frequency", EmitDefaultValue = false)]
        public AlertFrequency Frequency { get; set; }

        [DataMember(Name = "filter", EmitDefaultValue = false)]
        public AuditAlertFilterDetail Filter { get; set; }

        [DataMember(Name = "recipients", EmitDefaultValue = false)]
        public AlertRecipient[] Recipients { get; set; }

        [DataMember(Name = "sendToOriginator", EmitDefaultValue = false)]
        public bool SendToOriginator { get; set; }
    }

    [DataContract]
    public class AlertFrequency
    {
        [DataMember(Name = "period")]
        public string Period { get; set; }

        [DataMember(Name = "count", EmitDefaultValue = false)]
        public int? Count { get; set; }
    }

    [DataContract]
    public class AuditAlertFilterDetail
    {
        [DataMember(Name = "events", EmitDefaultValue = false)]
        public int[] Events { get; set; }

        [DataMember(Name = "userIds", EmitDefaultValue = false)]
        public long[] UserIds { get; set; }

        [DataMember(Name = "recordUids", EmitDefaultValue = false)]
        public IdSelectedEntry[] RecordUids { get; set; }

        [DataMember(Name = "sharedFolderUids", EmitDefaultValue = false)]
        public IdSelectedEntry[] SharedFolderUids { get; set; }
    }

    [DataContract]
    public class IdSelectedEntry
    {
        [DataMember(Name = "id")]
        public string Id { get; set; }

        [DataMember(Name = "selected")]
        public bool Selected { get; set; }
    }

    [DataContract]
    public class AlertRecipient
    {
        [DataMember(Name = "id")]
        public int Id { get; set; }

        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [DataMember(Name = "disabled", EmitDefaultValue = false)]
        public bool Disabled { get; set; }

        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        [DataMember(Name = "phone", EmitDefaultValue = false)]
        public string Phone { get; set; }

        [DataMember(Name = "phoneCountry", EmitDefaultValue = false)]
        public int? PhoneCountry { get; set; }

        [DataMember(Name = "webhook", EmitDefaultValue = false)]
        public AlertWebhookInfo Webhook { get; set; }
    }

    [DataContract]
    public class AlertWebhookInfo
    {
        [DataMember(Name = "url")]
        public string Url { get; set; }

        [DataMember(Name = "template", EmitDefaultValue = false)]
        public string Template { get; set; }

        [DataMember(Name = "token", EmitDefaultValue = false)]
        public string Token { get; set; }

        [DataMember(Name = "allowUnverifiedCertificate", EmitDefaultValue = false)]
        public bool AllowUnverifiedCertificate { get; set; }
    }

    [DataContract]
    public class AuditAlertContextEntry
    {
        [DataMember(Name = "id")]
        public int Id { get; set; }

        [DataMember(Name = "counter", EmitDefaultValue = false)]
        public int? Counter { get; set; }

        [DataMember(Name = "sentCounter", EmitDefaultValue = false)]
        public int? SentCounter { get; set; }

        [DataMember(Name = "lastSent", EmitDefaultValue = false)]
        public string LastSent { get; set; }

        [DataMember(Name = "disabled", EmitDefaultValue = false)]
        public bool Disabled { get; set; }
    }

    [DataContract]
    public class AuditAlertContextPatch
    {
        [DataMember(Name = "id")]
        public int Id { get; set; }

        [DataMember(Name = "disabled", EmitDefaultValue = false)]
        public bool? Disabled { get; set; }

        [DataMember(Name = "counter", EmitDefaultValue = false)]
        public int? Counter { get; set; }

        [DataMember(Name = "sentCounter", EmitDefaultValue = false)]
        public int? SentCounter { get; set; }

        [DataMember(Name = "lastReset", EmitDefaultValue = false)]
        public long? LastReset { get; set; }
    }

    [DataContract]
    public class GetEnterpriseSettingCommand : AuthenticatedCommand
    {
        public GetEnterpriseSettingCommand() : base("get_enterprise_setting")
        {
        }

        [DataMember(Name = "include")]
        public string[] Include { get; set; }
    }

    [DataContract]
    public class GetEnterpriseSettingResponse : KeeperApiResponse
    {
        [DataMember(Name = "AuditAlertFilter")]
        public AuditAlertFilterEntry[] AuditAlertFilter { get; set; }

        [DataMember(Name = "AuditAlertContext")]
        public AuditAlertContextEntry[] AuditAlertContext { get; set; }
    }

    [DataContract]
    public class PutAuditAlertFilterEnterpriseSettingCommand : AuthenticatedCommand
    {
        public PutAuditAlertFilterEnterpriseSettingCommand() : base("put_enterprise_setting")
        {
        }

        [DataMember(Name = "type")]
        public string Type { get; set; } = "AuditAlertFilter";

        [DataMember(Name = "settings")]
        public AuditAlertFilterEntry Settings { get; set; }
    }

    [DataContract]
    public class PutAuditAlertContextEnterpriseSettingCommand : AuthenticatedCommand
    {
        public PutAuditAlertContextEnterpriseSettingCommand() : base("put_enterprise_setting")
        {
        }

        [DataMember(Name = "type")]
        public string Type { get; set; } = "AuditAlertContext";

        [DataMember(Name = "settings")]
        public AuditAlertContextPatch Settings { get; set; }
    }

    [DataContract]
    public class DeleteEnterpriseSettingCommand : AuthenticatedCommand
    {
        public DeleteEnterpriseSettingCommand() : base("delete_enterprise_setting")
        {
        }

        [DataMember(Name = "type")]
        public string Type { get; set; }

        [DataMember(Name = "id")]
        public int Id { get; set; }
    }
}
