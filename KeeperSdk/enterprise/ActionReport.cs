using KeeperSecurity.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Target user status for action report
    /// </summary>
    public enum ActionReportTargetStatus
    {
        /// <summary>Users who haven't logged in</summary>
        NoLogon,
        /// <summary>Users who haven't added/updated records</summary>
        NoUpdate,
        /// <summary>Users who are locked</summary>
        Locked,
        /// <summary>Users who are invited but haven't accepted</summary>
        Invited,
        /// <summary>Users who haven't set up recovery</summary>
        NoRecovery
    }

    /// <summary>
    /// Admin action to apply to users
    /// </summary>
    public enum ActionReportAdminAction
    {
        /// <summary>No action</summary>
        None,
        /// <summary>Lock the user account</summary>
        Lock,
        /// <summary>Delete the user account</summary>
        Delete,
        /// <summary>Transfer and delete the user account</summary>
        Transfer
    }

    /// <summary>
    /// Options for action report
    /// </summary>
    public class ActionReportOptions
    {
        /// <summary>
        /// Target user status to report on (default: NoLogon)
        /// </summary>
        public ActionReportTargetStatus TargetStatus { get; set; } = ActionReportTargetStatus.NoLogon;

        /// <summary>
        /// Number of days since the event of interest (default: 30 for most, 90 for locked)
        /// </summary>
        public int? DaysSince { get; set; }

        /// <summary>
        /// Node name or ID to filter users
        /// </summary>
        public string Node { get; set; }

        /// <summary>
        /// Admin action to apply (default: None)
        /// </summary>
        public ActionReportAdminAction ApplyAction { get; set; } = ActionReportAdminAction.None;

        /// <summary>
        /// Target user for transfer action
        /// </summary>
        public string TargetUser { get; set; }

        /// <summary>
        /// Dry run mode - don't actually apply actions
        /// </summary>
        public bool DryRun { get; set; }

        /// <summary>
        /// Force action without confirmation
        /// </summary>
        public bool Force { get; set; }
    }

    /// <summary>
    /// User info for action report
    /// </summary>
    public class ActionReportUser
    {
        /// <summary>Enterprise user ID</summary>
        public long UserId { get; set; }
        /// <summary>User email/username</summary>
        public string Username { get; set; }
        /// <summary>User display name</summary>
        public string DisplayName { get; set; }
        /// <summary>User status</summary>
        public UserStatus Status { get; set; }
        /// <summary>Transfer status</summary>
        public string TransferStatus { get; set; }
        /// <summary>Node ID</summary>
        public long NodeId { get; set; }
        /// <summary>Node path</summary>
        public string NodePath { get; set; }
    }

    /// <summary>
    /// Result of action report
    /// </summary>
    public class ActionReportResult
    {
        /// <summary>Users matching the criteria</summary>
        public List<ActionReportUser> Users { get; set; } = new List<ActionReportUser>();
        /// <summary>Action applied</summary>
        public string ActionApplied { get; set; }
        /// <summary>Action status</summary>
        public string ActionStatus { get; set; }
        /// <summary>Number of users affected</summary>
        public int AffectedCount { get; set; }
        /// <summary>Error message if any</summary>
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Internal command for audit report
    /// </summary>
    [DataContract]
    internal class ActionAuditReportCommand : Commands.AuthenticatedCommand
    {
        public ActionAuditReportCommand() : base("get_audit_event_reports") { }

        [DataMember(Name = "report_type", EmitDefaultValue = false)]
        public string ReportType { get; set; }

        [DataMember(Name = "scope", EmitDefaultValue = false)]
        public string Scope { get; set; }

        [DataMember(Name = "filter", EmitDefaultValue = false)]
        public ActionAuditFilter Filter { get; set; }

        [DataMember(Name = "columns", EmitDefaultValue = false)]
        public List<string> Columns { get; set; }

        [DataMember(Name = "aggregate", EmitDefaultValue = false)]
        public List<string> Aggregate { get; set; }

        [DataMember(Name = "limit", EmitDefaultValue = false)]
        public int? Limit { get; set; }
    }

    [DataContract]
    internal class ActionAuditFilter
    {
        [DataMember(Name = "audit_event_type", EmitDefaultValue = false)]
        public List<string> AuditEventType { get; set; }

        [DataMember(Name = "created", EmitDefaultValue = false)]
        public ActionAuditCreatedFilter Created { get; set; }
    }

    [DataContract]
    internal class ActionAuditCreatedFilter
    {
        [DataMember(Name = "min", EmitDefaultValue = false)]
        public long? Min { get; set; }

        [DataMember(Name = "max", EmitDefaultValue = false)]
        public long? Max { get; set; }
    }

    [DataContract]
    internal class ActionAuditReportResponse : Commands.KeeperApiResponse
    {
        [DataMember(Name = "audit_event_overview_report_rows", EmitDefaultValue = false)]
        public List<Dictionary<string, object>> Rows { get; set; }
    }

    /// <summary>
    /// Action Report functionality
    /// </summary>
    public static class ActionReportExtensions
    {
        private const int ApiEventSummaryRowLimit = 2000;

        /// <summary>
        /// Gets the allowed actions for a given target status
        /// </summary>
        public static HashSet<ActionReportAdminAction> GetAllowedActions(ActionReportTargetStatus status)
        {
            var defaultAllowed = new HashSet<ActionReportAdminAction> { ActionReportAdminAction.None };
            
            switch (status)
            {
                case ActionReportTargetStatus.NoLogon:
                    return new HashSet<ActionReportAdminAction>(defaultAllowed) { ActionReportAdminAction.Lock };
                case ActionReportTargetStatus.NoUpdate:
                    return defaultAllowed;
                case ActionReportTargetStatus.Locked:
                    return new HashSet<ActionReportAdminAction>(defaultAllowed) { ActionReportAdminAction.Delete, ActionReportAdminAction.Transfer };
                case ActionReportTargetStatus.Invited:
                    return new HashSet<ActionReportAdminAction>(defaultAllowed) { ActionReportAdminAction.Delete };
                case ActionReportTargetStatus.NoRecovery:
                    return defaultAllowed;
                default:
                    return defaultAllowed;
            }
        }

        /// <summary>
        /// Runs the action report and returns users matching the criteria
        /// </summary>
        public static async Task<ActionReportResult> RunActionReport(
            this EnterpriseData enterpriseData,
            IAuthentication auth,
            ActionReportOptions options,
            Action<string> logger = null)
        {
            var result = new ActionReportResult();
            
            var daysSince = options.DaysSince ?? (options.TargetStatus == ActionReportTargetStatus.Locked ? 90 : 30);
            
            var activeUsers = enterpriseData.Users.Where(u => u.UserStatus == UserStatus.Active).ToList();
            var lockedUsers = enterpriseData.Users.Where(u => u.UserStatus == UserStatus.Locked).ToList();
            var invitedUsers = enterpriseData.Users.Where(u => u.UserStatus == UserStatus.Inactive).ToList();

            HashSet<long> targetNodeIds = null;
            if (!string.IsNullOrEmpty(options.Node))
            {
                targetNodeIds = GetDescendantNodeIds(enterpriseData, options.Node, logger);
                if (targetNodeIds == null)
                {
                    result.ErrorMessage = $"Node '{options.Node}' not found";
                    return result;
                }

                activeUsers = activeUsers.Where(u => targetNodeIds.Contains(u.ParentNodeId)).ToList();
                lockedUsers = lockedUsers.Where(u => targetNodeIds.Contains(u.ParentNodeId)).ToList();
                invitedUsers = invitedUsers.Where(u => targetNodeIds.Contains(u.ParentNodeId)).ToList();
            }

            List<EnterpriseUser> candidateUsers;
            List<string> eventTypes;
            string usernameField = "username";

            switch (options.TargetStatus)
            {
                case ActionReportTargetStatus.NoLogon:
                    candidateUsers = activeUsers;
                    eventTypes = new List<string> { "login", "login_console", "chat_login", "accept_invitation" };
                    break;
                case ActionReportTargetStatus.NoUpdate:
                    candidateUsers = activeUsers;
                    eventTypes = new List<string> { "record_add", "record_update" };
                    break;
                case ActionReportTargetStatus.Locked:
                    candidateUsers = lockedUsers;
                    eventTypes = new List<string> { "lock_user" };
                    usernameField = "to_username";
                    break;
                case ActionReportTargetStatus.Invited:
                    candidateUsers = invitedUsers;
                    eventTypes = new List<string> { "send_invitation", "auto_invite_user" };
                    usernameField = "email";
                    break;
                case ActionReportTargetStatus.NoRecovery:
                    candidateUsers = activeUsers;
                    eventTypes = new List<string> { "change_security_question", "account_recovery_setup" };
                    break;
                default:
                    candidateUsers = new List<EnterpriseUser>();
                    eventTypes = new List<string>();
                    break;
            }

            if (candidateUsers.Count == 0)
            {
                logger?.Invoke("No candidate users found for the specified criteria");
                return result;
            }

            var noActionUsers = await GetNoActionUsers(
                auth, 
                candidateUsers, 
                daysSince, 
                eventTypes, 
                usernameField, 
                logger);

            foreach (var user in noActionUsers)
            {
                var nodePath = "";
                if (enterpriseData.TryGetNode(user.ParentNodeId, out var node))
                {
                    nodePath = string.Join(" \\ ", GetNodePath(enterpriseData, node).Reverse());
                }

                var transferStatus = GetTransferStatus(user);

                result.Users.Add(new ActionReportUser
                {
                    UserId = user.Id,
                    Username = user.Email,
                    DisplayName = user.DisplayName,
                    Status = user.UserStatus,
                    TransferStatus = transferStatus,
                    NodeId = user.ParentNodeId,
                    NodePath = nodePath
                });
            }

            logger?.Invoke($"Found {result.Users.Count} user(s) matching criteria");

            if (options.ApplyAction != ActionReportAdminAction.None && result.Users.Count > 0)
            {
                var allowedActions = GetAllowedActions(options.TargetStatus);
                if (!allowedActions.Contains(options.ApplyAction))
                {
                    result.ErrorMessage = $"Action '{options.ApplyAction}' is not allowed for status '{options.TargetStatus}'. Allowed: {string.Join(", ", allowedActions)}";
                    result.ActionStatus = "invalid";
                    return result;
                }

                result.ActionApplied = options.ApplyAction.ToString();
                
                if (options.DryRun)
                {
                    result.ActionStatus = "dry_run";
                    result.AffectedCount = result.Users.Count;
                    logger?.Invoke($"Dry run: Would {options.ApplyAction.ToString().ToLower()} {result.Users.Count} user(s)");
                }
                else
                {
                    result.ActionStatus = "not_implemented";
                    logger?.Invoke($"Action '{options.ApplyAction}' execution requires enterprise admin API - not yet implemented in SDK");
                }
            }
            else
            {
                result.ActionApplied = "none";
                result.ActionStatus = "n/a";
            }

            return result;
        }

        private static string GetTransferStatus(EnterpriseUser user)
        {
            switch (user.TransferAcceptanceStatus)
            {
                case TransferAcceptanceStatus.NotRequired: return "Not required";
                case TransferAcceptanceStatus.NotAccepted: return "Pending transfer";
                case TransferAcceptanceStatus.PartiallyAccepted: return "Partially accepted";
                case TransferAcceptanceStatus.Accepted: return "Transfer accepted";
                default: return "";
            }
        }

        private static HashSet<long> GetDescendantNodeIds(EnterpriseData enterpriseData, string nodeNameOrId, Action<string> logger)
        {
            EnterpriseNode targetNode = null;

            if (long.TryParse(nodeNameOrId, out var nodeId))
            {
                enterpriseData.TryGetNode(nodeId, out targetNode);
            }

            if (targetNode == null)
            {
                targetNode = enterpriseData.Nodes.FirstOrDefault(n => 
                    string.Equals(n.DisplayName, nodeNameOrId, StringComparison.OrdinalIgnoreCase));
            }

            if (targetNode == null)
            {
                logger?.Invoke($"Node '{nodeNameOrId}' not found");
                return null;
            }

            var descendants = new HashSet<long> { targetNode.Id };
            var queue = new Queue<long>();
            queue.Enqueue(targetNode.Id);

            while (queue.Count > 0)
            {
                var currentId = queue.Dequeue();
                foreach (var node in enterpriseData.Nodes.Where(n => n.ParentNodeId == currentId))
                {
                    if (descendants.Add(node.Id))
                    {
                        queue.Enqueue(node.Id);
                    }
                }
            }

            return descendants;
        }

        private static async Task<List<EnterpriseUser>> GetNoActionUsers(
            IAuthentication auth,
            List<EnterpriseUser> candidateUsers,
            int daysSince,
            List<string> eventTypes,
            string usernameField,
            Action<string> logger)
        {
            var nowDt = DateTime.UtcNow;
            var minDt = nowDt.AddDays(-daysSince);
            var start = new DateTimeOffset(minDt).ToUnixTimeSeconds();
            var end = new DateTimeOffset(nowDt).ToUnixTimeSeconds();

            var candidateEmails = new HashSet<string>(
                candidateUsers.Select(u => u.Email.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var excluded = await GetExcludedUsers(
                auth, 
                candidateEmails, 
                eventTypes, 
                start, 
                end, 
                usernameField, 
                logger);

            return candidateUsers.Where(u => !excluded.Contains(u.Email.ToLowerInvariant())).ToList();
        }

        private static async Task<HashSet<string>> GetExcludedUsers(
            IAuthentication auth,
            HashSet<string> candidateUsernames,
            List<string> eventTypes,
            long startTime,
            long endTime,
            string usernameField,
            Action<string> logger)
        {
            var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            if (candidateUsernames.Count == 0)
            {
                return excluded;
            }

            var done = false;
            var currentEndTime = endTime;

            while (!done)
            {
                done = true;

                var command = new ActionAuditReportCommand
                {
                    ReportType = "span",
                    Scope = "enterprise",
                    Columns = new List<string> { usernameField },
                    Aggregate = new List<string> { "last_created" },
                    Limit = ApiEventSummaryRowLimit,
                    Filter = new ActionAuditFilter
                    {
                        AuditEventType = eventTypes,
                        Created = new ActionAuditCreatedFilter
                        {
                            Min = startTime,
                            Max = currentEndTime
                        }
                    }
                };

                try
                {
                    var response = await auth.ExecuteAuthCommand<ActionAuditReportCommand, ActionAuditReportResponse>(command);
                    var events = response?.Rows ?? new List<Dictionary<string, object>>();

                    foreach (var evt in events)
                    {
                        if (evt.TryGetValue(usernameField, out var usernameObj) && usernameObj != null)
                        {
                            var username = usernameObj.ToString().ToLowerInvariant();
                            if (candidateUsernames.Contains(username))
                            {
                                excluded.Add(username);
                            }
                        }
                    }

                    if (events.Count >= ApiEventSummaryRowLimit && excluded.Count < candidateUsernames.Count)
                    {
                        var lastEvent = events.LastOrDefault();
                        if (lastEvent != null && lastEvent.TryGetValue("last_created", out var lastCreatedObj))
                        {
                            var lastCreated = Convert.ToInt64(lastCreatedObj);
                            if (lastCreated > startTime)
                            {
                                currentEndTime = lastCreated + 1;
                                done = false;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger?.Invoke($"Error querying audit events: {ex.Message}");
                    break;
                }
            }

            return excluded;
        }

        /// <summary>
        /// Gets the node path for display
        /// </summary>
        public static IEnumerable<string> GetNodePath(EnterpriseData enterpriseData, EnterpriseNode node)
        {
            while (node != null)
            {
                yield return node.DisplayName;
                if (node.ParentNodeId <= 0) break;
                if (!enterpriseData.TryGetNode(node.ParentNodeId, out var parent)) break;
                node = parent;
            }
        }
    }
}
