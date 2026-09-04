using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Enterprise
{
    /// <summary>Options for pushing record templates to enterprise users.</summary>
    public class EnterprisePushOptions
    {
        public string[] Users { get; set; }
        public string[] Teams { get; set; }
        public bool DryRun { get; set; }
        public Action<string> Warnings { get; set; }
    }

    /// <summary>One planned or completed enterprise-push action.</summary>
    public class EnterprisePushAction
    {
        public string Action { get; internal set; }
        public string RecordTitle { get; internal set; }
        public string RecordUid { get; internal set; }
        public string Target { get; internal set; }
        public string TargetType { get; internal set; }
    }

    /// <summary>Result of an enterprise-push operation.</summary>
    public class EnterprisePushResult
    {
        public IReadOnlyList<EnterprisePushAction> Actions { get; internal set; } = Array.Empty<EnterprisePushAction>();
        public int RecordsCreated { get; internal set; }
        public int RecordsFailed { get; internal set; }
        public int TransfersCompleted { get; internal set; }
        public int TransfersFailed { get; internal set; }
    }

    public partial class EnterpriseData
    {
        private static readonly Regex TemplateParameter = new Regex(@"\$\{(?<name>\w+)\}", RegexOptions.Compiled);

        /// <summary>
        /// Creates a separate copy of each template record for every resolved target user,
        /// then transfers ownership of the copy to that user.
        /// </summary>
        public async Task<EnterprisePushResult> PushEnterpriseRecords(
            VaultOnline vault,
            ImportRecord[] templateRecords,
            EnterprisePushOptions options = null)
        {
            if (vault == null) throw new ArgumentNullException(nameof(vault));
            if (templateRecords == null) throw new ArgumentNullException(nameof(templateRecords));

            options ??= new EnterprisePushOptions();
            var result = new EnterprisePushResult();
            var actions = new List<EnterprisePushAction>();
            var targets = ResolveTargets(options, vault.Auth.Username, options.Warnings);

            if (templateRecords.Length == 0)
            {
                options.Warnings?.Invoke("Template file contains no records.");
                result.Actions = actions;
                return result;
            }

            if (targets.Count == 0)
            {
                options.Warnings?.Invoke("No target users found.");
                result.Actions = actions;
                return result;
            }

            if (!options.DryRun)
            {
                var targetEmails = targets.Select(x => x.Email).Where(x => !string.IsNullOrEmpty(x)).ToArray();
                try
                {
                    var skippedUsers = new HashSet<string>(
                        await vault.Auth.LoadUsersKeys(targetEmails),
                        StringComparer.InvariantCultureIgnoreCase);
                    targets = targets.Where(target =>
                    {
                        if (skippedUsers.Contains(target.Email)
                            || !vault.Auth.TryGetUserKeys(target.Email, out var keys)
                            || keys == null
                            || (vault.Auth.AuthContext.ForbidKeyType2
                                ? keys.EcPublicKey == null || keys.EcPublicKey.Length == 0
                                : keys.RsaPublicKey == null || keys.RsaPublicKey.Length == 0))
                        {
                            var requiredKey = vault.Auth.AuthContext.ForbidKeyType2 ? "ECC" : "RSA";
                            options.Warnings?.Invoke($"Skipping user \"{target.Email}\": {requiredKey} public key is unavailable.");
                            return false;
                        }

                        return true;
                    }).ToList();
                }
                catch (Exception ex)
                {
                    options.Warnings?.Invoke($"Unable to load target user public keys: {ex.Message}");
                    targets.Clear();
                }

                if (targets.Count == 0)
                {
                    options.Warnings?.Invoke("No target users with usable public keys found.");
                    result.Actions = actions;
                    return result;
                }
            }

            foreach (var target in targets)
            {
                var records = templateRecords
                    .Where(x => x != null)
                    .Select(x => PrepareTemplateRecord(x, target))
                    .ToArray();

                if (options.DryRun)
                {
                    foreach (var record in records)
                    {
                        actions.Add(new EnterprisePushAction
                        {
                            Action = "Transfer Record",
                            RecordTitle = record.Title,
                            Target = target.Email,
                            TargetType = "User"
                        });
                    }
                    continue;
                }

                try
                {
                    var importResult = await vault.ImportJson(new ImportFile { Records = records }, RecordMatch.None);
                    result.RecordsCreated += importResult.LegacyRecordCount + importResult.TypedRecordCount;
                    result.RecordsFailed += importResult.RecordFailure.Count;

                    if (importResult.LegacyRecordCount + importResult.TypedRecordCount == 0)
                    {
                        options.Warnings?.Invoke($"No records were created for user \"{target.Email}\".");
                        continue;
                    }

                    foreach (var record in records)
                    {
                        if (importResult.RecordFailure.ContainsKey(record.Uid)) continue;

                        try
                        {
                            if (!importResult.RecordKeys.TryGetValue(record.Uid, out var recordKey))
                            {
                                result.TransfersFailed++;
                                options.Warnings?.Invoke($"Record key for \"{record.Title}\" was not returned by the import operation.");
                                continue;
                            }

                            vault.Auth.TryGetUserKeys(target.Email, out var userKeys);
                            await vault.TransferRecordToUser(record.Uid, target.Email, recordKey, userKeys);
                            try
                            {
                                await vault.RemoveTransferredRecord(record.Uid);
                            }
                            catch (Exception cleanupException)
                            {
                                options.Warnings?.Invoke($"Transferred \"{record.Title}\" to \"{target.Email}\", but could not remove the administrator copy: {cleanupException.Message}");
                            }
                            result.TransfersCompleted++;
                            actions.Add(new EnterprisePushAction
                            {
                                Action = "Transfer Record",
                                RecordTitle = record.Title,
                                RecordUid = record.Uid,
                                Target = target.Email,
                                TargetType = "User"
                            });
                        }
                        catch (Exception ex)
                        {
                            result.TransfersFailed++;
                            options.Warnings?.Invoke($"Failed to transfer \"{record.Title}\" to \"{target.Email}\": {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.RecordsFailed += records.Length;
                    options.Warnings?.Invoke($"Failed to create records for \"{target.Email}\": {ex.Message}");
                }
            }

            result.Actions = actions;
            return result;
        }

        private List<EnterpriseUser> ResolveTargets(EnterprisePushOptions options, string currentUser, Action<string> warning)
        {
            var users = new Dictionary<long, EnterpriseUser>();

            foreach (var identifier in options.Users ?? Array.Empty<string>())
            {
                var value = NormalizeIdentifier(identifier);
                if (string.IsNullOrEmpty(value)) continue;

                EnterpriseUser user = null;
                if (!TryGetUserByEmail(value, out user) &&
                    (!long.TryParse(value, out var id) || !TryGetUserById(id, out user)))
                {
                    user = Users.FirstOrDefault(x => string.Equals(x.DisplayName, value, StringComparison.OrdinalIgnoreCase));
                    if (user == null)
                    {
                        warning?.Invoke($"User \"{value}\" not found.");
                        continue;
                    }
                }

                AddTargetUser(users, user);
            }

            foreach (var identifier in options.Teams ?? Array.Empty<string>())
            {
                var value = NormalizeIdentifier(identifier);
                if (string.IsNullOrEmpty(value)) continue;

                var team = Teams.FirstOrDefault(x =>
                    string.Equals(x.Uid, value, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(x.Name, value, StringComparison.OrdinalIgnoreCase));
                if (team == null)
                {
                    warning?.Invoke($"Team \"{value}\" not found.");
                    continue;
                }

                foreach (var userId in GetUsersForTeam(team.Uid))
                {
                    if (TryGetUserById(userId, out var user)) AddTargetUser(users, user);
                }
            }

            return users.Values
                .Where(x => !string.Equals(x.Email, currentUser, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        private static void AddTargetUser(IDictionary<long, EnterpriseUser> users, EnterpriseUser user)
        {
            if (user != null) users[user.Id] = user;
        }

        private static string NormalizeIdentifier(string value)
        {
            return value?.Trim().Replace("\\@", "@");
        }

        private static ImportRecord PrepareTemplateRecord(ImportRecord source, EnterpriseUser target)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["user_email"] = target.Email ?? string.Empty,
                ["user_name"] = target.DisplayName ?? string.Empty,
                ["generate_password"] = CryptoUtils.GeneratePassword(new PasswordGenerationOptions { Length = 32 })
            };

            return new ImportRecord
            {
                Uid = CryptoUtils.GenerateUid(),
                Title = Substitute(source.Title, values),
                RecordType = source.RecordType,
                Login = Substitute(source.Login, values),
                Password = Substitute(source.Password, values),
                LoginUrl = Substitute(source.LoginUrl, values),
                Notes = Substitute(source.Notes, values),
                Folders = null,
                CustomFields = source.CustomFields?.Select(field => new ImportCustomField
                {
                    Name = field?.Name,
                    TextValue = Substitute(field?.TextValue, values),
                    Elements = field?.Elements?.Select(element => new ImportCustomFieldElement
                    {
                        Name = element?.Name,
                        Value = Substitute(element?.Value, values)
                    }).ToArray()
                }).ToArray()
            };
        }

        private static string Substitute(string value, IReadOnlyDictionary<string, string> parameters)
        {
            if (value == null) return null;
            return TemplateParameter.Replace(value, match =>
                parameters.TryGetValue(match.Groups["name"].Value, out var replacement)
                    ? replacement
                    : match.Value);
        }
    }
}
