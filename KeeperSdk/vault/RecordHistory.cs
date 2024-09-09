using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault.Commands;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Storage;

namespace KeeperSecurity
{
    namespace Vault
    {
        public partial class VaultOnline
        {
            public async Task<RecordHistory[]> GetRecordHistory(string recordUid)
            {
                if (!TryGetKeeperRecord(recordUid, out var r))
                {
                    throw new Exception($"Record UID {recordUid} not found");
                }
                var rq = new GetRecordHistoryCommand
                {
                    RecordUid = recordUid,
                };
                var rs = await Auth.ExecuteAuthCommand<GetRecordHistoryCommand, GetRecordHistoryResponse>(rq);
                var history = new List<RecordHistory>();
                foreach (var rh in rs.History)
                {
                    try
                    {
                        history.Add(new RecordHistory
                        {
                            KeeperRecord = rh.Load(r.RecordKey),
                            Username = rh.Username,
                        });
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Parse record revision error: {e}");
                    }
                }
                for (var i = 1; i < history.Count; i++)
                {
                    var r1 = history[i].KeeperRecord;
                    var r2 = history[i - 1].KeeperRecord;
                    history[i].RecordChange = RecordHistoryUtils.GetRecordChanges(r1, r2);
                }

                history.Reverse();
                return history.ToArray();
            }

        }
        internal static class RecordHistoryUtils
        {
            internal static RecordChange GetRecordChanges(KeeperRecord r1, KeeperRecord r2)
            {
                RecordChange change = 0;
                if (!string.Equals(r1.ExtractType(), r2.ExtractType())) { 
                    change |= RecordChange.RecordType;
                }
                if (!string.Equals(r1.ExtractTitle(), r2.ExtractTitle()))
                {
                    change |= RecordChange.Title;
                }
                if (!string.Equals(r1.ExtractLogin(), r2.ExtractLogin()))
                {
                    change |= RecordChange.Login;
                }
                if (!string.Equals(r1.ExtractPassword(), r2.ExtractPassword()))
                {
                    change |= RecordChange.Password;
                }
                if (!string.Equals(r1.ExtractUrl(), r2.ExtractUrl()))
                {
                    change |= RecordChange.Url;
                }
                if (!string.Equals(r1.ExtractNotes(), r2.ExtractNotes()))
                {
                    change |= RecordChange.Notes;
                }
                if (!string.Equals(r1.ExtractTotp(), r2.ExtractTotp()))
                {
                    change |= RecordChange.Totp;
                }
                if (!string.Equals(r1.ExtractHost(), r2.ExtractHost()))
                {
                    change |= RecordChange.Hostname;
                }
                if (!string.Equals(r1.ExtractAddress(), r2.ExtractAddress()))
                {
                    change |= RecordChange.Address;
                }
                if (!string.Equals(r1.ExtractCard(), r2.ExtractCard()))
                {
                    change |= RecordChange.PaymentCard;
                }
                if (!string.Equals(r1.ExtractCustomFields(), r2.ExtractCustomFields()))
                {
                    change |= RecordChange.CustomField;
                }
                if (!string.Equals(r1.ExtractAttachments(), r2.ExtractAttachments()))
                {
                    change |= RecordChange.File;
                }

                return change;
            }

            private static string ExtractType(this KeeperRecord record)
            {
                return record switch
                {
                    null => null,
                    PasswordRecord => "legacy",
                    TypedRecord tr => tr.TypeName,
                    ApplicationRecord => "app",
                    _ => "",
                };
            }
            private static string ExtractTitle(this KeeperRecord record)
            {
                return record?.Title;
            }
            private static string ExtractLogin(this KeeperRecord record)
            {
                return record switch
                {
                    null => null,
                    PasswordRecord pr => pr.Login,
                    TypedRecord tr when tr.FindTypedField("login", null, out var rf) => rf.GetExternalValue(),
                    _ => "",
                };
            }
            private static string ExtractPassword(this KeeperRecord record)
            {
                return record switch
                {
                    null => null,
                    PasswordRecord pr => pr.Password,
                    TypedRecord tr when tr.FindTypedField("password", null, out var rf) => rf.GetExternalValue(),
                    _ => "",
                };
            }
            private static string ExtractUrl(this KeeperRecord record)
            {
                return record switch
                {
                    null => null,
                    PasswordRecord pr => pr.Link,
                    TypedRecord tr when tr.FindTypedField("url", null, out var rf) => rf.GetExternalValue(),
                    _ => "",
                };
            }

            private static string ExtractNotes(this KeeperRecord record)
            {
                switch (record)
                {
                    case null:
                        return null;
                    case PasswordRecord pr:
                        return pr.Notes;
                    case TypedRecord tr:
                    {
                        var notes = tr.Notes ?? "";
                        if (tr.FindTypedField("note", null, out var rf))
                        {
                            notes += rf.GetExternalValue();
                        }
                        return notes;
                    }
                    default:
                        return "";
                }
            }

            private static string ExtractTotp(this KeeperRecord record)
            {
                switch (record)
                {
                    case null:
                        return null;
                    case PasswordRecord pr:
                        return pr.Totp;
                    case TypedRecord tr when tr.FindTypedField("oneTimeCode", null, out var rf):
                    {
                        var totp = rf.GetExternalValue();
                        if (!string.IsNullOrEmpty(totp)) {
                            Debug.WriteLine(totp);
                        }
                        return totp;
                    }
                    default:
                        return "";
                }
            }

            private static string ExtractHost(this KeeperRecord record)
            {
                switch (record)
                {
                    case null:
                        return null;
                    case TypedRecord tr when tr.FindTypedField("host", null, out var rf):
                    {
                        var totp = rf.GetExternalValue();
                        if (!string.IsNullOrEmpty(totp))
                        {
                            Debug.WriteLine(totp);
                        }
                        return totp;
                    }
                    default:
                        return "";
                }
            }

            private static string ExtractAddress(this KeeperRecord record)
            {
                switch (record)
                {
                    case null:
                        return null;
                    case TypedRecord tr when tr.FindTypedField("address", null, out var rf):
                    {
                        var totp = rf.GetExternalValue();
                        if (!string.IsNullOrEmpty(totp))
                        {
                            Debug.WriteLine(totp);
                        }
                        return totp;
                    }
                    default:
                        return "";
                }
            }

            private static string ExtractCard(this KeeperRecord record)
            {
                switch (record)
                {
                    case null:
                        return null;
                    case TypedRecord tr when tr.FindTypedField("paymentCard", null, out var rf):
                    {
                        var totp = rf.GetExternalValue();
                        if (!string.IsNullOrEmpty(totp))
                        {
                            Debug.WriteLine(totp);
                        }
                        return totp;
                    }
                    default:
                        return "";
                }
            }

            private static string ExtractCustomFields(this KeeperRecord record)
            {
                if (record == null) return null;
                List<string> values = null;

                switch (record)
                {
                    case PasswordRecord pr:
                    {
                        if ((pr.Custom?.Count ?? 0) > 0)
                        {
                            values = new List<string>();
                            foreach (var cf in pr.Custom)
                            {
                                values.Add($"$text.{cf.Name}:{cf.Value}");
                            }
                        }

                        break;
                    }
                    case TypedRecord tr:
                    {
                        if ((tr.Custom?.Count ?? 0) > 0) {
                            values = new List<string>();
                            foreach (var cf in tr.Custom)
                            {
                                values.Add($"${cf.FieldName}.{cf.FieldLabel ?? string.Empty}:{cf.GetExternalValue()}");
                            }
                        }

                        break;
                    }
                }

                if (values == null || values.Count <= 0) return "";

                values.Sort();
                return string.Join("\n", values);
            }

            private static string ExtractAttachments(this KeeperRecord record)
            {
                if (record == null) return null;
                List<string> values = null;

                switch (record)
                {
                    case PasswordRecord pr:
                    {
                        if ((pr.Attachments?.Count ?? 0) > 0)
                        {
                            values = new List<string>();
                            foreach (var atta in pr.Attachments)
                            {
                                values.Add(atta.Id);
                            }
                        }

                        break;
                    }
                    case TypedRecord tr:
                    {
                        if (tr.FindTypedField("fileRef", null, out var rf))
                        {
                            values = new List<string>();
                            for (int i = 0; i < rf.Count; i++) 
                            {
                                var v = rf.GetValueAt(i);
                                if (v is string s) { 
                                    values.Add(s);
                                }
                            }
                        }

                        break;
                    }
                }

                if (values == null || values.Count <= 0) return "";
                values.Sort();
                return string.Join("\n", values);
            }
        }

        namespace Commands
        {
            [DataContract]
            internal class GetRecordHistoryCommand : AuthenticatedCommand
            {
                public GetRecordHistoryCommand() : base("get_record_history")
                {
                }

                [DataMember(Name = "record_uid")]
                public string RecordUid;

                [DataMember(Name = "client_time")]
                public long ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            [DataContract]
            public class RecordHistoryStorage : IStorageRecord
            {
                [DataMember(Name = "record_uid")]
                public string RecordUid { get; internal set; }
                [DataMember(Name = "user_name")]
                public string Username { get; internal set; }
                [DataMember(Name = "client_version")]
                public string ClientVersion;
                [DataMember(Name = "version")]
                public int Version { get; internal set; }
                [DataMember(Name = "revision")]
                public long Revision { get; internal set; }
                [DataMember(Name = "shared")]
                public bool Shared { get; set; }
                [DataMember(Name = "client_modified_time")]
                internal double _client_modified_time;
                public long ClientModifiedTime => (long) _client_modified_time;
                [DataMember(Name = "data")]
                public string Data { get; internal set; }
                [DataMember(Name = "extra")]
                public string Extra { get; internal set; }
                [DataMember(Name = "udata")]
                internal SyncDownRecordUData udata;
                public string Udata => udata != null ? Encoding.UTF8.GetString(JsonUtils.DumpJson(udata)) : null;

                public bool Owner { get; set; }
                string IUid.Uid => RecordUid;
            }

            [DataContract]
            internal class GetRecordHistoryResponse : KeeperApiResponse
            {
                [DataMember(Name = "history")]
                public RecordHistoryStorage[] History;
            }

        }
    }
}
