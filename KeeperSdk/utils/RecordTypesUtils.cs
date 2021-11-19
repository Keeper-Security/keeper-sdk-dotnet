using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Utils
{
    /// <summary>
    /// Provides extension methods for Vault Record Types
    /// </summary>
    public static class RecordTypesUtils
    {
        /// <exclude />
        public static string ToText(this RecordTypeScope scope)
        {
            switch (scope)
            {
                case RecordTypeScope.Standard:
                    return "standard";
                case RecordTypeScope.Enterprise:
                    return "enterprise";
                case RecordTypeScope.User:
                    return "user";
                default:
                    return "";
            }
        }

        /// <summary>
        /// Returns record type information.
        /// </summary>
        /// <param name="record">Keeper Record</param>
        /// <returns></returns>
        public static string KeeperRecordType(this KeeperRecord record)
        {
            if (record is PasswordRecord)
            {
                return "";
            }

            if (record is TypedRecord tr)
            {
                return tr.TypeName ?? "";
            }

            if (record is FileRecord)
            {
                return "file";
            }

            return "";
        }

        /// <summary>
        /// Returns common record information.
        /// Does not include sensitive data
        /// </summary>
        /// <param name="record">Keeper Record</param>
        /// <returns>General record information</returns>
        public static string KeeperRecordPublicInformation(this KeeperRecord record)
        {
            switch (record)
            {
                case PasswordRecord pr:
                    return string.Join(" (at) ", new[] { pr.Login, pr.Link }.Where(x => !string.IsNullOrEmpty(x)));
                case TypedRecord tr:
                {
                    var loginField = tr.Fields.FirstOrDefault(x => x.FieldName == "login");
                    if (loginField != null)
                    {
                        var login = loginField.GetTypedFieldInformation().FirstOrDefault();
                        string host = null;
                        var urlField = tr.Fields.FirstOrDefault(x => x.FieldName == "url");
                        if (urlField != null)
                        {
                            host = urlField.GetTypedFieldInformation().FirstOrDefault();
                        }
                        else
                        {
                            var hostField = tr.Fields.FirstOrDefault(x => x.FieldName == "host");
                            if (hostField != null)
                            {
                                host = hostField.GetTypedFieldInformation().FirstOrDefault();
                            }
                        }

                        return string.Join(" (at) ", new[] { login, host }.Where(x => !string.IsNullOrEmpty(x)));
                    }

                    var nameField = tr.Fields.FirstOrDefault(x => x.FieldName == "name");
                    if (nameField != null)
                    {
                        return nameField.GetTypedFieldInformation().FirstOrDefault() ?? "";
                    }

                    var cardField = tr.Fields.FirstOrDefault(x => x.FieldName == "paymentCard");
                    if (cardField != null)
                    {
                        return cardField.GetTypedFieldInformation().FirstOrDefault() ?? "";
                    }

                    var keyPairField = tr.Fields.FirstOrDefault(x => x.FieldName == "keyPair");
                    if (keyPairField != null)
                    {
                        return keyPairField.GetTypedFieldInformation().FirstOrDefault() ?? "";
                    }

                    return "";
                }
                case FileRecord fr when fr.FileSize == 0:
                    return "";
                case FileRecord fr when fr.FileSize < 2000:
                    return $"{fr.FileSize} bytes";
                case FileRecord fr:
                {
                    var sz = fr.FileSize / 1024.0;
                    if (sz < 1000)
                    {
                        return $"{sz:F1} KB";
                    }

                    sz /= 1024.0;
                    if (sz < 1000)
                    {
                        return $"{sz:F1} MB";
                    }

                    sz /= 1024.0;
                    return $"{sz:F1} gB";
                }
                default:
                    return "";
            }
        }

        /// <summary>
        /// Encodes record field name
        /// </summary>
        /// <param name="field">Field definition</param>
        /// <returns>Record field full name.</returns>
        public static string GetTypedFieldName(this IRecordTypeField field)
        {
            return $"{field.FieldLabel ?? ""} ({(string.IsNullOrEmpty(field.FieldName) ? "text" : field.FieldName)})".Trim();
        }

        /// <summary>
        /// Returns typed field values converted to string
        /// </summary>
        /// <param name="field">Record Field</param>
        /// <returns>Field values.</returns>
        public static IEnumerable<string> GetTypedFieldValues(this ITypedField field)
        {
            if (!RecordTypesConstants.TryGetRecordField(field.FieldName, out _))
            {
                yield return "<not supported>";
            }
            else
            {
                for (var i = 0; i < field.Count; i++)
                {
                    var value = field.GetValueAt(i);
                    if (value == null) continue;

                    if (value is string str)
                    {
                        if (!string.IsNullOrEmpty(str))
                        {
                            yield return str;
                        }
                    }
                    else if (value is long l)
                    {
                        if (l != 0)
                        {
                            var dt = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(l);
                            yield return dt.ToString("d");
                        }
                    }
                    else if (value is IFieldTypeSerialize fts)
                    {
                        var fields = fts.ElementValues.ToArray();
                        if (fields.Any(x => !string.IsNullOrEmpty(x)))
                        {
                            yield return string.Join(" | ", fields.Select(x => x ?? ""));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Returns general typed field values masking sensitive information.
        /// </summary>
        /// <param name="field">Record Field</param>
        /// <returns>Field common values</returns>
        public static IEnumerable<string> GetTypedFieldInformation(this ITypedField field)
        {
            if (field.FieldName == "password" || field.FieldName == "secret" ||
                field.FieldName == "pinCode")
            {
                if (field.Count > 0)
                {
                    yield return "***";
                }
            }
            else
            {
                if (!RecordTypesConstants.TryGetRecordField(field.FieldName, out var recordField))
                {
                    yield return "<unsupported>";
                }

                else if (recordField.Type.Name == "secret" || recordField.Type.Name == "password")
                {
                    if (field.Count > 0)
                    {
                        yield return "***";
                    }
                }
                else
                {
                    for (var i = 0; i < field.Count; i++)
                    {
                        var value = field.GetValueAt(i);
                        if (value == null) continue;
                        if (value is long dv)
                        {
                            if (dv == 0) continue;
                            if (recordField.Type.Name == "date")
                            {
                                if (dv != 0)
                                {
                                    var dt = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(dv);
                                    yield return dt.ToString("d");
                                }
                            }
                            else
                            {
                                yield return dv.ToString();
                            }
                        }
                        else if (value is string sv)
                        {
                            yield return sv;
                        }
                        else
                        {
                            switch (value)
                            {
                                case FieldTypeHost fth:
                                    if (!string.IsNullOrEmpty(fth.HostName))
                                    {
                                        yield return string.IsNullOrEmpty(fth.Port)
                                            ? fth.HostName
                                            : $"{fth.HostName}:{fth.Port}";
                                    }

                                    break;
                                case FieldTypePhone ftph:
                                    if (!string.IsNullOrEmpty(ftph.Number))
                                    {
                                        var text = ftph.Number;
                                        if (!string.IsNullOrEmpty(ftph.Region))
                                        {
                                            text = $"({ftph.Region})" + text;
                                        }

                                        if (!string.IsNullOrEmpty(ftph.Type))
                                        {
                                            text = $"[{ftph.Type}] " + ftph.Number;
                                        }

                                        if (!string.IsNullOrEmpty(ftph.Ext))
                                        {
                                            text += $" - {ftph.Ext}";
                                        }

                                        yield return text;
                                    }

                                    break;
                                case FieldTypeName ftn:
                                    yield return string.Join(" ",
                                        new[] { ftn.First, ftn.Middle, ftn.Last }.Where(x => !string.IsNullOrEmpty(x)));
                                    break;
                                case FieldTypeAddress fts:
                                    var address = $"{fts.Street1 ?? ""} {fts.Street2 ?? ""}".Trim();
                                    if (!string.IsNullOrEmpty(fts.City))
                                    {
                                        if (!string.IsNullOrEmpty(address))
                                        {
                                            address += ", ";
                                        }

                                        address += fts.City;
                                    }

                                    address += $" {fts.State ?? ""} {fts.Zip ?? ""} {fts.Country ?? ""}".Trim();
                                    if (!string.IsNullOrEmpty(address))
                                    {
                                        yield return address;
                                    }

                                    break;
                                case FieldTypeSecurityQuestion ftsq:
                                    if (!string.IsNullOrEmpty(ftsq.Question))
                                    {
                                        yield return ftsq.Question;
                                    }

                                    break;

                                case FieldTypeBankAccount ftba:
                                    var account = ftba.AccountNumber ?? "";
                                    if (!string.IsNullOrEmpty(ftba.RoutingNumber))
                                    {
                                        account = $"{ftba.RoutingNumber} / " + account;
                                    }

                                    if (!string.IsNullOrEmpty(account))
                                    {
                                        if (!string.IsNullOrEmpty(ftba.AccountType))
                                        {
                                            account += $"[ {ftba.AccountType}]";
                                        }

                                        yield return account;
                                    }

                                    break;

                                case FieldTypePaymentCard ftpc:
                                    if (!string.IsNullOrEmpty(ftpc.CardNumber))
                                    {
                                        if (ftpc.CardNumber.Length > 4)
                                        {
                                            yield return
                                                $"x{ftpc.CardNumber.Substring(ftpc.CardNumber.Length - 4)}";
                                        }
                                        else
                                        {
                                            yield return "***";
                                        }
                                    }

                                    break;
                                case FieldTypeKeyPair ftpk:
                                    if (!string.IsNullOrEmpty(ftpk.PrivateKey) && !string.IsNullOrEmpty(ftpk.PublicKey))
                                    {
                                        yield return "<Private Key> <Public Key>";
                                    }
                                    else if (string.IsNullOrEmpty(ftpk.PrivateKey))
                                    {
                                        yield return "<Private Key>";
                                    }
                                    else if (string.IsNullOrEmpty(ftpk.PublicKey))
                                    {
                                        yield return "<Public Key>";
                                    }

                                    break;
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Verifies Typed record.
        /// </summary>
        /// <param name="vault">Vault</param>
        /// <param name="typed">Typed Record</param>
        public static void AdjustTypedRecord(this VaultData vault, TypedRecord typed)
        {
            if (!vault.TryGetRecordTypeByName(typed.TypeName, out var recordType)) return;

            var fields = new Dictionary<string, int>(StringComparer.InvariantCultureIgnoreCase);
            for (var i = 0; i < typed.Fields.Count; i++)
            {
                var rf = typed.Fields[i];
                fields[rf.GetTypedFieldName()] = i;
            }

            foreach (var field in recordType.Fields)
            {
                if (!fields.ContainsKey(field.GetTypedFieldName()))
                {
                    typed.Fields.Add(field.CreateTypedField());
                }
            }

            fields.Clear();
            for (var i = 0; i < recordType.Fields.Length; i++)
            {
                var rf = recordType.Fields[i];
                fields[rf.GetTypedFieldName()] = i;
            }

            typed.Fields.Sort((f1, f2) =>
            {
                var name1 = f1.GetTypedFieldName();
                var name2 = f2.GetTypedFieldName();
                if (fields.ContainsKey(name1) && fields.ContainsKey(name2))
                {
                    return fields[name1] - fields[name2];
                }

                if (fields.ContainsKey(name1))
                {
                    return -1;
                }

                if (fields.ContainsKey(name2))
                {
                    return 1;
                }

                return 0;
            });
            foreach (var field in typed.Fields.Concat(typed.Custom))
            {
                for (var i = field.Count - 1; i >= 0; i--)
                {
                    var value = field.GetValueAt(i);
                    if (value == null)
                    {
                        field.DeleteValueAt(0);
                    }
                }
            }
        }
    }
}
