﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
            return scope switch
            {
                RecordTypeScope.Standard => "standard",
                RecordTypeScope.Enterprise => "enterprise",
                RecordTypeScope.User => "user",
                _ => "",
            };
        }

        /// <summary>
        /// Returns record type information.
        /// </summary>
        /// <param name="record">Keeper Record</param>
        /// <returns></returns>
        public static string KeeperRecordType(this KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord => "",
                TypedRecord tr => tr.TypeName ?? "",
                FileRecord => "file",
                ApplicationRecord ar => ar.Type,
                _ => "",
            };
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
                case FileRecord { FileSize: 0 }:
                    return "";
                case FileRecord { FileSize: < 2000 } fr:
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
            var name = field.FieldName ?? "";
            if (string.Equals(name, "text"))
            {
                name = "";
            }
            if (string.IsNullOrEmpty(field.FieldLabel))
            {
                return "$" + (string.IsNullOrEmpty(name) ? "text" : name);
            }
            if (!string.IsNullOrEmpty(name))
            {
                name = "$" + name + ":";
            }
            return name + field.FieldLabel;
        }

        /// <summary>
        /// Returns typed field values converted to string
        /// </summary>
        /// <param name="field">Record Field</param>
        /// <returns>Field values.</returns>
        public static IEnumerable<string> GetTypedFieldValues(this ITypedField field)
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
                else if (value is bool b)
                {
                    if (b)
                    {
                        yield return "true";
                    }
                }
                else if (value is IFieldTypeSerialize fts)
                {
                    yield return fts.GetValueAsString();
                }
                else
                {
                    string text;
                    try
                    {
                        text = Encoding.UTF8.GetString(JsonUtils.DumpJson(value, indent: true));
                    }
                    catch
                    {
                        text = "<not supported>";
                    }
                    yield return text;
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
                                var dt = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(dv);
                                yield return dt.ToString("d");
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

            var allFields = new Dictionary<string, ITypedField>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var rf in typed.Fields.Concat(typed.Custom))
            {
                for (var i = rf.Count - 1; i >= 0; i--)
                {
                    var value = rf.GetValueAt(i);
                    if (value == null)
                    {
                        rf.DeleteValueAt(i);
                    }
                }
                var fieldKey = rf.GetTypedFieldName();
                if (!allFields.ContainsKey(fieldKey))
                {
                    allFields.Add(fieldKey, rf);
                }
            }

            typed.Fields.Clear();
            foreach (var field in recordType.Fields)
            {
                var fieldKey = field.GetTypedFieldName();
                if (allFields.TryGetValue(fieldKey, out var rf))
                {
                    allFields.Remove(fieldKey);
                }
                else
                {
                    rf = field.CreateTypedField();
                }
                rf.Required = field.Required;
                typed.Fields.Add(rf);
            }

            var customFields = new List<ITypedField>(typed.Custom);
            typed.Custom.Clear();
            foreach (var rf in customFields)
            {
                if (rf.Count > 0)
                {
                    var fieldKey = rf.GetTypedFieldName();
                    if (allFields.ContainsKey(fieldKey))
                    {
                        typed.Custom.Add(rf);
                        allFields.Remove(fieldKey);
                    }
                }
            }
            if (allFields.Count > 0)
            {
                typed.Custom.AddRange(allFields.Values.Where(x => x.Count > 0));
            }
            typed.Custom.RemoveAll(rf => rf.Count == 0);
            foreach (var rf in typed.Custom)
            {
                rf.Required = false;
            }
        }
    }
}
