using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    public static class CommanderExtensions
    {
        public static string BiometricCredentialTarget(this string username, byte[] token)
        {
            return $"Keeper.{username}.Bio.{token.TokenToString()}";
        }

        public static string TokenToString(this byte[] token)
        {
            var sb = new StringBuilder();
            foreach (var b in token)
            {
                sb.AppendFormat("{0:x2}", b);
                if (sb.Length >= 20)
                {
                    break;
                }
            }

            return sb.ToString();
        }

        public static string DeviceStatusToString(this DeviceStatus status)
        {
            switch (status)
            {
                case DeviceStatus.DeviceOk: return "OK";
                case DeviceStatus.DeviceNeedsApproval: return "Need Approval";
                case DeviceStatus.DeviceDisabledByUser: return "Disabled";
                case DeviceStatus.DeviceLockedByAdmin: return "Locked";
                default: return "";
            }
        }

        internal static PasswordGenerationOptions RestoreRules(string password)
        {
            var options = new PasswordGenerationOptions();
            if (!string.IsNullOrEmpty(password))
            {
                options.Length = password.Length;
                options.Upper = -1;
                options.Lower = -1;
                options.Digit = -1;
                options.Special = -1;
                foreach (var ch in password)
                {
                    if (char.IsDigit(ch))
                    {
                        options.Digit = (options.Digit >= 0 ? options.Digit : 0) + 1;
                    }
                    else if (char.IsLetter(ch))
                    {
                        if (char.IsLower(ch))
                        {
                            options.Lower = (options.Lower >= 0 ? options.Lower : 0) + 1;
                        }
                        else
                        {
                            options.Upper = (options.Upper >= 0 ? options.Upper : 0) + 1;
                        }
                    }
                    else
                    {
                        options.Special = (options.Special >= 0 ? options.Special : 0) + 1;
                    }
                }
            }
            else
            {
                options.Length = 20;
                options.Upper = 4;
                options.Lower = 4;
                options.Digit = 2;
                options.Special = -1;
            }
            return options;
        }

        public static bool RotateRecordPassword(this IVault vault, KeeperRecord record)
        {
            if (record == null)
            {
                return false;
            }
            PasswordGenerationOptions options = null;
            if (record is PasswordRecord password)
            {
                options = RestoreRules(password.Password);
                password.Password = CryptoUtils.GeneratePassword(options);
                return true;
            }
            if (record is TypedRecord typed)
            {
                ITypedField passwordField = null;
                if (!string.IsNullOrEmpty(typed.TypeName))
                {
                    if (vault.TryGetRecordTypeByName(typed.TypeName, out var recordType))
                    {
                        var passwordFieldType = recordType.Fields.FirstOrDefault(x => x.FieldName == "password");
                        if (passwordFieldType != null)
                        {
                            if (!typed.Fields.FindTypedField(passwordFieldType, out passwordField))
                            {
                                passwordField = new TypedField<string>(passwordFieldType.FieldName, passwordFieldType.FieldLabel);
                                typed.Fields.Add(passwordField);
                            }
                            if (passwordFieldType is RecordTypePasswordField rtpf)
                            {
                                options = rtpf.PasswordOptions;
                            }
                        }
                    }
                }
                if (passwordField == null)
                {
                    typed.FindTypedField(new RecordTypeField("password"), out passwordField);
                }
                if (passwordField != null)
                {
                    if (options == null)
                    {
                        if (passwordField.ObjectValue is string pwd)
                        {
                            options = RestoreRules(pwd);
                        }
                    }
                    passwordField.ObjectValue = CryptoUtils.GeneratePassword(options);
                    return true;
                }
            }

            return false;
        }
    }
}
