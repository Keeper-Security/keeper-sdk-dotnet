using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Shared helpers for post-rotation script samples.
    /// </summary>
    internal static class PamRotationScriptHelper
    {
        public static bool IsRotationScriptField(TypedField<FieldScript> field)
        {
            return field != null
                   && (string.Equals(field.FieldName, "script", StringComparison.Ordinal)
                       || string.Equals(field.FieldLabel, "rotationScripts", StringComparison.Ordinal));
        }

        public static TypedField<FieldScript> GetOrCreateScriptField(TypedRecord record)
        {
            var scriptField = record.Fields
                .OfType<TypedField<FieldScript>>()
                .FirstOrDefault(IsRotationScriptField);
            if (scriptField == null)
            {
                scriptField = new TypedField<FieldScript>("script", "rotationScripts");
                record.Fields.Add(scriptField);
            }

            return scriptField;
        }

        public static TypedField<FieldScript> GetScriptField(TypedRecord record)
        {
            return record.Fields
                .OfType<TypedField<FieldScript>>()
                .FirstOrDefault(IsRotationScriptField);
        }

        public static HashSet<string> GetFileRefUids(TypedField<string> fileRef)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (fileRef == null)
            {
                return result;
            }

            foreach (var uid in fileRef.Values)
            {
                if (!string.IsNullOrEmpty(uid))
                {
                    result.Add(uid);
                }
            }

            return result;
        }

        public static FieldScript FindScriptValue(
            VaultOnline vault,
            TypedRecord record,
            string scriptName,
            out TypedField<FieldScript> scriptField)
        {
            scriptField = GetScriptField(record);
            if (scriptField == null)
            {
                return null;
            }

            foreach (var scriptValue in scriptField.Values)
            {
                if (scriptValue != null && scriptValue.FileRef == scriptName)
                {
                    return scriptValue;
                }
            }

            foreach (var scriptValue in scriptField.Values)
            {
                if (string.IsNullOrEmpty(scriptValue?.FileRef))
                {
                    continue;
                }

                if (!vault.TryGetKeeperRecord(scriptValue.FileRef, out var keeperRecord))
                {
                    continue;
                }

                var fileRecord = keeperRecord as FileRecord;
                if (fileRecord == null)
                {
                    continue;
                }

                if (string.Equals(fileRecord.Uid, scriptName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(fileRecord.Title, scriptName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(fileRecord.Name, scriptName, StringComparison.OrdinalIgnoreCase))
                {
                    return scriptValue;
                }
            }

            return null;
        }

        public static string[] ResolveCredentialUids(VaultOnline vault, IEnumerable<string> credentials)
        {
            if (credentials == null)
            {
                return Array.Empty<string>();
            }

            var refs = new List<string>();
            foreach (var credential in credentials)
            {
                if (string.IsNullOrWhiteSpace(credential))
                {
                    continue;
                }

                var cred = credential.Trim();
                if (!vault.TryGetKeeperRecord(cred, out var record))
                {
                    throw new InvalidOperationException($"Credential record '{cred}' not found.");
                }

                refs.Add(record.Uid);
            }

            return refs.ToArray();
        }

        public static TypedRecord ResolveScriptRecord(VaultOnline vault, string recordId)
        {
            if (string.IsNullOrWhiteSpace(recordId))
            {
                return null;
            }

            return PamVaultHelpers.ResolveRecord(vault, recordId.Trim(), PamRecordTypes.Script);
        }

        public static bool MatchesPattern(KeeperRecord record, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return true;
            }

            if (string.Equals(record.Uid, pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return record.Title != null
                   && record.Title.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsOwnerScriptError(string code)
        {
            return string.Equals(code, "only_owner_can_modify_scripts", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(code, "RS_ONLY_OWNER_CAN_MODIFY_SCRIPTS", StringComparison.OrdinalIgnoreCase);
        }
    }
}
