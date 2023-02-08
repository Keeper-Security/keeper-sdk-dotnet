using System;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Vault
{
    /// <exclude/>
    public static class VaultDataExtensions
    {
        public static FolderNode GetFolder(this IVaultData vaultData, string folderUid)
        {
            if (string.IsNullOrEmpty(folderUid))
            {
                return vaultData.RootFolder;
            }

            if (vaultData.TryGetFolder(folderUid, out var folder))
            {
                return folder;
            }

            throw new VaultException($"Folder UID \"{folderUid}\" not found.");
        }

        public static SharedFolder GetSharedFolder(this IVaultData vaultData, string sharedFolderUid)
        {
            if (string.IsNullOrEmpty(sharedFolderUid))
            {
                throw new VaultException("Shared Folder UID cannot be empty.");
            }

            if (vaultData.TryGetSharedFolder(sharedFolderUid, out var folder))
            {
                return folder;
            }

            throw new VaultException($"Shared Folder UID \"{sharedFolderUid}\" not found.");
        }

        public static KeeperRecord GetRecord(this IVaultData vaultData, string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                throw new VaultException("Record UID cannot be empty.");
            }

            if (vaultData.TryGetKeeperRecord(recordUid, out var record))
            {
                return record;
            }

            throw new VaultException($"Record UID \"{recordUid}\" not found.");
        }

        public static ITypedField CreateTypedField(string fieldName, string fieldLabel = null)
        {
            if (!RecordTypesConstants.TryGetRecordField(fieldName, out var rf))
            {
                throw new Exception($"Field \"{fieldName}\" not found.");
            }

            if (!RecordTypesConstants.GetTypedFieldType(rf.Type.Type, out var tft))
            {
                throw new Exception($"Field type \"{rf.Type.Type.Name}\" is not registered.");
            }

            return (ITypedField) Activator.CreateInstance(tft, fieldName, fieldLabel);
        }

        public static ITypedField CreateTypedField(this IRecordTypeField fieldInfo)
        {
            var tf = CreateTypedField(fieldInfo.FieldName, fieldInfo.FieldLabel);
            if (fieldInfo is RecordTypeField rtf) 
            { 
            }

            return tf;
        }

        public static bool FindTypedField(this IList<ITypedField> fields, IRecordTypeField fieldInfo, out ITypedField field)
        {
            field = fields.FirstOrDefault(x =>
            {
                if (!string.Equals(x.FieldName, fieldInfo.FieldName, StringComparison.InvariantCultureIgnoreCase))
                {
                    return false;
                }
                if (string.IsNullOrEmpty(x.FieldLabel) && string.IsNullOrEmpty(fieldInfo.FieldLabel))
                {
                    return true;
                }
                return string.Equals(x.FieldLabel, fieldInfo.FieldLabel, StringComparison.InvariantCultureIgnoreCase);
            });
            return field != null;
        }

        public static bool FindTypedField(this TypedRecord record, IRecordTypeField fieldInfo, out ITypedField field)
        {
            if (record.Fields.FindTypedField(fieldInfo, out field))
            {
                return true;
            }

            return record.Custom.FindTypedField(fieldInfo, out field);
        }
    }
}
