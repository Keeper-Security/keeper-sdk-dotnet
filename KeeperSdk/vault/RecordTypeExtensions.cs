using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Runtime.Serialization;
using KeeperSecurity.Utils;
using System.Text;
using Records;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline : IRecordTypeManagement
    {
        internal readonly string RECORD_TYPE_ADD_URL = "vault/record_type_add";
        internal readonly string RECORD_TYPE_DELETE_URL = "vault/record_type_delete";
        internal readonly string RECORD_TYPE_UPDATE_URL = "vault/record_type_update";
        public async Task<string> AddRecordType(string recordTypeData)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeData });
            recordTypeService.checkAdminAccess();

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));
            recordTypeService.validateRecordTypeData(recordTypeObj);

            Records.RecordType record = recordTypeService.CreateRecordTypeObject(recordTypeObj);

            var response = await Auth.ExecuteAuthRest(RECORD_TYPE_ADD_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
            return response.RecordTypeId.ToString();

        }

        public async Task<string> UpdateRecordTypeAsync(string recordTypeId, string recordTypeData)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeId, recordTypeData });
            recordTypeService.checkAdminAccess();

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));
            recordTypeService.validateRecordTypeData(recordTypeObj);

            Records.RecordType record = recordTypeService.CreateRecordTypeObject(recordTypeObj);

            if (!int.TryParse(recordTypeId, out int parsedRecordTypeId))
            {
                throw new ArgumentException($"Record type ID is supposed to be an integer but {recordTypeId} is provided");
            }
            record.RecordTypeId = parsedRecordTypeId;
            var response = await Auth.ExecuteAuthRest(RECORD_TYPE_UPDATE_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
            return response.RecordTypeId.ToString();

        }

        public async Task<string> DeleteRecordTypeAsync(string recordTypeId)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeId });
            recordTypeService.checkAdminAccess();

            Records.RecordType record = new();

            if (!int.TryParse(recordTypeId, out int parsedRecordTypeId))
            {
                throw new ArgumentException($"Record type ID is supposed to be an integer but {recordTypeId} is provided");
            }
            record.RecordTypeId = parsedRecordTypeId;
            record.Scope = Records.RecordTypeScope.RtEnterprise;
            var response = await Auth.ExecuteAuthRest(RECORD_TYPE_DELETE_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
            return response.RecordTypeId.ToString();

        }


        internal class RecordTypeService
        {
            private readonly IAuthContext auth;

            public RecordTypeService(IAuthContext auth)
            {
                this.auth = auth;
            }

            public Records.RecordType CreateRecordTypeObject(CustomRecordType customRecordObject = null, string scope = "enterprise")
            {
                var title = customRecordObject.Id;
                var fields = customRecordObject.Fields
                            .Select(f => new Dictionary<string, string> { ["$ref"] = f.Ref })
                            .ToList();
                var description = customRecordObject.Description ?? string.Empty;
                var categories = customRecordObject.Categories;
                string[] parsedCategroies = categories != null ? categories.ToArray() : new string[] { };

                var cleanedFields = validateRecordTypeData(scope, fields);

                var recordTypeData = new CustomRecordType
                {
                    Id = title,
                    Description = description,
                    Categories = parsedCategroies,
                    Fields = cleanedFields.Select(f => new RecordTypeField { Ref = f["$ref"] }).ToArray()
                };

                var recordTypeProto = new Records.RecordType
                {
                    Content = Encoding.UTF8.GetString(JsonUtils.DumpJson(recordTypeData)),
                    Scope = Records.RecordTypeScope.RtEnterprise,
                };
                return recordTypeProto;
            }

            private List<Dictionary<string, string>> validateRecordTypeData(string scope, List<Dictionary<string, string>> fields)
            {
                if (scope != "enterprise")
                    throw new ArgumentException("This command is restricted to record types with scope of enterprise");

                if (fields == null || fields.Count == 0)
                    throw new ArgumentException("At least one field must be specified.");

                var cleanedFields = new List<Dictionary<string, string>>();
                foreach (var field in fields)
                {
                    if (!field.TryGetValue("$ref", out var fieldName) || string.IsNullOrWhiteSpace(fieldName))
                        throw new ArgumentException("Each field must contain a '$ref' key.");

                    if (!(RecordTypesConstants.RecordFields.Any(f => f.Name == fieldName) || RecordTypesConstants.FieldTypes.Any(f => f.Name == fieldName)))
                        throw new ArgumentException($"Field '{fieldName}' is not a valid RecordField.");

                    cleanedFields.Add(new Dictionary<string, string> { { "$ref", fieldName } });
                }
                return cleanedFields;
            }

            public void validateRecordTypeData(CustomRecordType recordTypeObj)
            {
                if (recordTypeObj == null)
                    throw new ArgumentException("Invalid recordTypeData JSON");

                if (string.IsNullOrWhiteSpace(recordTypeObj.Id))
                    throw new ArgumentException("Record type must have a title or name");
            }

            public void validateParameterExistence(List<string> objects)
            {
                objects.ForEach(o =>
                {
                    if (string.IsNullOrWhiteSpace(o))
                    {
                        throw new ArgumentException($"{o} cannot be null or empty");
                    }
                });
            }

            public void checkAdminAccess()
            {
                var enterprise_admin_status = auth.IsEnterpriseAdmin;

                if (!enterprise_admin_status)
                {
                    throw new VaultException("Enterprise admin access is required for this command");
                }
            }
        }

        [DataContract]
        internal class RecordTypeField
        {
            [DataMember(Name = "$ref", EmitDefaultValue = false)]
            public string Ref { get; set; }

            [DataMember(Name = "label", EmitDefaultValue = false)]
            public string Label { get; set; }

            [DataMember(Name = "required", EmitDefaultValue = false)]
            public bool? Required { get; set; }
        }

        [DataContract]
        internal class CustomRecordType
        {
            [DataMember(Name = "$id", EmitDefaultValue = false)]
            public string Id { get; set; }

            [DataMember(Name = "description", EmitDefaultValue = false)]
            public string Description { get; set; }

            [DataMember(Name = "categories", EmitDefaultValue = false)]
            public string[] Categories { get; set; }

            [DataMember(Name = "fields", EmitDefaultValue = false)]
            public RecordTypeField[] Fields { get; set; }
        }
    }
}
