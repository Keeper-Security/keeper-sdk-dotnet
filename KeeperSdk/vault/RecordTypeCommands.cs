using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Runtime.Serialization;
using KeeperSecurity.Utils;
using System.Text;
using Records;
using System.Reflection;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline : IRecordTypeManagement
    {
        public async Task<string> AddRecordType(string recordTypeData, List<string> categories=null)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeData });
            recordTypeService.checkAdminAccess();

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));
            recordTypeService.validateRecordTypeData(recordTypeObj);

            Records.RecordType record = recordTypeService.CreateCustomRecordType(recordTypeObj);

            try
            {
                var response = await Auth.ExecuteAuthRest("vault/record_type_add", record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while creating a new custom record type. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message}");
                throw;
            }
        }

        public async Task<string> UpdateRecordTypeAsync(string recordTypeId, string recordTypeData, List<string> categories=null)
        {
            var recordTypeService = new RecordTypeService(this.Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeId, recordTypeData });
            recordTypeService.CheckEnterpriseRecordTypeStatus(recordTypeId);
            recordTypeService.checkAdminAccess();

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));
            recordTypeService.validateRecordTypeData(recordTypeObj);

            Records.RecordType record = recordTypeService.CreateCustomRecordType(recordTypeObj);

            try
            {
                int.TryParse(recordTypeId, out int parsedRecordTypeId);
                record.RecordTypeId = parsedRecordTypeId;
                var response = await this.Auth.ExecuteAuthRest("vault/record_type_update", record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while updating the custom record type with id {recordTypeId}. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message}");
                throw;
            }
        }

        internal class RecordTypeService
        {
            private readonly IAuthContext auth;

            public RecordTypeService(IAuthContext auth)
            {
                this.auth = auth;
            }

            public Records.RecordType CreateCustomRecordType(CustomRecordType customRecordObject = null, string scope = "enterprise", List<string> categories = null)
            {
                var title = customRecordObject.Id;
                var fields = customRecordObject.Fields
                            .Select(f => new Dictionary<string, string> { ["$ref"] = f.Ref })
                            .ToList();
                var description = customRecordObject.Description ?? string.Empty;
                string[] parsedCategroies = (categories != null && categories.Count > 0) ? categories.ToArray() : new string[] { "note" };

                var cleanedFields = validateRecordTypeData(scope,fields);                

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
                    throw new ArgumentException("This command is restricted to Keeper Enterprise administrators.");

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

            public bool CheckEnterpriseRecordTypeStatus(string recordTypeID)
            {
                int parsedRecordTypeId;
                if (!int.TryParse(recordTypeID, out parsedRecordTypeId))
                {
                    throw new ArgumentException($"Record type ID is supposed to be an integrer but {recordTypeID} is provided");
                }

                var recordTypesPerScope = 1_000_000;
                var enterpriseScope = Records.RecordTypeScope.RtEnterprise;
                var minimumId = recordTypesPerScope * (int) enterpriseScope;
                var maximumId = recordTypesPerScope + minimumId;
                bool isEnterpriseRecordType = (minimumId < parsedRecordTypeId) && (maximumId > parsedRecordTypeId);
                return isEnterpriseRecordType;
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
                    if (String.IsNullOrWhiteSpace(o))
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
                    throw new VaultException("User doesn't have permissions to create a new record type");
                }
            }
        }

        [DataContract]
        internal class RecordTypeField
        {
            [DataMember(Name = "$ref", EmitDefaultValue = false)]
            public string Ref { get; set; }
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

