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
using System.IO;

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

            try
            {
                var response = await Auth.ExecuteAuthRest(RECORD_TYPE_ADD_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while creating a new custom record type. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message}");
                throw;
            }
        }

        public async Task<string> UpdateRecordTypeAsync(string recordTypeId, string recordTypeData)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeId, recordTypeData });
            bool enterpriseStatus = recordTypeService.CheckEnterpriseRecordTypeStatus(recordTypeId);
            if (!enterpriseStatus)
            {
                Console.WriteLine($"the given id is {recordTypeId}, Assuming its an enterprise record and updating this record");
            }
            recordTypeService.checkAdminAccess();

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));
            recordTypeService.validateRecordTypeData(recordTypeObj);

            Records.RecordType record = recordTypeService.CreateRecordTypeObject(recordTypeObj);

            try
            {
                int.TryParse(recordTypeId, out int parsedRecordTypeId);
                record.RecordTypeId = parsedRecordTypeId;
                var response = await Auth.ExecuteAuthRest(RECORD_TYPE_UPDATE_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while updating the custom record type with id {recordTypeId}. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message}");
                throw;
            }
        }

        public async Task<string> DeleteRecordTypeAsync(string recordTypeId)
        {
            var recordTypeService = new RecordTypeService(Auth.AuthContext);

            recordTypeService.validateParameterExistence(new List<string> { recordTypeId });
            recordTypeService.checkAdminAccess();
            bool enterpriseStatus = recordTypeService.CheckEnterpriseRecordTypeStatus(recordTypeId);
            if (!enterpriseStatus)
            {
                Console.WriteLine($"the given id is {recordTypeId}, Assuming its an enterprise record and deleting this record");
            }

            Records.RecordType record = new Records.RecordType();

            try
            {
                int.TryParse(recordTypeId, out int parsedRecordTypeId);
                record.RecordTypeId = parsedRecordTypeId;
                record.Scope = Records.RecordTypeScope.RtEnterprise;
                var response = await Auth.ExecuteAuthRest(RECORD_TYPE_DELETE_URL, record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while deleting the custom record type with id {recordTypeId}. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message}");
                throw;
            }
        }

        public async Task<List<string>> LoadRecordTypesAsync(string filePath)
        {
            var uploadCount = 0;
            var uploadedRecordTypeIds = new List<string>();

            var recordTypeService = new RecordTypeService(Auth.AuthContext);
            var newRecordTypes = recordTypeService.ValidateRecordTypeFile(filePath);
            var existingRecordTypes = recordTypeService.MapExistingRecordTypesToDictionary(RecordTypes.ToList());
            if (existingRecordTypes != null)
            {
                foreach (var recordType in newRecordTypes)
                {
                    if (existingRecordTypes.ContainsKey(recordType.RecordTypeName))
                    {
                        Console.WriteLine($"Record type '{recordType.RecordTypeName}' already exists. Skipping upload.");
                        continue;
                    }

                    try
                    {
                        var parsedRecord = recordTypeService.CreateRecordTypeObject(recordType);
                        var recordTypeID = await AddRecordType(Encoding.UTF8.GetString(JsonUtils.DumpJson(parsedRecord)));
                        uploadCount++;
                        uploadedRecordTypeIds.Add(recordTypeID);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error creating record type object for '{recordType.RecordTypeName}': {ex.Message}");
                        continue; 
                    }
                }
            }
            Console.WriteLine($"Successfully uploaded {uploadCount} record types from the file '{filePath}'.");
            return uploadedRecordTypeIds; 
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
                    throw new VaultException("Enterprise admin access is required for this command");
                }
            }

            public List<InputRecordType> ValidateRecordTypeFile(string filePath)
            {
                if (string.IsNullOrWhiteSpace(filePath))
                    throw new ArgumentException("File path is required.");

                if (!filePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Record type file must be a JSON file.");

                string content;
                try
                {
                    content = System.IO.File.ReadAllText(filePath);
                }
                catch (FileNotFoundException)
                {
                    throw new ArgumentException($"Record type file not found: {filePath}");
                }

                Dictionary<string, List<InputRecordType>> root = JsonUtils.ParseJson<Dictionary<string, List<InputRecordType>>>(Encoding.UTF8.GetBytes(content));

                List<InputRecordType> recordTypes;
                if (!root.TryGetValue("record_types", out recordTypes))
                {
                    throw new ArgumentException("Missing 'record_types' array in the file.");
                }

                return recordTypes;
            }

            public Dictionary<string, RecordType> MapExistingRecordTypesToDictionary(List<RecordType> recordTypes)
            {
                {
                    if (recordTypes == null || recordTypes.Count == 0)
                        return new Dictionary<string, RecordType>();

                    return recordTypes.ToDictionary(rt => rt.Name.ToString(), rt => rt);
                }
            }

            public CustomRecordType CreateRecordTypeObject(InputRecordType inputRecordType)
            {
                if (inputRecordType == null)
                    throw new ArgumentException("Input record type cannot be null.");

                var fields = inputRecordType.Fields.Select(f => new Dictionary<string, string>
                {
                    { "$type", f.Type },
                    { "label", f.Label ?? string.Empty },
                    { "required", f.Required?.ToString() ?? "false" }
                }).ToList();

                var add_fields = new List<RecordTypeField>();
                foreach (var field in fields)
                {
                    var fieldObject = new RecordTypeField { Ref = field.ContainsKey("$type") ? field["$type"] : null };
                    if (field.TryGetValue("required", out var requiredValue) && bool.TryParse(requiredValue, out var isRequired) && isRequired)
                    {
                        fieldObject.Required = isRequired;
                    }
                    add_fields.Add(fieldObject);
                }

                return new CustomRecordType
                {
                    Id = inputRecordType.RecordTypeName,
                    Description = inputRecordType.Description,
                    Categories = inputRecordType.Categories,
                    Fields = add_fields.ToArray()
                };
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

        [DataContract]
        internal class InputRecordType
        {
            [DataMember(Name = "record_type_name", EmitDefaultValue = false)]
            internal string RecordTypeName { get; set; }

            [DataMember(Name = "description", EmitDefaultValue = false)]
            public string Description { get; set; }

            [DataMember(Name = "categories", EmitDefaultValue = false)]
            public string[] Categories { get; set; }

            [DataMember(Name = "fields", EmitDefaultValue = false)]
            public List<InputRecordTypeField> Fields { get; set; }
        }

        [DataContract]
        public class InputRecordTypeField
        {
            [DataMember(Name = "$type", IsRequired = true)]
            public string Type { get; set; }

            [DataMember(Name = "label", EmitDefaultValue = false)]
            public string Label { get; set; }

            [DataMember(Name = "required", EmitDefaultValue = false)]
            public bool? Required { get; set; }
        }
    }
}
