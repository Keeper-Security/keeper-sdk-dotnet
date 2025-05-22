using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Runtime.Serialization;
using KeeperSecurity.Utils;
using System.Text;
using Records;
using System.Reflection;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline : IRecordTypeManagement
    {
        public async Task<string> AddRecordType(string recordTypeData)
        {
            if (string.IsNullOrWhiteSpace(recordTypeData))
            {
                throw new ArgumentException("recordTypeData cannot be null or empty");
            }

            var enterprise_admin_status = this.Auth.AuthContext.IsEnterpriseAdmin;

            if (!enterprise_admin_status)
            {
                throw new VaultException("User doesn't have permissions to create a new record type");
            }

            var recordTypeObj = JsonUtils.ParseJson<CustomRecordType>(Encoding.UTF8.GetBytes(recordTypeData));

            if (recordTypeObj == null)
                throw new ArgumentException("Invalid recordTypeData JSON");

            if (string.IsNullOrWhiteSpace(recordTypeObj.Id))
                throw new ArgumentException("Record type must have a title or name");

            var fieldsList = recordTypeObj.Fields
                .Select(f => new Dictionary<string, string> { ["$ref"] = f.Ref })
                .ToList();

            var recordTypeService = new RecordTypeService();

            Records.RecordType record = await recordTypeService.CreateCustomRecordType(
                recordTypeObj.Id,
                fieldsList,
                recordTypeObj.Description ?? string.Empty,
                "enterprise"
            );

            try
            {
                var response = await this.Auth.ExecuteAuthRest("vault/record_type_add", record, typeof(RecordTypeModifyResponse)) as RecordTypeModifyResponse;
                return response.RecordTypeId.ToString();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occured while creating a new custom record type. Code: {ex.GetType().GetProperty("Code", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(ex)}, Message: {ex.Message.ToString()}");
                throw;
            }
        }

        internal class RecordTypeService
        {
            public Task<Records.RecordType> CreateCustomRecordType(string title, List<Dictionary<string, string>> fields, string description = "", string scope = "enterprise")
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

                    if (!RecordTypesConstants.FieldTypes.Any(f => f.Name == fieldName))
                        throw new ArgumentException($"Field '{fieldName}' is not a valid RecordField.");

                    cleanedFields.Add(new Dictionary<string, string> { { "$ref", fieldName } });
                }

                var recordTypeData = new CustomRecordType
                {
                    Id = title,
                    Description = description,
                    Categories = new string[] { "note" },
                    Fields = fields.Select(f => new RecordTypeField { Ref = f["$ref"] }).ToArray()
                };

                var recordTypeProto = new Records.RecordType
                {
                    Content = Encoding.UTF8.GetString(JsonUtils.DumpJson(recordTypeData)),
                    Scope = Records.RecordTypeScope.RtEnterprise,

                };

                return Task.FromResult(recordTypeProto);
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

