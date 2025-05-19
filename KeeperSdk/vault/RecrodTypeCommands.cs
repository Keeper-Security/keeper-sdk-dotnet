using System;
using System.Collections.Generic;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;
using System.Linq;
using System.Runtime.Serialization;

namespace KeeperSdk.Enterprise
{
    public partial class Enterprise : IRecordTypeManagement
    {
        private readonly EnterpriseData _enterpriseData;
        public Enterprise(EnterpriseData enterpriseData)
        {
            _enterpriseData = enterpriseData ?? throw new ArgumentNullException(nameof(enterpriseData));
        }
        public async Task<Records.RecordType> AddRecordType(string recordData)
        {
            if (string.IsNullOrWhiteSpace(recordData))
            {
                throw new ArgumentException("recordData cannot be null or empty");
            }

            // Deserialize incoming JSON to CustomRecordType
            var recordTypeObj = DeserializeJson<CustomRecordType>(recordData);

            if (recordTypeObj == null)
                throw new ArgumentException("Invalid recordData JSON");

            if (string.IsNullOrWhiteSpace(recordTypeObj.Id))
                throw new ArgumentException("Record type must have an '$id'");

            if (recordTypeObj.Fields == null || recordTypeObj.Fields.Length == 0)
                throw new ArgumentException("Record type must have at least one field");

            // Convert Fields to List<Dictionary<string, string>>
            var fieldsList = recordTypeObj.Fields
                .Select(f => new Dictionary<string, string> { ["$ref"] = f.Ref })
                .ToList();

            // Instantiate your RecordTypeService with _enterpriseData
            var recordTypeService = new RecordTypeService(_enterpriseData);

            // Call async CreateCustomRecordType and await result
            var result = await recordTypeService.CreateCustomRecordType(
                recordTypeObj.Id,
                fieldsList,
                recordTypeObj.Description ?? string.Empty,
                "enterprise" // or you can pass this from recordTypeObj if present
            );

            return result;
        }

        internal class RecordTypeService
        {
            private readonly EnterpriseData _enterpriseData;

            public RecordTypeService(EnterpriseData enterpriseData)
            {
                _enterpriseData = enterpriseData;
            }

            public Task<Records.RecordType> CreateCustomRecordType(string title, List<Dictionary<string, string>> fields, string description = "", string scope = "enterprise")
            {
                if (scope != "enterprise")
                    throw new ArgumentException("This command is restricted to Keeper Enterprise administrators.");

                if (fields == null || fields.Count == 0)
                    throw new ArgumentException("At least one field must be specified.");

                // Validate and clean field references
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
                    Content = recordTypeData.ToString(),
                    Scope = Records.RecordTypeScope.RtEnterprise,

                };

                return Task.FromResult(recordTypeProto);
            }
        }
    public static T DeserializeJson<T>(string json)
        {
            using (var ms = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(json)))
            {
                var ser = new DataContractJsonSerializer(typeof(T));
                return (T) ser.ReadObject(ms);
            }
        }
    }
}



[DataContract]
public class RecordTypeField
{
    [DataMember(Name = "$ref")]
    public string Ref { get; set; }
}

public class CustomRecordType
{
    [DataMember(Name = "$id")]
    public string Id { get; set; }

    [DataMember(Name = "description")]
    public string Description { get; set; }

    [DataMember(Name = "categories")]
    public string[] Categories { get; set; }

    [DataMember(Name = "fields")]
    public RecordTypeField[] Fields { get; set; }
}
