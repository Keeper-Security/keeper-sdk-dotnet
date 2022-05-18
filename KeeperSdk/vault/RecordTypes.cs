using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Record Types Schema: Field Type definition.
    /// </summary>
    public class FieldType
    {
        /// <exclude />
        public FieldType(string name, Type type, string description)
        {
            Name = name;
            Type = type;
            Description = description;
        }

        /// <summary>
        /// Type name
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Type description
        /// </summary>
        public string Description { get; }
        /// <summary>
        /// .Net Type object
        /// </summary>
        public Type Type { get; }
    }

    /// <summary>
    /// Specifies if Record Field allows multiple values.
    /// </summary>
    public enum RecordFieldMultiple
    {
        /// <summary>
        /// Single Value only
        /// </summary>
        None,
        /// <summary>
        /// Maybe multi-valued
        /// </summary>
        Optional,
        /// <summary>
        /// Multi-Value field
        /// </summary>
        Default,
    }

    /// <summary>
    /// Record Types Schema: Field definition.
    /// </summary>
    public class RecordField
    {
        /// <exclude />
        public RecordField(string name, FieldType fieldType, RecordFieldMultiple multiple = RecordFieldMultiple.None)
        {
            Name = name;
            Type = fieldType;
            Multiple = multiple;
        }

        /// <summary>
        /// Record Field Name
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Field Type
        /// </summary>
        public FieldType Type { get; }
        /// <summary>
        /// Multi-Value attribute
        /// </summary>
        public RecordFieldMultiple Multiple { get; }
    }

    /// <summary>
    /// Defines common properties for Record Field
    /// </summary>
    public interface IRecordTypeField
    {
        /// <summary>
        /// Record Field Name
        /// </summary>
        string FieldName { get; }
        /// <summary>
        /// Record Field Label
        /// </summary>
        string FieldLabel { get; }
    }

    /// <summary>
    /// Record Types Schema: Record Field definition.
    /// </summary>
    public class RecordTypeField : IRecordTypeField
    {
        /// <summary>
        /// Initializes a new instance of the RecordTypeField class
        /// </summary>
        /// <param name="fieldName">Field Name</param>
        public RecordTypeField(string fieldName): this(fieldName, null)
        {
        }
        /// <summary>
        /// Initializes a new instance of the RecordTypeField class
        /// </summary>
        /// <param name="fieldName">Field Name</param>
        /// <param name="label">Field Label</param>
        public RecordTypeField(string fieldName, string label)
        {
            if (RecordTypesConstants.TryGetRecordField(fieldName, out var rf))
            {
                RecordField = rf;
            }
            FieldName = fieldName;
            FieldLabel = label;
        }
        /// <summary>
        /// Initializes a new instance of the RecordTypeField class
        /// </summary>
        /// <param name="recordField">Field</param>
        /// <param name="label">Field Label</param>
        public RecordTypeField(RecordField recordField, string label = null)
        {
            RecordField = recordField;
            FieldName = RecordField.Name;
            FieldLabel = label;
        }

        /// <summary>
        /// Gets Record Field
        /// </summary>
        public RecordField RecordField { get; }

        /// <summary>
        /// Gets field name
        /// </summary>
        public string FieldName { get; }
        /// <summary>
        /// Gets field label
        /// </summary>
        public string FieldLabel { get; }
    }

    /// <summary>
    ///  Record Types Schema: Record Type definition.
    /// </summary>
    public class RecordType
    {
        /// <exclude />
        public RecordType() { }

        /// <exclude />
        public RecordType(int id, string name, string description, IEnumerable<RecordTypeField> fields) : this()
        {
            Id = id;
            Scope = RecordTypeScope.User;
            Name = name;
            Description = description;
            Fields = fields.ToArray();
        }

        /// <summary>
        /// Gets record type ID
        /// </summary>
        public int Id { get; internal set; }
        /// <summary>
        /// Gets record type scope
        /// </summary>
        public RecordTypeScope Scope { get; internal set; }
        /// <summary>
        /// Gets record type name
        /// </summary>
        public string Name { get; internal set; }
        /// <summary>
        /// Gets record type description
        /// </summary>
        public string Description { get; internal set; }
        /// <summary>
        /// Gets record type fields
        /// </summary>
        public RecordTypeField[] Fields { get; internal set; }
    }

    /// <summary>
    /// Defines access methods for compound record types
    /// </summary>
    public interface IFieldTypeSerialize
    {
        /// <summary>
        /// Enumerates property names
        /// </summary>
        IEnumerable<string> Elements { get; }
        /// <summary>
        /// Enumerates property values
        /// </summary>
        IEnumerable<string> ElementValues { get; }
        /// <summary>
        /// Sets property value
        /// </summary>
        /// <param name="element">Property or element name</param>
        /// <param name="value">Property value</param>
        /// <returns>true is the property was set</returns>
        bool SetElementValue(string element, string value);
    }

    /// <summary>
    /// "host" field type
    /// </summary>
    [DataContract]
    public class FieldTypeHost : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypeHost()
        {
            HostName = "";
            Port = "";
        }
        /// <summary>
        /// Gets or sets hostname
        /// </summary>
        [DataMember(Name = "hostName", EmitDefaultValue = true)]
        public string HostName { get; set; }
        /// <summary>
        /// Gets or sets port
        /// </summary>
        [DataMember(Name = "port", EmitDefaultValue = true)]
        public string Port { get; set; }

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { HostName, Port };

        private static readonly string[] HostElements = new[] { "hostName", "port" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => HostElements;

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "hostName")
            {
                HostName = value;
            }
            else if (element == "port")
            {
                Port = value;
            }
            else
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// "phone" field type
    /// </summary>
    [DataContract]
    public class FieldTypePhone : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypePhone()
        {
            Region = "";
            Number = "";
            Ext = "";
            Type = "";
        }

        /// <summary>
        /// Gets or sets phone region
        /// </summary>
        [DataMember(Name = "region", EmitDefaultValue = true)]
        public string Region { get; set; }
        /// <summary>
        /// Gets or sets phone number
        /// </summary>
        [DataMember(Name = "number", EmitDefaultValue = true)]
        public string Number { get; set; }
        /// <summary>
        /// Gets or sets phone extension
        /// </summary>
        [DataMember(Name = "ext", EmitDefaultValue = true)]
        public string Ext { get; set; }
        /// <summary>
        /// Gets or sets phone type
        /// </summary>
        [DataMember(Name = "type", EmitDefaultValue = true)]
        public string Type { get; set; }

        private static readonly string[] PhoneElements = new[] { "region", "number", "ext", "type" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => PhoneElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { Region, Number, Ext, Type };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "region")
            {
                Region = value;
            }
            else if (element == "number")
            {
                Number = value;
            }
            else if (element == "ext")
            {
                Ext = value;
            }
            else if (element == "type")
            {
                Type = value;
            }
            else
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// "name" field type
    /// </summary>
    [DataContract(Name = "Name")]
    public class FieldTypeName : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypeName()
        {
            First = "";
            Middle = "";
            Last = "";
        }

        /// <summary>
        /// Gets or sets first name
        /// </summary>
        [DataMember(Name = "first", EmitDefaultValue = true)]
        public string First { get; set; }

        /// <summary>
        /// Gets or sets last name
        /// </summary>
        [DataMember(Name = "last", EmitDefaultValue = true)]
        public string Last { get; set; }

        /// <summary>
        /// Gets or sets middle name
        /// </summary>
        [DataMember(Name = "middle", EmitDefaultValue = true)]
        public string Middle { get; set; }

        private static readonly string[] NameElements = new string[] { "first", "middle", "last" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => NameElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { First, Middle, Last };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "first")
            {
                First = value;
            }
            else if (element == "last")
            {
                Last = value;
            }
            else if (element == "middle")
            {
                Middle = value;
            }
            else
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// "address" field type
    /// </summary>
    [DataContract]
    public class FieldTypeAddress : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypeAddress()
        {
            Street1 = "";
            Street2 = "";
            City = "";
            State = "";
            Zip = "";
            Country = "";
        }

        /// <summary>
        /// Gets or sets Street 1
        /// </summary>
        [DataMember(Name = "street1", EmitDefaultValue = true)]
        public string Street1 { get; set; }

        /// <summary>
        /// Gets or sets Street 1
        /// </summary>
        [DataMember(Name = "street2", EmitDefaultValue = true)]
        public string Street2 { get; set; }

        /// <summary>
        /// Gets or sets City
        /// </summary>
        [DataMember(Name = "city", EmitDefaultValue = true)]
        public string City { get; set; }

        /// <summary>
        /// Gets or sets State
        /// </summary>
        [DataMember(Name = "state", EmitDefaultValue = true)]
        public string State { get; set; }

        /// <summary>
        /// Gets or sets Zip/Postal Code
        /// </summary>
        [DataMember(Name = "zip", EmitDefaultValue = true)]
        public string Zip { get; set; }

        /// <summary>
        /// Gets or sets Country
        /// </summary>
        [DataMember(Name = "country", EmitDefaultValue = true)]
        public string Country { get; set; }

        private static readonly string[] AddressElements = new string[] { "street1", "street2", "city", "state", "zip", "country" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => AddressElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { Street1, Street2, City, State, Zip, Country };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "street1")
            {
                Street1 = value;
            }
            else if (element == "street2")
            {
                Street2 = value;
            }
            else if (element == "city")
            {
                City = value;
            }
            else if (element == "state")
            {
                State = value;
            }
            else if (element == "zip")
            {
                Zip = value;
            }
            else if (element == "country")
            {
                Country = value;
            }
            else
            {
                return false;
            }

            return true;
        }

    }

    /// <summary>
    /// "securityQuestion" field type
    /// </summary>
    [DataContract]
    public class FieldTypeSecurityQuestion : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypeSecurityQuestion()
        {
            Question = "";
            Answer = "";
        }

        /// <summary>
        /// Gets or sets Security Question
        /// </summary>
        [DataMember(Name = "question", EmitDefaultValue = true)]
        public string Question { get; set; }
        /// <summary>
        /// Gets or sets Security Answer
        /// </summary>
        [DataMember(Name = "answer", EmitDefaultValue = true)]
        public string Answer { get; set; }

        private static readonly string[] QAElements = new[] { "question", "answer" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => QAElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { Question, Answer };


        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "question")
            {
                Question = value;
            }
            else if (element == "answer")
            {
                Answer = value;
            }
            else
            {
                return false;
            }
            return true;
        }

    }


    /// <summary>
    /// "bankAccount" field type
    /// </summary>
    [DataContract]
    public class FieldTypeBankAccount : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypeBankAccount()
        {
            AccountType = "";
            RoutingNumber = "";
            AccountNumber = "";
        }

        /// <summary>
        /// Gets or sets Account Type
        /// </summary>
        [DataMember(Name = "accountType", EmitDefaultValue = true)]
        public string AccountType { get; set; }

        /// <summary>
        /// Gets or sets Routing Number
        /// </summary>
        [DataMember(Name = "routingNumber", EmitDefaultValue = true)]
        public string RoutingNumber { get; set; }

        /// <summary>
        /// Gets or setsAccount Number
        /// </summary>
        [DataMember(Name = "accountNumber", EmitDefaultValue = true)]
        public string AccountNumber { get; set; }

        private static readonly string[] AccountElements = new[] { "accountType", "routingNumber", "accountNumber" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => AccountElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { AccountType, RoutingNumber, AccountNumber };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "accountType")
            {
                AccountType = value;
            }
            else if (element == "routingNumber")
            {
                RoutingNumber = value;
            }
            else if (element == "accountNumber")
            {
                AccountNumber = value;
            }
            else
            {
                return false;
            }
            return true;
        }
    }

    /// <summary>
    /// "paymentCard" field type
    /// </summary>
    [DataContract]

    public class FieldTypePaymentCard : IFieldTypeSerialize
    {
        /// <exclude />
        public FieldTypePaymentCard()
        {
            CardNumber = "";
            CardExpirationDate = "";
            CardSecurityCode = "";
        }
        /// <summary>
        /// Gets or sets Card Number
        /// </summary>
        [DataMember(Name = "cardNumber", EmitDefaultValue = true)]
        public string CardNumber { get; set; }

        /// <summary>
        /// Gets or sets Card Expiration Date
        /// </summary>
        [DataMember(Name = "cardExpirationDate", EmitDefaultValue = true)]
        public string CardExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets Card Security Code
        /// </summary>
        [DataMember(Name = "cardSecurityCode", EmitDefaultValue = true)]
        public string CardSecurityCode { get; set; }

        private static string[] CardElements = new[] { "cardNumber", "cardExpirationDate", "cardSecurityCode" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => CardElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { CardNumber, CardExpirationDate, CardSecurityCode };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "cardNumber")
            {
                CardNumber = value;
            }
            else if (element == "cardExpirationDate")
            {
                CardExpirationDate = value;
            }
            else if (element == "cardSecurityCode")
            {
                CardSecurityCode = value;
            }
            else
            {
                return false;
            }
            return true;
        }
    }

    /// <summary>
    /// "keyPair" field type
    /// </summary>
    [DataContract]
    public class FieldTypeKeyPair : IFieldTypeSerialize
    {
        public FieldTypeKeyPair()
        {
            PublicKey = "";
            PrivateKey = "";
        }
        /// <summary>
        /// Gets or sets Public Key
        /// </summary>
        [DataMember(Name = "publicKey", EmitDefaultValue = true)]
        public string PublicKey { get; set; }

        /// <summary>
        /// Gets or sets Private Key
        /// </summary>
        [DataMember(Name = "privateKey", EmitDefaultValue = true)]
        public string PrivateKey { get; set; }

        private static string[] KeyPairElements = new[] { "publicKey", "privateKey" };
        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.Elements => KeyPairElements;

        /// <exclude />
        IEnumerable<string> IFieldTypeSerialize.ElementValues => new[] { PublicKey, PrivateKey };

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            if (element == "publicKey")
            {
                PublicKey = value;
            }
            else if (element == "privateKey")
            {
                PrivateKey = value;
            }
            else
            {
                return false;
            }
            return true;
        }
    }

    internal class RecordTypeInfo
    {
        public Type RecordFieldType { get; set; }   // RecordTypeDataField
        public Type TypedFieldType { get; set; }   // TypedField
        public DataContractJsonSerializer Serializer { get; set; }
    }

    /// <summary>
    /// Record Types Schema: Fields
    /// </summary>
    public static class RecordTypesConstants
    {
        private static readonly Dictionary<string, FieldType> _fieldTypes = new Dictionary<string, FieldType>(StringComparer.InvariantCultureIgnoreCase);
        private static readonly Dictionary<string, RecordField> _recordFields = new Dictionary<string, RecordField>(StringComparer.InvariantCultureIgnoreCase);

        static RecordTypesConstants()
        {
            var types = new[]
            {
                new FieldType("text", typeof(string), "plain text"),
                new FieldType("url", typeof(string), "url string, can be clicked"),
                new FieldType("multiline", typeof(string), "multiline text"),
                new FieldType("fileRef", typeof(string), "reference to the file field on another record"),
                new FieldType("email", typeof(string), "valid email address plus tag"),
                new FieldType("host", typeof(FieldTypeHost), "multiple fields to capture host information"),
                new FieldType("phone", typeof(FieldTypePhone), "numbers and symbols only plus tag"),
                new FieldType("name", typeof(FieldTypeName), "multiple fields to capture name"),
                new FieldType("address", typeof(FieldTypeAddress), "multiple fields to capture address"),
                new FieldType("addressRef", typeof(string), "reference to the address field on another record"),
                new FieldType("cardRef", typeof(string), "reference to the card record type"),
                new FieldType("secret", typeof(string), "the field value is masked"),
                new FieldType("login", typeof(string), "Login field, detected as the website login for browser extension or KFFA."),
                new FieldType("password", typeof(string), "Field value is masked and allows for generation. Also complexity enforcements."),
                new FieldType("securityQuestion", typeof(FieldTypeSecurityQuestion), "Security Question and Answer"),
                new FieldType("otp", typeof(string), "captures the seed, displays QR code"),
                new FieldType("paymentCard", typeof(FieldTypePaymentCard), "Field consisting of validated card number, expiration date and security code."),
                new FieldType("date", typeof(long), "calendar date with validation, stored as unix milliseconds"),
                new FieldType("bankAccount", typeof(FieldTypeBankAccount), "bank account information"),
                new FieldType("privateKey", typeof(FieldTypeKeyPair), "private and/or public keys in ASN.1 format"),
            };

            foreach (var t in types)
            {
                _fieldTypes.Add(t.Name, t);
            }

            var fields = new[]
            {
                new RecordField("text", _fieldTypes["text"]),
                new RecordField("title", _fieldTypes["text"]),
                new RecordField("login", _fieldTypes["login"]),
                new RecordField("password", _fieldTypes["password"]),
                new RecordField("name", _fieldTypes["name"]),
                new RecordField("company", _fieldTypes["text"]),
                new RecordField("phone", _fieldTypes["phone"], RecordFieldMultiple.Optional),
                new RecordField("email", _fieldTypes["email"], RecordFieldMultiple.Optional),
                new RecordField("address", _fieldTypes["address"]),
                new RecordField("addressRef", _fieldTypes["addressRef"]),
                new RecordField("date", _fieldTypes["date"]),
                new RecordField("expirationDate", _fieldTypes["date"]),
                new RecordField("birthDate", _fieldTypes["date"]),
                new RecordField("paymentCard", _fieldTypes["paymentCard"]),
                new RecordField("accountNumber", _fieldTypes["text"]),
                new RecordField("bankAccount", _fieldTypes["bankAccount"]),
                new RecordField("cardRef", _fieldTypes["cardRef"], RecordFieldMultiple.Default),
                new RecordField("note", _fieldTypes["multiline"]),
                new RecordField("url", _fieldTypes["url"], RecordFieldMultiple.Optional),
                new RecordField("fileRef", _fieldTypes["fileRef"], RecordFieldMultiple.Default),
                new RecordField("host", _fieldTypes["host"], RecordFieldMultiple.Optional),
                new RecordField("securityQuestion", _fieldTypes["securityQuestion"], RecordFieldMultiple.Default),
                new RecordField("pinCode", _fieldTypes["secret"]),
                new RecordField("oneTimeCode", _fieldTypes["otp"]),
                new RecordField("keyPair", _fieldTypes["privateKey"]),
                new RecordField("licenseNumber", _fieldTypes["multiline"]),
            };
            foreach (var rf in fields)
            {
                _recordFields.Add(rf.Name, rf);
            }
        }

        /// <summary>
        /// Gets supported Field Types
        /// </summary>
        public static IEnumerable<FieldType> FieldTypes => _fieldTypes.Values;

        /// <summary>
        /// Gets supported Fields
        /// </summary>
        public static IEnumerable<RecordField> RecordFields => _recordFields.Values;
        public static bool TryGetRecordField(string name, out RecordField value)
        {
            return _recordFields.TryGetValue(name ?? "text", out value);
        }

        private static readonly Dictionary<Type, RecordTypeInfo> _recordTypeInfo = new Dictionary<Type, RecordTypeInfo>();

        internal static bool GetRecordType(Type dataType, out RecordTypeInfo recordTypeInfo)
        {
            lock (_recordTypeInfo)
            {
                if (_recordTypeInfo.TryGetValue(dataType, out recordTypeInfo))
                {
                    return true;
                }
                var genericRecordType = typeof(RecordTypeDataField<>);
                var genericTypedFieldType = typeof(TypedField<>);
                recordTypeInfo = new RecordTypeInfo
                {
                    RecordFieldType = genericRecordType.MakeGenericType(dataType),
                    TypedFieldType = genericTypedFieldType.MakeGenericType(dataType),
                };
                recordTypeInfo.Serializer = new DataContractJsonSerializer(recordTypeInfo.RecordFieldType, JsonUtils.JsonSettings);
                _recordTypeInfo.Add(dataType, recordTypeInfo);
                return true;
            }
        }

        /// <exclude />
        public static bool GetTypedFieldType(Type dataType, out Type typedFieldType)
        {
            if (GetRecordType(dataType, out var rt))
            {
                typedFieldType = rt.TypedFieldType;
                return true;
            }

            typedFieldType = null;
            return false;
        }

        /// <exclude />
        public static bool GetRecordFieldDataType(Type dataType, out Type recordFieldType)
        {
            if (GetRecordType(dataType, out var rt))
            {
                recordFieldType = rt.RecordFieldType;
                return true;
            }

            recordFieldType = null;
            return false;
        }
        /// <exclude />
        public static bool GetJsonParser(Type dataType, out DataContractJsonSerializer jsonType)
        {
            if (GetRecordType(dataType, out var rt))
            {
                jsonType = rt.Serializer;
                return true;
            }

            jsonType = null;
            return false;
        }
    }

    internal class ApiRecordType : IRecordType
    {
        private readonly string _uid;
        public ApiRecordType(Records.RecordType recordType)
        {
            string scopeName;
            Id = recordType.RecordTypeId;
            switch (recordType.Scope)
            {
                case Records.RecordTypeScope.RtStandard:
                    Scope = RecordTypeScope.Standard;
                    scopeName = "standard";
                    break;
                case Records.RecordTypeScope.RtEnterprise:
                    Scope = RecordTypeScope.Enterprise;
                    scopeName = "enterprise";
                    break;
                default:
                    Scope = RecordTypeScope.User;
                    scopeName = "user";
                    break;
            }
            _uid = $"{scopeName}:{Id}";
            Content = recordType.Content;
        }

        public int Id { get; }
        public RecordTypeScope Scope { get; }
        public string Content { get; }
        string IUid.Uid => _uid;
    }

    [DataContract]
    internal class RecordTypeContentField
    {
        [DataMember(Name = "$ref")]
        public string Ref { get; set; }

        [DataMember(Name = "label")]
        public string Label { get; set; }
    }

    [DataContract]
    internal class RecordTypeContent
    {
        [DataMember(Name = "$id")]
        public string Name { get; set; }

        [DataMember(Name = "categories")]
        public string[] Categories { get; set; }

        [DataMember(Name = "description")]
        public string Description { get; set; }

        [DataMember(Name = "fields")]
        public RecordTypeContentField[] Fields { get; set; }
    }

    [DataContract]
    internal class RecordTypeDataField<T> : RecordTypeDataFieldBase
    {
        [DataMember(Name = "value", Order = 3, EmitDefaultValue = false)]
        public T[] Value { get; set; }

        public override ITypedField CreateTypedField()
        {
            return new TypedField<T>(this);
        }

        public RecordTypeDataField(TypedField<T> typedField)
        {
            Type = typedField.FieldName;
            Label = typedField.FieldLabel;
            Value = typedField.Values.Where(x => x != null).ToArray();
        }
    }


    [DataContract]
    internal class RecordTypeDataFieldBase : IExtensibleDataObject
    {
        [DataMember(Name = "type", Order = 1)]
        public string Type { get; set; }
        [DataMember(Name = "label", Order = 2, EmitDefaultValue = false)]
        public string Label { get; set; }
        public ExtensionDataObject ExtensionData { get; set; }

        public virtual ITypedField CreateTypedField()
        {
            return null;
        }
    }

    [DataContract]
    internal class RecordTypeData
    {
        [DataMember(Name = "type", Order = 1)]
        public string Type { get; set; }

        [DataMember(Name = "title", Order = 2)]
        public string Title { get; set; }

        [DataMember(Name = "notes", Order = 3)]
        public string Notes { get; set; }

        [DataMember(Name = "fields", Order = 4)]
        public RecordTypeDataFieldBase[] Fields { get; set; }

        [DataMember(Name = "custom", Order = 5)]
        public RecordTypeDataFieldBase[] Custom { get; set; }
    }

    [DataContract]
    internal class RecordFileData
    {
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [DataMember(Name = "size", EmitDefaultValue = false)]
        public long? Size { get; set; }

        [DataMember(Name = "thumbnail_size", EmitDefaultValue = false)]
        public long? ThumbnailSize { get; set; }

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        [DataMember(Name = "lastModified", EmitDefaultValue = false)]
        public long? LastModified { get; set; }
    }

}
