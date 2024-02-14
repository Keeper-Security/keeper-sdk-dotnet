using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Record Types Schema: Field Type definition.
    /// </summary>
    public class FieldType
    {
        /// <exclude />
        public FieldType(string name, Type type, string defaultValue, string description)
        {
            Name = name;
            Type = type;
            Description = description;
            DefaultValue = defaultValue;
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

        public string DefaultValue { get; }
    }

    /// <summary>
    /// Specifies if Record Field allows multiple values.
    /// </summary>
    public enum RecordFieldMultiple
    {
        /// <summary>
        /// Single Value only
        /// </summary>
        Never,
        /// <summary>
        /// Maybe multi-valued
        /// </summary>
        Optional,
        /// <summary>
        /// Multi-Value field
        /// </summary>
        Always,
    }

    /// <summary>
    /// Record Types Schema: Field definition.
    /// </summary>
    public class RecordField
    {
        /// <exclude />
        public RecordField(string name, FieldType fieldType, RecordFieldMultiple multiple = RecordFieldMultiple.Optional)
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
            if (string.IsNullOrEmpty(fieldName)) 
            {
                fieldName = "text";
            }
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

    public class RecordTypePasswordField : RecordTypeField
    {
        public RecordTypePasswordField(RecordField recordField, string label) : base(recordField, label)
        {
        }
        public PasswordGenerationOptions PasswordOptions { get; set; }
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

        /// <summary>
        /// Sets field value from human friendly text
        /// </summary>
        /// <param name="value">String representation</param>
        void SetValueAsString(string value);
        /// <summary>
        /// Gets human friendly text
        /// </summary>
        /// <returns></returns>
        string GetValueAsString();
    }


    [DataContract]
    public class FieldTypeBase : IExtensibleDataObject
    {
        public ExtensionDataObject ExtensionData { get; set; }
    }

    /// <summary>
    /// "host" field type
    /// </summary>
    [DataContract]
    public class FieldTypeHost : FieldTypeBase, IFieldTypeSerialize
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


        private static readonly string[] HostElements = new[] { "hostName", "port" };
        /// <exclude />
        public IEnumerable<string> Elements => HostElements;
        /// <exclude />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return HostName;
                yield return Port;
            }
        }

        public bool SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "hostName": HostName = value; return true;
                case "port": Port = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                var idx = value.LastIndexOf(':');
                if (idx >= 0)
                {
                    HostName = value.Substring(0, idx).Trim();
                    Port = value.Substring(idx + 1).Trim();
                }
                else
                {
                    HostName = value;
                    Port = "";
                }
            }
            else
            {
                HostName = "";
                Port = "";
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }
            var result = !string.IsNullOrEmpty(HostName) ? HostName : "";
            if (!string.IsNullOrEmpty(Port))
            {
                result += $":{Port}";
            }
            return result;
        }
    }

    /// <summary>
    /// "phone" field type
    /// </summary>
    [DataContract]
    public class FieldTypePhone : FieldTypeBase, IFieldTypeSerialize
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
        public IEnumerable<string> Elements => PhoneElements;

        /// <exclude />
        public IEnumerable<string> ElementValues 
        { 
            get 
            {
                yield return Region;
                yield return Number;
                yield return Ext;
                yield return Type;
            }
        }

        /// <exclude />
        public bool SetElementValue(string element, string value)
        {
            switch (element) 
            {
                case "region": Region = value; return true;
                case "number": Number = value; return true;
                case "ext": Ext = value; return true;
                case "type": Type = value; return true;
                default: return true;
            }
        }
        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            Type = "";
            Region = "";
            Number = "";
            Ext = "";
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            var idx = value.LastIndexOf(':');
            if (idx >= 0)
            {
                Type = value.Substring(0, idx).Trim();
                value = value.Substring(idx + 1).Trim();
            }
            var comps = value.Split(' ').Select(x => x.Trim()).Where(x => !string.IsNullOrEmpty(x)).ToArray();
            if (comps.Length == 0)
            {
                return;
            }
            if (comps.Length == 1)
            {
                Number = comps[0];
                return;
            }

            if (comps[0].StartsWith("+") || comps[0].Length == 2) 
            { 
                Region = comps[0];
                comps[0] = null;
                comps = comps.Where(x => !string.IsNullOrEmpty(x)).ToArray();
            }
            if (comps.Length == 1)
            {
                Number = comps[0];
                return;
            }
            Ext = comps[comps.Length - 1];
            Number = string.Join(" ", comps.Take(comps.Length - 1));
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }
            var result = !string.IsNullOrEmpty(Type) ? $"{Type}: " : "";
            result += string.Join(" ", (new string[] { Region, Number, Ext }).Where(x => !string.IsNullOrEmpty(x)));
            return result;
        }
    }

    /// <summary>
    /// "name" field type
    /// </summary>
    [DataContract(Name = "Name")]
    public class FieldTypeName : FieldTypeBase, IFieldTypeSerialize
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
        public IEnumerable<string> Elements => NameElements;

        /// <exclude />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return First;
                yield return Middle;
                yield return Last;
            }
        }

        /// <exclude />
        public bool SetElementValue(string element, string value)
        {
            switch (element) 
            {
                case "first": First = value; return true;
                case "last": Last = value; return true;
                case "middle": Middle = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            First = "";
            Last = "";
            Middle = "";
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            var idx = value.LastIndexOf(',');
            if (idx >= 0)
            {
                Last = value.Substring(0, idx).Trim();
                value = value.Substring(idx + 1).Trim();
            }
            else
            {
                idx = value.LastIndexOf(' ');
                if (idx >= 0)
                {
                    Last = value.Substring(idx + 1).Trim();
                    value = value.Substring(0, idx).Trim();
                }
            }
            idx = value.LastIndexOf(' ');
            if (idx >= 0)
            {
                First = value.Substring(0, idx).Trim();
                Middle = value.Substring(idx + 1).Trim();
            }
            else
            {
                First = value;
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }
            var result = string.IsNullOrEmpty(Last) ? "" : $"{Last}, ";
            result += string.Join(" ", (new string[] { First, Middle }).Where(x => !string.IsNullOrEmpty(x)));
            return result.Trim();
        }
    }

    /// <summary>
    /// "address" field type
    /// </summary>
    [DataContract]
    public class FieldTypeAddress : FieldTypeBase, IFieldTypeSerialize
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
        public IEnumerable<string> Elements => AddressElements;

        /// <exclude />
        public IEnumerable<string> ElementValues
        {
            get {
                yield return Street1;
                yield return Street2;
                yield return City;
                yield return State;
                yield return Zip;
                yield return Country;
            }
        }

        /// <exclude />
        public bool SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "street1": Street1 = value; return true;
                case "street2": Street2 = value; return true;
                case "city": City = value; return true;
                case "state": State = value; return true;
                case "zip": Zip = value; return true;
                case "country": Country = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            Street1 = "";
            Street2 = "";
            City = "";
            State = "";
            Zip = "";
            Country = "";
            if (string.IsNullOrEmpty(value))
            {
                return;
            }
            var comps = value.Split(',').Select(x => x.Trim()).ToArray();
            if (comps.Length == 0) {
                return;
            }
            if (comps.Length >= 4) {
                Country = comps[comps.Length - 1];
                comps = comps.Take(comps.Length - 1).ToArray();
            }
            if (comps.Length >= 3)
            {
                var zip = comps[comps.Length - 1];
                var pos = zip.LastIndexOf(' ');
                if (pos > 0)
                {
                    State = zip.Substring(0, pos).Trim();
                    Zip = zip.Substring(pos + 1).Trim();
                }
                else
                {
                    if (zip.Any(x => Char.IsNumber(x)))
                    {
                        Zip = zip;
                    }
                    else
                    {
                        State = zip;
                    }
                }
                comps = comps.Take(comps.Length - 1).ToArray();
            }
            if (comps.Length >= 2)
            {
                City = comps[comps.Length - 1];
                comps = comps.Take(comps.Length - 1).ToArray();
            }

            if (comps.Length >= 2)
            {
                Street2 = comps[comps.Length - 1];
                Street1 = string.Join(" ", comps.Take(comps.Length - 1));
            }
            else if (comps.Length >= 1)
            {
                Street1 = string.Join(" ", comps);
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }

            var result = Street1 ?? "";
            if (!string.IsNullOrEmpty(Street2))
            {
                result += $" {Street2}";
            }
            result += $", {City ?? ""}, {State} {Zip}";
            if (!string.IsNullOrEmpty(Country))
            {
                result += $", {Country}";
            }
            return result;
        }
    }

    /// <summary>
    /// "securityQuestion" field type
    /// </summary>
    [DataContract]
    public class FieldTypeSecurityQuestion : FieldTypeBase, IFieldTypeSerialize
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
        public IEnumerable<string> Elements => QAElements;

        /// <exclude />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return Question;
                yield return Answer;
            }
        }

        /// <exclude />
        public bool SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "question": Question = value; return true;
                case "answer": Answer = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            Question = "";
            Answer = "";
            if (string.IsNullOrEmpty(value))
            {
                return;
            }
            var pos = value.IndexOf('?');
            if (pos >= 0)
            {
                Question = value.Substring(0, pos).Trim();
                Answer = value.Substring(pos + 1).Trim();
            }
            else
            {
                Question = value;
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }

            var result = (Question ?? "").Replace("?", "") + "?";
            if (!string.IsNullOrEmpty(Answer))
            {
                result += $" {Answer}";
            }
            return result;
        }
    }


    /// <summary>
    /// "bankAccount" field type
    /// </summary>
    [DataContract]
    public class FieldTypeBankAccount : FieldTypeBase, IFieldTypeSerialize
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
        public IEnumerable<string> Elements => AccountElements;

        /// <exclude />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return AccountType;
                yield return RoutingNumber;
                yield return AccountNumber;
            }
        }

        /// <exclude />
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "accountType": AccountType = value; return true;
                case "routingNumber": RoutingNumber = value; return true;
                case "accountNumber": AccountNumber = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            AccountType = "";
            RoutingNumber = "";
            AccountNumber = "";

            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            var pos = value.IndexOf(':');
            if (pos >= 0)
            {
                AccountType = value.Substring(0, pos).Trim();
                value = value.Substring(pos + 1).Trim();
            }
            pos = value.IndexOf(' ');
            if (pos >= 0)
            {
                RoutingNumber = value.Substring(0, pos).Trim();
                AccountNumber = value.Substring(pos + 1).Trim();
            }
            else
            {
                RoutingNumber = value;
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }

            var result = string.IsNullOrEmpty(AccountType) ? "" : $"{AccountType}: ";
            result += string.Join(" ", (new string[] { RoutingNumber, AccountNumber }).Where(x => !string.IsNullOrEmpty(x)));
            return result;
        }
    }

    /// <summary>
    /// "paymentCard" field type
    /// </summary>
    [DataContract]

    public class FieldTypePaymentCard : FieldTypeBase, IFieldTypeSerialize
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

        /// <inheritdoc />
        public IEnumerable<string> Elements => CardElements;

        /// <inheritdoc />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return CardNumber;
                yield return CardExpirationDate;
                yield return CardSecurityCode;
            }
        }

        /// <inheritdoc />
        public bool SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "cardNumber": CardNumber = value; return true;
                case "cardExpirationDate": CardExpirationDate = value; return true;
                case "cardSecurityCode": CardSecurityCode = value; return true;
                default: return false;
            }
        }

        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            CardNumber = "";
            CardExpirationDate = "";
            CardSecurityCode = "";

            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            foreach (var comp in value.Split(' ').Select(x => x.Trim()).Where(x => !string.IsNullOrEmpty(x)))
            {
                if (comp.Length > 10)
                {
                    CardNumber = comp;
                }
                else if (comp.IndexOf('/') >= 0)
                {
                    CardExpirationDate = comp;
                }
                else if (comp.Length < 6)
                {
                    CardSecurityCode = comp;
                }
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }

            return string.Join(" ", (new string[] { CardNumber, CardExpirationDate, CardSecurityCode }).Where(x => !string.IsNullOrEmpty(x)));
        }
    }

    /// <summary>
    /// "keyPair" field type
    /// </summary>
    [DataContract]
    public class FieldTypeKeyPair : FieldTypeBase, IFieldTypeSerialize
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

        /// <inheritdoc />
        public IEnumerable<string> Elements => KeyPairElements;

        /// <inheritdoc />
        public IEnumerable<string> ElementValues
        {
            get
            {
                yield return PublicKey;
                yield return PrivateKey;
            }
        }

        /// <inheritdoc />
        public bool SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "publicKey": PublicKey = value; return true;
                case "privateKey": PrivateKey = value; return true;
                default: return false;
            }
        }

        private const string PUBLIC_KEY = "Public Key:";
        /// <inheritdoc/>
        public void SetValueAsString(string value)
        {
            PrivateKey = "";
            PublicKey = "";

            if (string.IsNullOrEmpty(value))
            {
                return;
            }
            if (value.StartsWith(PUBLIC_KEY))
            {
                PublicKey = value.Substring(PUBLIC_KEY.Length).Trim();
            }
            else
            {
                PrivateKey = value;
            }
        }

        /// <inheritdoc/>
        public string GetValueAsString()
        {
            if (ElementValues.All(x => string.IsNullOrEmpty(x)))
            {
                return "";
            }
            if (string.IsNullOrEmpty(PrivateKey))
            {
                return PrivateKey;
            }

            return $"{PUBLIC_KEY} {PublicKey}";
        }
    }

    [DataContract]
    public class FieldTypeAppFiller : FieldTypeBase, IFieldTypeSerialize
    {
        [DataMember(Name = "applicationTitle", EmitDefaultValue = true)]
        public string ApplicationTitle { get; set; }

        [DataMember(Name = "contentFilter", EmitDefaultValue = true)]
        public string ContentFilter { get; set; }
        [DataMember(Name = "macroSequence", EmitDefaultValue = true)]
        public string MacroSequence { get; set; }


        private static string[] KeyPairElements = new[] { "applicationTitle", "contentFilter", "macroSequence" };
        IEnumerable<string> IFieldTypeSerialize.Elements => KeyPairElements;

        IEnumerable<string> IFieldTypeSerialize.ElementValues
        {
            get
            {
                yield return ApplicationTitle;
                yield return ContentFilter;
                yield return MacroSequence;
            }
        }
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            switch (element)
            {
                case "applicationTitle": { ApplicationTitle = value; return true; }
                case "macroSequence": { MacroSequence = value; return true; }
                case "contentFilter": { ContentFilter = value; return true; }
            }
            return false;
        }

        void IFieldTypeSerialize.SetValueAsString(string value)
        {
            var appFiller = JsonUtils.ParseJson<FieldTypeAppFiller>(Encoding.UTF8.GetBytes(value));
            if (appFiller != null) 
            { 
                ApplicationTitle = appFiller.ApplicationTitle;
                MacroSequence = appFiller.MacroSequence;
                ContentFilter = appFiller.ContentFilter;
            }
        }
        string IFieldTypeSerialize.GetValueAsString()
        {
            var e = (this as IFieldTypeSerialize).ElementValues.ToArray();
            return string.Join("\n", e);
        }
    }

    /// <excluded/>
    [DataContract]
    public class JsonWebKey
    {
        [DataMember(Name = "kty", EmitDefaultValue = true)]
        public string Kty {  get; set; }

        [DataMember(Name = "crv", EmitDefaultValue = true)]
        public string Crv { get; set; }

        [DataMember(Name = "x", EmitDefaultValue = true)]
        public string X { get; set; }

        [DataMember(Name = "y", EmitDefaultValue = true)]
        public string Y { get; set; }

        [DataMember(Name = "kid", EmitDefaultValue = true)]
        public string Kid { get; set; }
    }

    /// <summary>
    /// "passkey" field type
    /// </summary>
    [DataContract]
    public class FieldTypePasskey : FieldTypeBase
    {
        public FieldTypePasskey()
        {
            RelyingParty = "";
            CredentialId = "";
            UserId = "";
            Username = "";
        }

        [DataMember(Name = "privateKey", EmitDefaultValue = true)]
        public JsonWebKey PrivateKey { get; set; }

        /// <summary>
        /// Gets or sets Relying Party
        /// </summary>
        [DataMember(Name = "relyingParty", EmitDefaultValue = true)]
        public string RelyingParty { get; set; }

        /// <summary>
        /// Gets or sets Credential Id
        /// </summary>
        [DataMember(Name = "credentialId", EmitDefaultValue = true)]
        public string CredentialId { get; set; }

        /// <summary>
        /// Gets or sets User Id
        /// </summary>
        [DataMember(Name = "userId", EmitDefaultValue = true)]
        public string UserId { get; set; }

        /// <summary>
        /// Gets or sets Username
        /// </summary>
        [DataMember(Name = "username", EmitDefaultValue = true)]
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets Sign Count
        /// </summary>
        [DataMember(Name = "signCount", EmitDefaultValue = true)]
        public long SignCount { get; set; }

        /// <summary>
        /// Gets or sets Created Date
        /// </summary>
        [DataMember(Name = "createdDate", EmitDefaultValue = true)]
        public long CreatedDate { get; set; }
    }

    public class AnyComplexField : Dictionary<string, string>, IExtensibleDataObject, IFieldTypeSerialize
    {
        public ExtensionDataObject ExtensionData { get; set; }
        IEnumerable<string> IFieldTypeSerialize.Elements
        {
            get
            {
                return this.OrderBy(x => x.Key).Select(x => x.Key);
            }
        }
        public IEnumerable<string> ElementValues
        {
            get
            {
                return this.OrderBy(x => x.Key).Select(x => x.Value);
            }
        }
        bool IFieldTypeSerialize.SetElementValue(string element, string value)
        {
            this[element] = value;
            return true;
        }

        void IFieldTypeSerialize.SetValueAsString(string value)
        {
        }
        string IFieldTypeSerialize.GetValueAsString()
        {
            return string.Join("\n", ElementValues);
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
                new FieldType("text", typeof(string), "''", "plain text"),
                new FieldType("url", typeof(string), "''", "url string, can be clicked"),
                new FieldType("multiline", typeof(string), "''", "multiline text"),
                new FieldType("fileRef", typeof(string), "''", "reference to the file field on another record"),
                new FieldType("email", typeof(string), "''", "valid email address plus tag"),
                new FieldType("host", typeof(FieldTypeHost), "{'hostName': '', 'port': ''}", "multiple fields to capture host information"),
                new FieldType("phone", typeof(FieldTypePhone), "{'region': '', 'number': '', 'ext': '', 'type': ''}", "numbers and symbols only plus tag"),
                new FieldType("name", typeof(FieldTypeName), "{'first': '', 'middle': '', 'last': ''}", "multiple fields to capture name"),
                new FieldType("address", typeof(FieldTypeAddress), "{'street1': '', 'street2': '', 'city': '', 'state': '', 'zip': '', 'country': ''}", "multiple fields to capture address"),
                new FieldType("addressRef", typeof(string), "''", "reference to the address field on another record"),
                new FieldType("cardRef", typeof(string), "''", "reference to the card record type"),
                new FieldType("secret", typeof(string), "''", "the field value is masked"),
                new FieldType("login", typeof(string), "''", "Login field, detected as the website login for browser extension or KFFA."),
                new FieldType("password", typeof(string), "''", "Field value is masked and allows for generation. Also complexity enforcements."),
                new FieldType("securityQuestion", typeof(FieldTypeSecurityQuestion), "{'question': '', 'answer': ''}", "Security Question and Answer"),
                new FieldType("otp", typeof(string), "''", "captures the seed, displays QR code"),
                new FieldType("paymentCard", typeof(FieldTypePaymentCard), "{'cardNumber': '', 'cardExpirationDate': '', 'cardSecurityCode': ''}", "Field consisting of validated card number, expiration date and security code."),
                new FieldType("date", typeof(long), "0", "calendar date with validation, stored as unix milliseconds"),
                new FieldType("bankAccount", typeof(FieldTypeBankAccount), "{'accountType': '', 'routingNumber': '', 'accountNumber': '', 'otherType': ''}", "bank account information"),
                new FieldType("privateKey", typeof(FieldTypeKeyPair), "{'publicKey': '', 'privateKey': ''}", "private and/or public keys in ASN.1 format"),
                new FieldType("passkey", typeof(JsonWebKey), "{'privateKey': {}, 'credentialId': '', 'signCount': 0, 'userId': '', 'relyingParty': '', 'username': '', 'createdDate': 0}", "passwordless login passkey"),
                new FieldType("checkbox", typeof(bool), "false", "on/off checkbox"),
                new FieldType("dropdown", typeof(string), "''", "list of text choices"),
                new FieldType("appFiller", typeof(FieldTypeAppFiller), "{'macroSequence': '', 'applicationTitle': '', 'contentFilter': ''}", "native application filler"),
            };

            foreach (var t in types)
            {
                _fieldTypes.Add(t.Name, t);
            }

            var fields = new[]
            {
                new RecordField("login", _fieldTypes["login"], RecordFieldMultiple.Never),
                new RecordField("password", _fieldTypes["password"], RecordFieldMultiple.Never),
                new RecordField("company", _fieldTypes["text"], RecordFieldMultiple.Never),
                new RecordField("licenseNumber", _fieldTypes["multiline"], RecordFieldMultiple.Never),
                new RecordField("accountNumber", _fieldTypes["text"], RecordFieldMultiple.Never),
                new RecordField("bankAccount", _fieldTypes["bankAccount"], RecordFieldMultiple.Never),
                new RecordField("note", _fieldTypes["multiline"], RecordFieldMultiple.Never),
                new RecordField("oneTimeCode", _fieldTypes["otp"], RecordFieldMultiple.Never),
                new RecordField("keyPair", _fieldTypes["privateKey"], RecordFieldMultiple.Never),
                new RecordField("pinCode", _fieldTypes["secret"], RecordFieldMultiple.Never),
                new RecordField("expirationDate", _fieldTypes["date"], RecordFieldMultiple.Never),
                new RecordField("birthDate", _fieldTypes["date"], RecordFieldMultiple.Never),
                new RecordField("text", _fieldTypes["text"]),
                new RecordField("name", _fieldTypes["name"]),
                new RecordField("phone", _fieldTypes["phone"]),
                new RecordField("email", _fieldTypes["email"]),
                new RecordField("address", _fieldTypes["address"]),
                new RecordField("addressRef", _fieldTypes["addressRef"]),
                new RecordField("date", _fieldTypes["date"]),
                new RecordField("paymentCard", _fieldTypes["paymentCard"]),
                new RecordField("cardRef", _fieldTypes["cardRef"]),
                new RecordField("url", _fieldTypes["url"]),
                new RecordField("host", _fieldTypes["host"]),
                new RecordField("secret", _fieldTypes["secret"]),
                new RecordField("securityQuestion", _fieldTypes["securityQuestion"], RecordFieldMultiple.Always),
                new RecordField("fileRef", _fieldTypes["fileRef"], RecordFieldMultiple.Always),
            };
            foreach (var rf in fields)
            {
                _recordFields.Add(rf.Name, rf);
            }
            foreach (var ft in _fieldTypes.Values)
            {
                if (!_recordFields.ContainsKey(ft.Name))
                {
                    _recordFields.Add(ft.Name, new RecordField(ft.Name, ft));
                }
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
    internal class PasswordFieldComplexity
    {
        [DataMember(Name = "length")]
        public int Length { get; set; }
        [DataMember(Name = "caps")]
        public int Upper { get; set; }
        [DataMember(Name = "lowercase")]
        public int Lower { get; set; }
        [DataMember(Name = "digits")]
        public int Digit { get; set; }
        [DataMember(Name = "special")]
        public int Special { get; set; }
    }

    [DataContract]
    internal class RecordTypeContentField
    {
        [DataMember(Name = "$ref")]
        public string Ref { get; set; }

        [DataMember(Name = "label")]
        public string Label { get; set; }

        [DataMember(Name = "required")]
        public bool? Required { get; set; }

        [DataMember(Name = "complexity")]
        public PasswordFieldComplexity Complexity { get; set; }
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
        public double? LastModified { get; set; }
    }

    [DataContract]
    internal class RecordApplicationData
    {
        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }
    }
}
