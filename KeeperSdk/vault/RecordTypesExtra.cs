using System;
using System.Collections.Generic;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <exclude />
    public class TypedRecordFields
    {
        private List<ITypedField> _overflow;

        protected internal virtual void LoadTypedField(ITypedField field)
        {
            if (_overflow == null)
            {
                _overflow = new List<ITypedField>();
            }

            _overflow.Add(field);
        }

        protected internal virtual IEnumerable<ITypedField> CreateMissingFields()
        {
            yield break;
        }

        protected internal virtual string RecordType => null;
    }

    /// <exclude />
    public class TypedRecordFacade<T> where T : TypedRecordFields, new()
    {
        private readonly TypedRecord _typedRecord;

        public TypedRecordFacade(TypedRecord record = null)
        {
            Fields = new T();
            _typedRecord = record ?? new TypedRecord(Fields.RecordType);

            foreach (var field in _typedRecord.Fields)
            {
                Fields.LoadTypedField(field);
            }

            _typedRecord.Fields.AddRange(Fields.CreateMissingFields());
        }

        public TypedRecord TypedRecord => _typedRecord;
        public T Fields { get; }
        public IList<ITypedField> Custom => _typedRecord.Custom;
    }

    /// <exclude />
    public class TypedRecordFileRef : TypedRecordFields
    {
        public TypedField<string> FileRef { get; private set; }

        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "fileRef" && FileRef == null)
            {
                FileRef = field as TypedField<string>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (FileRef == null)
            {
                FileRef = new TypedField<string>("fileRef");
                yield return FileRef;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }
    }

    /// <exclude />
    public class AddressRecordType : TypedRecordFileRef
    {
        private TypedField<FieldTypeAddress> _address;

        public FieldTypeAddress Address => _address.TypedValue;

        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "address" && _address == null)
            {
                _address = field as TypedField<FieldTypeAddress>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (_address == null)
            {
                _address = new TypedField<FieldTypeAddress>("address");
                yield return _address;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }

        protected internal override string RecordType => "address";
    }

    /// <exclude />
    public class PersonBirthDateRecordType : TypedRecordFileRef
    {
        private TypedField<FieldTypeName> _name;
        private TypedField<long> _birthDate;

        public FieldTypeName Name => _name.TypedValue;

        public DateTimeOffset BirthDate
        {
            get => DateTimeOffsetExtensions.FromUnixTimeMilliseconds(_birthDate.TypedValue);
            set => _birthDate.TypedValue = value.ToUnixTimeMilliseconds();
        }

        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "name" && _name == null)
            {
                _name = field as TypedField<FieldTypeName>;
            }
            else if (field.FieldName == "birthDate" && _birthDate == null)
            {
                _birthDate = field as TypedField<long>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (_name == null)
            {
                _name = new TypedField<FieldTypeName>("name");
                yield return _name;
            }

            if (_birthDate == null)
            {
                _birthDate = new TypedField<long>("birthDate");
                yield return _birthDate;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }
    }


    /// <exclude />
    public class PassportRecordType : PersonBirthDateRecordType
    {
        private TypedField<string> _passportNumber;
        private TypedField<long> _expirationDate;
        private TypedField<long> _dateIssued;
        private TypedField<string> _password;
        private TypedField<string> _addressRef;

        public string PassportNumber
        {
            get => _passportNumber.TypedValue;
            set => _passportNumber.TypedValue = value;
        }

        public DateTimeOffset ExpirationDate
        {
            get => DateTimeOffsetExtensions.FromUnixTimeMilliseconds(_expirationDate.TypedValue);
            set => _expirationDate.TypedValue = value.ToUnixTimeMilliseconds();
        }

        public DateTimeOffset DateIssued
        {
            get => DateTimeOffsetExtensions.FromUnixTimeMilliseconds(_dateIssued.TypedValue);
            set => _dateIssued.TypedValue = value.ToUnixTimeMilliseconds();
        }

        public string Password
        {
            get => _password.TypedValue;
            set => _password.TypedValue = value;
        }

        public string AddressRef
        {
            get => _addressRef.TypedValue;
            set => _addressRef.TypedValue = value;
        }

        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "accountNumber" && field.FieldLabel == "passportNumber" && _passportNumber == null)
            {
                _passportNumber = field as TypedField<string>;
            }
            else if (field.FieldName == "expirationDate" && _expirationDate == null)
            {
                _expirationDate = field as TypedField<long>;
            }
            else if (field.FieldName == "date" && field.FieldLabel == "dateIssued" && _dateIssued == null)
            {
                _dateIssued = field as TypedField<long>;
            }
            else if (field.FieldName == "password" && _password == null)
            {
                _password = field as TypedField<string>;
            }
            else if (field.FieldName == "addressRef" && _addressRef == null)
            {
                _addressRef = field as TypedField<string>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (_passportNumber == null)
            {
                _passportNumber = new TypedField<string>("accountNumber", "passportNumber");
                yield return _passportNumber;
            }

            if (_expirationDate == null)
            {
                _expirationDate = new TypedField<long>("expirationDate");
                yield return _expirationDate;
            }

            if (_dateIssued == null)
            {
                _dateIssued = new TypedField<long>("date", "dateIssued");
                yield return _dateIssued;
            }

            if (_password == null)
            {
                _password = new TypedField<string>("password");
                yield return _password;
            }

            if (_addressRef == null)
            {
                _addressRef = new TypedField<string>("addressRef");
                yield return _addressRef;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }
        protected internal override string RecordType => "passport";
    }

    /// <exclude />
    public class DriverLicenseRecordType : PersonBirthDateRecordType
    {
        private TypedField<string> _dlNumber;
        private TypedField<long> _expirationDate;
        private TypedField<string> _addressRef;

        public string DlNumber
        {
            get => _dlNumber.TypedValue;
            set => _dlNumber.TypedValue = value;
        }

        public DateTimeOffset ExpirationDate
        {
            get => DateTimeOffsetExtensions.FromUnixTimeMilliseconds(_expirationDate.TypedValue);
            set => _expirationDate.TypedValue = value.ToUnixTimeMilliseconds();
        }

        public string AddressRef
        {
            get => _addressRef.TypedValue;
            set => _addressRef.TypedValue = value;
        }


        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "accountNumber" && field.FieldLabel == "dlNumber" && _dlNumber == null)
            {
                _dlNumber = field as TypedField<string>;
            }
            else if (field.FieldName == "expirationDate" && _expirationDate == null)
            {
                _expirationDate = field as TypedField<long>;
            }
            else if (field.FieldName == "addressRef" && _addressRef == null)
            {
                _addressRef = field as TypedField<string>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (_dlNumber == null)
            {
                _dlNumber = new TypedField<string>("accountNumber", "dlNumber");
                yield return _dlNumber;
            }

            if (_expirationDate == null)
            {
                _expirationDate = new TypedField<long>("expirationDate");
                yield return _expirationDate;
            }

            if (_addressRef == null)
            {
                _addressRef = new TypedField<string>("addressRef");
                yield return _addressRef;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }
        protected internal override string RecordType => "driverLicense";
    }

    /// <exclude />
    public class LoginRecordType : TypedRecordFileRef
    {
        private TypedField<string> _login;
        private TypedField<string> _password;
        private TypedField<string> _url;
        private TypedField<string> _oneTimeCode;

        public string Login
        {
            get => _login.TypedValue;
            set => _login.TypedValue = value;
        }

        public string Password
        {
            get => _password.TypedValue;
            set => _password.TypedValue = value;
        }

        public string Url
        {
            get => _url.TypedValue;
            set => _url.TypedValue = value;
        }

        public string OneTimeCode
        {
            get => _oneTimeCode.TypedValue;
            set => _oneTimeCode.TypedValue = value;
        }

        protected internal override void LoadTypedField(ITypedField field)
        {
            if (field.FieldName == "login" && _login == null)
            {
                _login = field as TypedField<string>;
            }
            else if (field.FieldName == "password" && _password == null)
            {
                _password = field as TypedField<string>;
            }
            else if (field.FieldName == "url" && _url == null)
            {
                _url = field as TypedField<string>;
            }
            else if (field.FieldName == "oneTimeCode" && _oneTimeCode == null)
            {
                _oneTimeCode = field as TypedField<string>;
            }
            else
            {
                base.LoadTypedField(field);
            }
        }

        protected internal override IEnumerable<ITypedField> CreateMissingFields()
        {
            if (_login == null)
            {
                _login = new TypedField<string>("login");
                yield return _login;
            }

            if (_password == null)
            {
                _password = new TypedField<string>("password");
                yield return _password;
            }

            if (_url == null)
            {
                _url = new TypedField<string>("url");
                yield return _url;
            }

            if (_oneTimeCode == null)
            {
                _oneTimeCode = new TypedField<string>("oneTimeCode");
                yield return _oneTimeCode;
            }

            foreach (var f in base.CreateMissingFields())
            {
                yield return f;
            }
        }

        protected internal override string RecordType => "login";
    }
}
