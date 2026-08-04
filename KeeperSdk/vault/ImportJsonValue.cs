using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;

namespace KeeperSecurity.Commands
{
    /// <summary>
    /// One JSON value from an import file or PowerShell payload.
    /// Numbers coming from dictionaries / ConvertFrom-Json are kept as text so large UIDs
    /// don't lose digits. Prefer AsString() when reading a value.
    /// </summary>
    public sealed class ImportJsonValue
    {
        /// <summary>Kind of value stored in this node.</summary>
        public enum JsonKind
        {
            Null,
            String,
            Boolean,
            Number,
            Object,
            Array,
        }

        private ImportJsonValue(JsonKind kind)
        {
            Kind = kind;
        }

        /// <summary>Which payload field is in use.</summary>
        public JsonKind Kind { get; }

        /// <summary>Text when Kind is String.</summary>
        public string StringValue { get; private set; }

        /// <summary>True/false when Kind is Boolean.</summary>
        public bool BooleanValue { get; private set; }

        /// <summary>
        /// Number when Kind is Number.
        /// Most import paths store numbers as text instead (see class summary).
        /// </summary>
        public double NumberValue { get; private set; }

        /// <summary>Properties when Kind is Object.</summary>
        public IReadOnlyDictionary<string, ImportJsonValue> ObjectValue { get; private set; }

        /// <summary>Items when Kind is Array.</summary>
        public IReadOnlyList<ImportJsonValue> ArrayValue { get; private set; }

        /// <summary>Shared null node for missing values.</summary>
        public static ImportJsonValue Null { get; } = new ImportJsonValue(JsonKind.Null);

        /// <summary>Creates a string node. Null input becomes Null; empty string is kept.</summary>
        public static ImportJsonValue FromString(string value) =>
            value == null
                ? Null
                : new ImportJsonValue(JsonKind.String) { StringValue = value };

        /// <summary>Creates a boolean node.</summary>
        public static ImportJsonValue FromBoolean(bool value) =>
            new ImportJsonValue(JsonKind.Boolean) { BooleanValue = value };

        /// <summary>
        /// Creates a Number node.
        /// For UIDs or other values that need exact digits, use FromString instead.
        /// Import code does not use this — it turns numbers into strings.
        /// </summary>
        public static ImportJsonValue FromNumber(double value) =>
            new ImportJsonValue(JsonKind.Number) { NumberValue = value };

        /// <summary>Creates an object node from a property map.</summary>
        public static ImportJsonValue FromObject(IDictionary<string, ImportJsonValue> value) =>
            new ImportJsonValue(JsonKind.Object)
            {
                ObjectValue = value == null
                    ? new Dictionary<string, ImportJsonValue>()
                    : new Dictionary<string, ImportJsonValue>(value),
            };

        /// <summary>Creates an array node from a list of values.</summary>
        public static ImportJsonValue FromArray(IList<ImportJsonValue> value)
        {
            if (value == null || value.Count == 0)
            {
                return new ImportJsonValue(JsonKind.Array) { ArrayValue = Array.Empty<ImportJsonValue>() };
            }

            var items = new ImportJsonValue[value.Count];
            for (var i = 0; i < value.Count; i++)
            {
                items[i] = value[i];
            }

            return new ImportJsonValue(JsonKind.Array) { ArrayValue = items };
        }

        /// <summary>
        /// Turns plain objects (dictionaries, PowerShell, samples) into ImportJsonValue.
        /// Numbers are stored as strings so digits stay exact.
        /// </summary>
        public static ImportJsonValue FromLegacyObject(object value)
        {
            if (value == null)
            {
                return Null;
            }

            value = UnwrapLegacyInteropValue(value);
            if (value == null)
            {
                return Null;
            }

            switch (value)
            {
                case string s:
                    return FromString(s);
                case bool b:
                    return FromBoolean(b);
                case byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal:
                    // Keep digits as text — safer for UIDs than storing as double.
                    return FromString(Convert.ToString(value, CultureInfo.InvariantCulture));
                case ImportJsonValue already:
                    return already;
            }

            if (value is IDictionary<string, ImportJsonValue> typedJson)
            {
                return FromObject(typedJson);
            }

            if (value is IDictionary<string, object> typed)
            {
                var map = new Dictionary<string, ImportJsonValue>(typed.Count);
                foreach (var pair in typed)
                {
                    map[pair.Key] = FromLegacyObject(pair.Value);
                }

                return FromObject(map);
            }

            if (value is IDictionary dictionary)
            {
                var map = new Dictionary<string, ImportJsonValue>();
                foreach (DictionaryEntry entry in dictionary)
                {
                    if (entry.Key is not string key)
                    {
                        continue;
                    }

                    map[key] = FromLegacyObject(entry.Value);
                }

                return FromObject(map);
            }

            if (value is Array array)
            {
                var items = new ImportJsonValue[array.Length];
                for (var i = 0; i < array.Length; i++)
                {
                    items[i] = FromLegacyObject(array.GetValue(i));
                }

                return FromArray(items);
            }

            if (value is IEnumerable enumerable and not string)
            {
                var items = new List<ImportJsonValue>();
                foreach (var item in enumerable)
                {
                    items.Add(FromLegacyObject(item));
                }

                return FromArray(items);
            }

            return FromString(value.ToString());
        }

        /// <summary>Text form of this value, or null for null / object / array.</summary>
        public string AsString()
        {
            return Kind switch
            {
                JsonKind.Null => null,
                JsonKind.String => StringValue,
                JsonKind.Boolean => BooleanValue ? "true" : "false",
                JsonKind.Number => NumberValue.ToString(CultureInfo.InvariantCulture),
                _ => null,
            };
        }

        /// <summary>Reads this as a boolean when possible; otherwise null.</summary>
        public bool? AsBoolean()
        {
            return Kind switch
            {
                JsonKind.Boolean => BooleanValue,
                JsonKind.Number => NumberValue != 0,
                JsonKind.String when bool.TryParse(StringValue, out var b) => b,
                JsonKind.String when StringValue == "1" => true,
                JsonKind.String when StringValue == "0" => false,
                _ => null,
            };
        }

        /// <summary>Converts back to a plain object / dictionary for older callers.</summary>
        public object ToLegacyObject()
        {
            switch (Kind)
            {
                case JsonKind.Null:
                    return null;
                case JsonKind.String:
                    return StringValue;
                case JsonKind.Boolean:
                    return BooleanValue;
                case JsonKind.Number:
                    return NumberValue;
                case JsonKind.Object:
                {
                    var dict = new Dictionary<string, object>();
                    if (ObjectValue != null)
                    {
                        foreach (var pair in ObjectValue)
                        {
                            dict[pair.Key] = pair.Value?.ToLegacyObject();
                        }
                    }

                    return dict;
                }
                case JsonKind.Array:
                {
                    if (ArrayValue == null || ArrayValue.Count == 0)
                    {
                        return Array.Empty<object>();
                    }

                    var items = new object[ArrayValue.Count];
                    for (var i = 0; i < ArrayValue.Count; i++)
                    {
                        items[i] = ArrayValue[i]?.ToLegacyObject();
                    }

                    return items;
                }
                default:
                    return null;
            }
        }

        // Peel PowerShell PSObject wrappers so we get the real BaseObject.
        private static object UnwrapLegacyInteropValue(object value)
        {
            while (value != null)
            {
                var type = value.GetType();
                if (!string.Equals(type.FullName, "System.Management.Automation.PSObject", StringComparison.Ordinal))
                {
                    return value;
                }

                var baseObject = type.GetProperty("BaseObject")?.GetValue(value);
                if (baseObject == null || ReferenceEquals(baseObject, value))
                {
                    return value;
                }

                value = baseObject;
            }

            return null;
        }
    }
}
