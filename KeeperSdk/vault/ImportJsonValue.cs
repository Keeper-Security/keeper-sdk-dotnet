using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;

namespace KeeperSecurity.Commands
{
    /// <summary>
    /// Typed JSON value used at the PowerShell/import parse boundary
    /// (replaces loose <c>object</c> / untyped dictionaries for <see cref="Vault.KeeperImport.LoadJsonDictionary(ImportJsonValue)"/>).
    /// </summary>
    public sealed class ImportJsonValue
    {
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

        public JsonKind Kind { get; }

        public string StringValue { get; private set; }

        public bool BooleanValue { get; private set; }

        public double NumberValue { get; private set; }

        public IReadOnlyDictionary<string, ImportJsonValue> ObjectValue { get; private set; }

        public IReadOnlyList<ImportJsonValue> ArrayValue { get; private set; }

        public static ImportJsonValue Null { get; } = new ImportJsonValue(JsonKind.Null);

        /// <summary>
        /// Creates a string value. <paramref name="value"/> null becomes <see cref="Null"/>
        /// (omit); empty string is preserved (clear).
        /// </summary>
        public static ImportJsonValue FromString(string value) =>
            value == null
                ? Null
                : new ImportJsonValue(JsonKind.String) { StringValue = value };

        public static ImportJsonValue FromBoolean(bool value) =>
            new ImportJsonValue(JsonKind.Boolean) { BooleanValue = value };

        public static ImportJsonValue FromNumber(double value) =>
            new ImportJsonValue(JsonKind.Number) { NumberValue = value };

        public static ImportJsonValue FromObject(IDictionary<string, ImportJsonValue> value) =>
            new ImportJsonValue(JsonKind.Object)
            {
                ObjectValue = value == null
                    ? new Dictionary<string, ImportJsonValue>()
                    : new Dictionary<string, ImportJsonValue>(value),
            };

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
        /// Converts a legacy untyped dictionary (C# JSON parsers / samples) into <see cref="ImportJsonValue"/>.
        /// Numeric values are stored as strings to avoid double precision loss (e.g. large UIDs).
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
                    // Keep exact decimal representation as string (uid-safe).
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
