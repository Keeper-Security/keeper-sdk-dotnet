using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;

namespace KeeperSecurity.Commands
{
    /// <summary>
    /// Typed JSON node used when parsing import/PowerShell payloads.
    /// </summary>
    public sealed class ImportJsonValue
    {
        /// <summary>
        /// What kind of JSON value this node holds.
        /// </summary>
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

        /// <summary>
        /// Discriminator for which value field is populated.
        /// </summary>
        public JsonKind Kind { get; }

        /// <summary>
        /// String payload when <see cref="Kind"/> is <see cref="JsonKind.String"/>.
        /// </summary>
        public string StringValue { get; private set; }

        /// <summary>
        /// Boolean payload when <see cref="Kind"/> is <see cref="JsonKind.Boolean"/>.
        /// </summary>
        public bool BooleanValue { get; private set; }

        /// <summary>
        /// Number payload when <see cref="Kind"/> is <see cref="JsonKind.Number"/>.
        /// </summary>
        public double NumberValue { get; private set; }

        /// <summary>
        /// Object properties when <see cref="Kind"/> is <see cref="JsonKind.Object"/>.
        /// </summary>
        public IReadOnlyDictionary<string, ImportJsonValue> ObjectValue { get; private set; }

        /// <summary>
        /// Array items when <see cref="Kind"/> is <see cref="JsonKind.Array"/>.
        /// </summary>
        public IReadOnlyList<ImportJsonValue> ArrayValue { get; private set; }

        /// <summary>
        /// Shared null node. Used when a field is omitted.
        /// </summary>
        public static ImportJsonValue Null { get; } = new ImportJsonValue(JsonKind.Null);

        /// <summary>
        /// Builds a string node. Null becomes <see cref="Null"/>; empty string is kept.
        /// </summary>
        public static ImportJsonValue FromString(string value) =>
            value == null
                ? Null
                : new ImportJsonValue(JsonKind.String) { StringValue = value };

        /// <summary>
        /// Builds a boolean node.
        /// </summary>
        public static ImportJsonValue FromBoolean(bool value) =>
            new ImportJsonValue(JsonKind.Boolean) { BooleanValue = value };

        /// <summary>
        /// Builds a number node.
        /// </summary>
        public static ImportJsonValue FromNumber(double value) =>
            new ImportJsonValue(JsonKind.Number) { NumberValue = value };

        /// <summary>
        /// Builds an object node from a property map.
        /// </summary>
        public static ImportJsonValue FromObject(IDictionary<string, ImportJsonValue> value) =>
            new ImportJsonValue(JsonKind.Object)
            {
                ObjectValue = value == null
                    ? new Dictionary<string, ImportJsonValue>()
                    : new Dictionary<string, ImportJsonValue>(value),
            };

        /// <summary>
        /// Builds an array node from a list of values.
        /// </summary>
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
        /// Converts untyped JSON (C# parsers, samples, PowerShell) into <see cref="ImportJsonValue"/>.
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
                    // Keep the exact digits as a string (safer for UIDs).
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

        /// <summary>
        /// Returns a string view of this value, or null for null/object/array.
        /// </summary>
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

        /// <summary>
        /// Tries to read this value as a boolean. Returns null when it can't.
        /// </summary>
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

        /// <summary>
        /// Converts back to the older untyped object/dictionary shape for callers that still need it.
        /// </summary>
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
