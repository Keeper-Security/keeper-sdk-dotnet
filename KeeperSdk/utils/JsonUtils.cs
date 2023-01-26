using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace KeeperSecurity.Utils
{
    /// <summary>
    ///     Provides methods for JSON (de)serialization.
    /// </summary>
    public static class JsonUtils
    {
        internal static readonly DataContractJsonSerializerSettings JsonSettings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true,
            EmitTypeInformation = EmitTypeInformation.Never
        };

        /// <summary>
        ///     Deserializes JSON data.
        /// </summary>
        /// <typeparam name="T">Type of JSON object.</typeparam>
        /// <param name="json">JSON data.</param>
        /// <returns>Parsed JSON object.</returns>
        public static T ParseJson<T>(byte[] json)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream(json))
            {
                return (T) serializer.ReadObject(ms);
            }
        }

        /// <summary>
        ///     Serializes object to JSON  format.
        /// </summary>
        /// <typeparam name="T">Type of JSON object.</typeparam>
        /// <param name="obj">JSON object.</param>
        /// <param name="indent">Pretty print</param>
        /// <returns>JSON data.</returns>
        public static byte[] DumpJson<T>(T obj, bool indent = true)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, false, indent))
                {
                    serializer.WriteObject(writer, obj);
                }

                return ms.ToArray();
            }
        }
    }

    /// <exclude />
    public static class StringUtils
    {
        public static string ToSnakeCase(this string text)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < text.Length; i++)
            {
                var ch = text[i];
                if (char.IsUpper(ch) && i > 0)
                {
                    sb.Append('_');
                    sb.Append(char.ToLower(ch));
                }
                else
                {
                    sb.Append(ch);
                }
            }

            return sb.ToString();
        }

        public static string StripUrl(this string url)
        {
            try
            {
                var builder = new UriBuilder(url);
                return builder.Host + builder.Path;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                return url;
            }
        }
    }

}
