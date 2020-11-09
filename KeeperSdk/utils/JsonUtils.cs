//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

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
        /// <returns>JSON data.</returns>
        public static byte[] DumpJson<T>(T obj)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, false, true))
                {
                    serializer.WriteObject(writer, obj);
                }

                return ms.ToArray();
            }
        }
    }
}
