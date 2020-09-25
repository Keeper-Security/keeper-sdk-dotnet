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

namespace KeeperSecurity.Sdk
{
    public static class JsonUtils
    {
        public static readonly DataContractJsonSerializerSettings JsonSettings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true,
            EmitTypeInformation = EmitTypeInformation.Never,
        };

        public static T ParseJson<T>(byte[] json)
        {
            var serializer = new DataContractJsonSerializer(typeof(T), JsonSettings);
            using (var ms = new MemoryStream(json))
            {
                return (T) serializer.ReadObject(ms);
            }
        }

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