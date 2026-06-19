using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace KeeperSecurity.Utils
{
    internal static class PassphraseWordList
    {
        internal const int Count = 7776;

        private const string ResourceName = "KeeperSecurity.utils.eff_words.txt.gz";

        private static readonly Lazy<IReadOnlyList<string>> _lazyWords =
            new(LoadCompressedWordList);

        internal static IReadOnlyList<string> Words => _lazyWords.Value;

        private static IReadOnlyList<string> LoadCompressedWordList()
        {
            var assembly = typeof(PassphraseWordList).GetTypeInfo().Assembly;
            using var compressedStream = assembly.GetManifestResourceStream(ResourceName);
            if (compressedStream == null)
            {
                throw new InvalidOperationException("Embedded EFF wordlist resource not found.");
            }

            using var decompressor = new GZipStream(compressedStream, CompressionMode.Decompress);
            using var reader = new StreamReader(decompressor);

            var wordList = new List<string>(Count);
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Length > 0)
                {
                    wordList.Add(line);
                }
            }

            if (wordList.Count == 0)
            {
                throw new InvalidOperationException("Passphrase word list is empty or invalid.");
            }

            return wordList.AsReadOnly();
        }
    }
}