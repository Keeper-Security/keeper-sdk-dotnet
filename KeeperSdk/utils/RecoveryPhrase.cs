using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeeperSecurity.Utils
{
    internal static class RecoveryPhraseWordList
    {
        internal const int Count = 2048;

        private const string ResourceName = "KeeperSecurity.utils.recovery_phrase_words.txt.gz";

        private static readonly Lazy<IReadOnlyList<string>> _lazyWords =
            new(LoadCompressedWordList);

        private static readonly Lazy<HashSet<string>> _lazyWordSet =
            new(() => new HashSet<string>(Words, StringComparer.Ordinal));

        internal static IReadOnlyList<string> Words => _lazyWords.Value;

        internal static bool Contains(string word) => _lazyWordSet.Value.Contains(word);

        private static IReadOnlyList<string> LoadCompressedWordList()
        {
            var assembly = typeof(RecoveryPhraseWordList).GetTypeInfo().Assembly;
            using var compressedStream = assembly.GetManifestResourceStream(ResourceName);
            if (compressedStream == null)
            {
                throw new InvalidOperationException("Embedded recovery phrase wordlist resource not found.");
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

            if (wordList.Count != Count)
            {
                throw new InvalidOperationException("Recovery phrase word list is invalid.");
            }

            return wordList.AsReadOnly();
        }
    }

    /// <summary>
    /// Generates and derives keys from an Account Recovery Phrase (24-word mnemonic).
    /// </summary>
    public static class RecoveryPhrase
    {
        /// <summary>
        /// Number of words in a recovery phrase.
        /// </summary>
        public const int WordCount = 24;

        private const string RecoveryKeyInfo = "recovery_key_aes_gcm_256";
        private const string RecoveryAuthTokenInfo = "recovery_auth_token";

        /// <summary>
        /// Generates a new 24-word recovery phrase using a cryptographically secure random source.
        /// </summary>
        /// <returns>Recovery phrase.</returns>
        public static string Generate()
        {
            var words = RecoveryPhraseWordList.Words;
            var sb = new StringBuilder();
            for (var i = 0; i < WordCount; i++)
            {
                var index = NextWordIndex(words.Count);
                if (i > 0)
                {
                    sb.Append(' ');
                }

                sb.Append(words[index]);
            }

            return sb.ToString();
        }

        // 65536 (2 random bytes) is an exact multiple of the wordlist size (2048),
        // so taking the value mod wordCount introduces no modulo bias.
        private static int NextWordIndex(int wordCount)
        {
            var bytes = CryptoUtils.GetRandomBytes(2);
            var value = (bytes[0] << 8) | bytes[1];
            return value % wordCount;
        }

        /// <summary>
        /// Cleans up a user-typed recovery phrase: trims, collapses whitespace, and lower-cases it.
        /// </summary>
        /// <param name="phrase">Recovery phrase as entered by the user.</param>
        /// <returns>Normalized recovery phrase.</returns>
        /// <exception cref="ArgumentException">The phrase does not contain exactly <see cref="WordCount"/> words.</exception>
        public static string Normalize(string phrase)
        {
            if (phrase == null) throw new ArgumentNullException(nameof(phrase));

            var words = phrase
                .Split((char[]) null, StringSplitOptions.RemoveEmptyEntries)
                .Select(w => w.ToLowerInvariant())
                .ToArray();

            if (words.Length != WordCount)
            {
                throw new ArgumentException($"Recovery phrase must contain exactly {WordCount} words.", nameof(phrase));
            }

            if (words.Any(word => !RecoveryPhraseWordList.Contains(word)))
            {
                throw new ArgumentException("Recovery phrase contains a word that is not in the recovery phrase word list.", nameof(phrase));
            }

            return string.Join(" ", words);
        }

        /// <summary>
        /// Derives the recovery key used to encrypt/decrypt the vault data key.
        /// </summary>
        /// <param name="normalizedPhrase">A normalized recovery phrase. See <see cref="Normalize"/>.</param>
        /// <returns>32 byte recovery key.</returns>
        public static byte[] DeriveRecoveryKey(string normalizedPhrase)
        {
            var ikm = Encoding.UTF8.GetBytes(normalizedPhrase);
            return CryptoUtils.DeriveHkdfSha512(ikm, Encoding.UTF8.GetBytes(RecoveryKeyInfo), 32);
        }

        /// <summary>
        /// Derives the recovery authentication token sent to the server to prove knowledge of the recovery phrase.
        /// </summary>
        /// <param name="normalizedPhrase">A normalized recovery phrase. See <see cref="Normalize"/>.</param>
        /// <returns>32 byte recovery authentication token.</returns>
        public static byte[] DeriveRecoveryAuthToken(string normalizedPhrase)
        {
            var ikm = Encoding.UTF8.GetBytes(normalizedPhrase);
            return CryptoUtils.DeriveHkdfSha512(ikm, Encoding.UTF8.GetBytes(RecoveryAuthTokenInfo), 32);
        }
    }
}
