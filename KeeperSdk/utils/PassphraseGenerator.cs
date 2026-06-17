using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KeeperSecurity.Utils
{
    /// <summary>
    /// Generates random passphrases from a dictionary word list.
    /// </summary>
    public static class PassphraseGenerator
    {
        /// <summary>
        /// Minimum number of words allowed in a passphrase.
        /// </summary>
        public const int MinWordCount = 5;

        /// <summary>
        /// Maximum number of words allowed in a passphrase.
        /// </summary>
        public const int MaxWordCount = 9;

        /// <summary>
        /// Allowed separators between passphrase words.
        /// </summary>
        public static readonly string[] AllowedSeparators = { "-", ".", "_", "!", "?", " " };

        /// <summary>
        /// Validates the number of words in a passphrase.
        /// </summary>
        /// <param name="wordCount">Requested word count.</param>
        /// <returns>Validated word count.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Word count is outside the allowed range.</exception>
        public static int ValidateWordCount(int wordCount)
        {
            if (wordCount < MinWordCount || wordCount > MaxWordCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(wordCount),
                    wordCount,
                    $"Passphrase word count must be between {MinWordCount} and {MaxWordCount}.");
            }

            return wordCount;
        }

        /// <summary>
        /// Validates and returns a passphrase separator.
        /// </summary>
        /// <param name="separator">Requested separator. Defaults to "-" when null or empty.</param>
        /// <returns>Validated separator.</returns>
        /// <exception cref="ArgumentException">Separator is not allowed.</exception>
        public static string ValidateSeparator(string separator)
        {
            if (string.IsNullOrEmpty(separator))
            {
                return "-";
            }

            foreach (var allowed in AllowedSeparators)
            {
                if (separator == allowed)
                {
                    return allowed;
                }
            }

            throw new ArgumentException(
                "Passphrase separator must be one of: '-', '.', '_', '!', '?', ' '.",
                nameof(separator));
        }

        /// <summary>
        /// Generates a random passphrase, loading the word list on first use (lazy-loaded and cached).
        /// </summary>
        public static string GeneratePassphrase(PassphraseGenerationOptions options = null)
        {
            return GeneratePassphrase(PassphraseWordList.Words, options);
        }

        /// <summary>
        /// Generates a random passphrase from a loaded word list.
        /// </summary>
        public static string GeneratePassphrase(IReadOnlyList<string> wordList, PassphraseGenerationOptions options = null)
        {
            options ??= new PassphraseGenerationOptions();
            ValidateWordCount(options.WordCount);

            if (wordList == null || wordList.Count == 0)
            {
                throw new ArgumentException("Word list is empty.", nameof(wordList));
            }

            var separator = ValidateSeparator(options.Separator);
            var digitWordIndex = options.UseDigits ? RandomIntInclusive(0, options.WordCount - 1) : -1;

            var result = new StringBuilder();
            var first = true;

            for (var i = 0; i < options.WordCount; i++)
            {
                var word = wordList[RandomIntInclusive(0, wordList.Count - 1)];

                if (options.UseCaps && word.Length > 0)
                {
                    word = char.ToUpper(word[0]) + word.Substring(1);
                }

                if (options.UseDigits && i == digitWordIndex)
                {
                    word += RandomIntInclusive(0, 9).ToString();
                }

                if (!first)
                {
                    result.Append(separator);
                }

                result.Append(word);
                first = false;
            }

            return result.ToString();
        }

        /// <summary>
        /// Generates a random passphrase, loading the word list on first use (lazy-loaded and cached).
        /// </summary>
        public static async Task<string> GeneratePassphraseAsync(
            PassphraseGenerationOptions options = null,
            Func<Task<IReadOnlyList<string>>> loadWordList = null)
        {
            options ??= new PassphraseGenerationOptions();
            ValidateWordCount(options.WordCount);

            var wordList = loadWordList != null
                ? await loadWordList()
                : PassphraseWordList.Words;
            return GeneratePassphrase(wordList, options);
        }

        private static int RandomIntInclusive(int min, int max)
        {
            if (min > max)
            {
                throw new ArgumentOutOfRangeException(nameof(min));
            }

#if NET8_0_OR_GREATER
            return RandomNumberGenerator.GetInt32(min, max + 1);
#else
            var range = (uint)(max - min + 1);
            var randoms = CryptoUtils.GetRandomBytes(4);
            var value = BitConverter.ToUInt32(randoms, 0);
            return (int)(min + (value % range));
#endif
        }
    }

    /// <summary>
    /// Defines passphrase generation rules.
    /// </summary>
    public class PassphraseGenerationOptions
    {
        /// <summary>
        /// Number of words in the passphrase.
        /// </summary>
        /// <remarks>Default: 5. Allowed range: 5–9.</remarks>
        public int WordCount { get; set; } = 5;

        /// <summary>
        /// Separator inserted between words.
        /// </summary>
        /// <remarks>Default: "-". Allowed: '-', '.', '_', '!', '?', ' '</remarks>
        public string Separator { get; set; } = "-";

        /// <summary>
        /// Whether to capitalize the first letter of each word.
        /// </summary>
        /// <remarks>Default: true</remarks>
        public bool UseCaps { get; set; } = true;

        /// <summary>
        /// Whether to append a digit to one of the words.
        /// </summary>
        /// <remarks>Default: true</remarks>
        public bool UseDigits { get; set; } = true;
    }
}