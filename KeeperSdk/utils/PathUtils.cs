using System;
using System.IO;

namespace KeeperSecurity.Utils
{
    /// <summary>
    /// Path helpers for attachment upload/download.
    /// Attachment names are encrypted client-side (zero-knowledge), so the client
    /// must sanitize before writing metadata or saving files to disk.
    /// </summary>
    public static class PathUtils
    {
        /// <summary>
        /// Returns a bare file name suitable for storage or disk write.
        /// Strips directories and absolute paths.
        /// </summary>
        /// <param name="name">Attachment name from local path or record metadata.</param>
        /// <returns>Sanitized file name with no directory components.</returns>
        /// <exception cref="ArgumentException">Name is missing or resolves to empty / "." / "..".</exception>
        public static string SanitizeFileName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Attachment file name is required.", nameof(name));
            }

            var fileName = Path.GetFileName(name.Trim());

            if (string.IsNullOrEmpty(fileName)
                || string.Equals(fileName, ".", StringComparison.Ordinal)
                || string.Equals(fileName, "..", StringComparison.Ordinal))
            {
                throw new ArgumentException("Attachment file name is invalid.", nameof(name));
            }

            return fileName;
        }

        /// <summary>
        /// Builds an absolute path under <paramref name="outputDirectory"/> using a sanitized
        /// attachment name, and verifies the result cannot escape that directory
        /// </summary>
        /// <param name="outputDirectory">Target folder for the download.</param>
        /// <param name="attachmentName">Attacker-influenced name from record metadata.</param>
        /// <returns>Full path that is guaranteed to stay inside <paramref name="outputDirectory"/>.</returns>
        public static string GetSafeDownloadPath(string outputDirectory, string attachmentName)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
            {
                throw new ArgumentException("Output directory is required.", nameof(outputDirectory));
            }

            var fileName = SanitizeFileName(attachmentName);
            var directoryFull = Path.GetFullPath(outputDirectory.Trim());
            var combined = Path.GetFullPath(Path.Combine(directoryFull, fileName));

            var root = directoryFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                       + Path.DirectorySeparatorChar;

            // Defense in depth: even after SanitizeFileName, refuse any escape.
            if (!combined.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Resolved download path escapes the output directory.");
            }

            return combined;
        }
    }
}
