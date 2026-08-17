using System;
using System.IO;
using System.Runtime.InteropServices;

namespace KeeperSecurity.Utils
{
    /// <summary>
    /// Helpers to keep attachment file names and download paths safe.
    /// Used by attachment upload/download in the SDK, Commander, PowerCommander, and samples.
    /// Names are encrypted client-side, so the server can't validate them — we clean them here.
    /// </summary>
    public static class PathUtils
    {
        private static StringComparison GetPathComparison()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
        }

        /// <summary>
        /// Takes a name (or full path) and returns just the file name with no folders.
        /// Used when setting attachment Name/Title, building download paths, and from PowerCommander.
        /// </summary>
        /// <param name="name">Attachment name or path.</param>
        /// <returns>The file name with no directory components.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="name"/> is null, empty, or resolves to an invalid file name.</exception>
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

            var invalidChars = Path.GetInvalidFileNameChars();
            if (fileName.IndexOfAny(invalidChars) >= 0)
            {
                throw new ArgumentException("Attachment file name contains invalid characters.", nameof(name));
            }

            return fileName;
        }

        /// <summary>
        /// Builds a full path under the output folder and checks it cannot escape that folder.
        /// Used by Commander download, PowerCommander Copy-KeeperFileAttachment, and the sample download.
        /// </summary>
        /// <param name="outputDirectory">Directory the file must stay under.</param>
        /// <param name="attachmentName">Attachment name or path. Directory components are stripped.</param>
        /// <returns>The full path under <paramref name="outputDirectory"/>.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="outputDirectory"/> or <paramref name="attachmentName"/> is invalid.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the resolved path escapes the output directory.</exception>
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

            // Extra check after sanitize — block anything that still points outside the folder.
            var comparison = GetPathComparison();

            if (!combined.StartsWith(root, comparison))
            {
                throw new InvalidOperationException(
                    "Resolved download path escapes the output directory.");
            }

            return combined;
        }
    }
}
