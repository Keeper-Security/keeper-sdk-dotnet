using System;
using System.IO;

namespace KeeperSecurity.Utils
{
    /// <summary>
    /// Helpers to keep attachment file names and download paths safe.
    /// Used by attachment upload/download in the SDK, Commander, PowerCommander, and samples.
    /// Names are encrypted client-side, so the server can't validate them — we clean them here.
    /// </summary>
    public static class PathUtils
    {
        /// <summary>
        /// Takes a name (or full path) and returns just the file name with no folders.
        /// Used when setting attachment Name/Title, building download paths, and from PowerCommander.
        /// </summary>
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
        /// Builds a full path under the output folder and checks it cannot escape that folder.
        /// Used by Commander download, PowerCommander Copy-KeeperFileAttachment, and the sample download.
        /// </summary>
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
            if (!combined.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Resolved download path escapes the output directory.");
            }

            return combined;
        }
    }
}
