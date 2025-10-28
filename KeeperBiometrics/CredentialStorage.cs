#if NET472_OR_GREATER
using System;
using Microsoft.Win32;

namespace KeeperBiometric
{
    /// <summary>
    /// Manages credential storage in Windows Registry for persistent credential ID tracking
    /// Mirrors the PowerShell implementation's registry-based storage
    /// </summary>
    public static class CredentialStorage
    {
        private const string RegistryPath = @"Software\Keeper Security\Commander\Biometric";
        
        /// <summary>
        /// Stores a Windows Hello credential ID for a specific username
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="credentialId">The credential ID (Base64Url encoded)</param>
        /// <returns>True if successful, false otherwise</returns>
        public static bool SetCredentialId(string username, string credentialId)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                System.Diagnostics.Debug.WriteLine("SetCredentialId failed: username cannot be null or empty");
                return false;
            }
            
            if (username.IndexOfAny(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }) >= 0)
            {
                System.Diagnostics.Debug.WriteLine($"SetCredentialId failed: username contains invalid characters: {username}");
                return false;
            }
            
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(RegistryPath))
                {
                    if (key != null)
                    {
                        if (!string.IsNullOrEmpty(credentialId))
                        {
                            key.SetValue(username, credentialId, RegistryValueKind.String);
                        }
                        else
                        {
                            key.DeleteValue(username, false);
                        }
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error setting credential ID for username {username}: {ex.Message} at path {RegistryPath}");
                return false;
            }
            
            return false;
        }
        
        /// <summary>
        /// Retrieves a stored credential ID for a username
        /// </summary>
        /// <param name="username">The username</param>
        /// <returns>The credential ID if found, null otherwise</returns>
        public static string GetCredentialId(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                System.Diagnostics.Debug.WriteLine("GetCredentialId failed: username cannot be null or empty");
                return null;
            }
            
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(RegistryPath))
                {
                    if (key != null)
                    {
                        var value = key.GetValue(username);
                        return value as string;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting credential ID for username {username}: {ex.Message} at path {RegistryPath}");
                return null;
            }
            
            return null;
        }
        
        /// <summary>
        /// Removes a credential ID from storage
        /// </summary>
        /// <param name="username">The username</param>
        /// <returns>True if successful, false otherwise</returns>
        public static bool RemoveCredentialId(string username)
        {
            return SetCredentialId(username, null);
        }
        
        /// <summary>
        /// Checks if a credential ID is stored for a username
        /// </summary>
        /// <param name="username">The username</param>
        /// <returns>True if credential exists, false otherwise</returns>
        public static bool HasCredential(string username)
        {
            return !string.IsNullOrEmpty(GetCredentialId(username));
        }
    }
}
#endif

