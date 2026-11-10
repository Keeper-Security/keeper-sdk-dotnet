using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ConfigExamples
{
    /// <summary>
    /// Lists PAM configuration records, or shows detail for a single configuration.
    /// Uses <c>KeeperSecurity.Plugins.PAM</c> (<see cref="PamVaultHelpers"/>, <see cref="PamConfigurationFacade"/>,
    /// <see cref="ConfigUtils"/>).
    /// </summary>
    public static class PamConfigListExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="configId">Optional: show detail for a single configuration UID or title.</param>
        /// <param name="verbose">Include allowed settings (connections/tunneling/rotation/etc.) in the output.</param>
        public static async Task ListConfigs(VaultOnline vault = null, string configId = null, bool verbose = false)
        {
            try
            {
                var (resolvedVault, _) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (!string.IsNullOrWhiteSpace(configId))
                {
                    TypedRecord config;
                    try
                    {
                        config = PamVaultHelpers.ResolveRecord(vault, configId.Trim(), PamRecordTypes.Configuration);
                    }
                    catch (InvalidOperationException ex)
                    {
                        Console.WriteLine(ex.Message);
                        return;
                    }

                    if (config == null)
                    {
                        Console.WriteLine($"PAM configuration '{configId}' not found.");
                        return;
                    }

                    await PrintConfigDetailAsync(vault, config);
                    return;
                }

                var configs = PamVaultHelpers.GetConfigurationRecords(vault).Values
                    .OrderBy(x => x.Title ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (configs.Count == 0)
                {
                    Console.WriteLine("No PAM configurations found.");
                    return;
                }

                Console.WriteLine(
                    $"{"UID",-25}  {"Name",-30}  {"Type",-28}  {"Gateway UID",-25}  {"Resources",-9}");
                Console.WriteLine(new string('-', 125));

                foreach (var config in configs)
                {
                    var facade = new PamConfigurationFacade(config);
                    Console.WriteLine(
                        $"{config.Uid,-25}  {Truncate(config.Title, 30),-30}  {config.TypeName,-28}  {facade.ControllerUid,-25}  {facade.ResourceRef.Count,-9}");

                    if (verbose)
                    {
                        await PrintAllowedSettingsAsync(vault, config.Uid, "    ");
                    }
                }

                Console.WriteLine();
                Console.WriteLine($"Total configurations: {configs.Count}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static async Task PrintConfigDetailAsync(VaultOnline vault, TypedRecord config)
        {
            var facade = new PamConfigurationFacade(config);
            Console.WriteLine($"UID: {config.Uid}");
            Console.WriteLine($"Name: {config.Title}");
            Console.WriteLine($"Config Type: {config.TypeName}");
            Console.WriteLine($"Gateway UID: {facade.ControllerUid}");
            Console.WriteLine($"Resource Record UIDs: {string.Join(", ", facade.ResourceRef)}");
            Console.WriteLine("Allowed settings:");
            await PrintAllowedSettingsAsync(vault, config.Uid, "  ");
        }

        private static async Task PrintAllowedSettingsAsync(VaultOnline vault, string configUid, string indent)
        {
            var allowed = await ConfigUtils.GetConfigurationAllowedSettingsAsync(vault.Auth, configUid);
            Console.WriteLine(
                $"{indent}Connections: {FormatTriState(allowed.Connections)}  " +
                $"Tunneling: {FormatTriState(allowed.Tunneling)}  " +
                $"Rotation: {FormatTriState(allowed.Rotation)}  " +
                $"RBI: {FormatTriState(allowed.RemoteBrowserIsolation)}");
            Console.WriteLine(
                $"{indent}Connections Recording: {FormatTriState(allowed.ConnectionsRecording)}  " +
                $"Typescript Recording: {FormatTriState(allowed.TypescriptRecording)}  " +
                $"AI Threat Detection: {FormatTriState(allowed.AiThreatDetection)}  " +
                $"AI Terminate On Detection: {FormatTriState(allowed.AiTerminateSessionOnDetection)}");
        }

        private static string FormatTriState(bool? value)
        {
            return value == null ? "default" : value.Value ? "on" : "off";
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? "";
            }

            return value.Substring(0, maxLength - 3) + "...";
        }
    }
}
