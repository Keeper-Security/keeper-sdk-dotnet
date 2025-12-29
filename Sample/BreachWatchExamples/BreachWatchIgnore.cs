using System;
using System.Threading.Tasks;
using Cli;
using BWIgnore = KeeperSecurity.BreachWatch.BreachWatchIgnore;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchIgnoreExample
    {
        public static async Task IgnoreRecord(string recordUid)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                // Ignore the record in BreachWatch
                await BWIgnore.IgnoreRecord(vault, recordUid);

                Console.WriteLine($"Record '{recordUid}' has been ignored in BreachWatch.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task CheckIfIgnored(string recordUid)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var isIgnored = BWIgnore.IsRecordIgnored(vault, recordUid);
                
                Console.WriteLine($"Record '{recordUid}' ignored: {isIgnored}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}