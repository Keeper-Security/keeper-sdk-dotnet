using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples
{
    public static class EnterpriseAuditReportExample
    {
        public static async Task GetAvailableAuditEvents()
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                
                var auditEvents = await vault.Auth.GetAvailableEvents();

                if (auditEvents == null || auditEvents.Length == 0)
                {
                    Console.WriteLine("No audit events available.");
                    return;
                }

                Console.WriteLine("======== Available Audit Events ========");
                Console.WriteLine($"Total Events: {auditEvents.Length}\n");
                
                foreach (var evt in auditEvents)
                {
                    Console.WriteLine($"[{evt.Id}] {evt.Name}");
                    Console.WriteLine($"     Category: {evt.Category}");
                    Console.WriteLine($"     Critical: {evt.Critical}");
                    if (!string.IsNullOrEmpty(evt.SyslogMessage))
                    {
                        Console.WriteLine($"     Syslog:   {evt.SyslogMessage}");
                    }
                    Console.WriteLine();
                }
                Console.WriteLine("=========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}