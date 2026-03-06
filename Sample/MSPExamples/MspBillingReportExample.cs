using System;
using KeeperSecurity.Vault;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BI;
using KeeperSecurity.Authentication;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspBillingReportExample
    {
        // BI API base plan IDs mapped to product names
        private static readonly Dictionary<int, string> PlanNames = new Dictionary<int, string>
        {
            { 1, "Business" },
            { 2, "Business Plus" },
            { 10, "Enterprise" },
            { 11, "Enterprise Plus" }
        };

        // BI API file plan IDs mapped to storage tier names (fallback if mapping/addons API is unavailable)
        private static readonly Dictionary<int, string> DefaultFilePlanNames = new Dictionary<int, string>
        {
            { 4, "100GB" },
            { 7, "1TB" },
            { 8, "10TB" }
        };

        /// <summary>
        /// Generates an MSP consumption billing report for the specified month.
        /// Retrieves daily snapshot data, pricing, and addon mappings from the BI API.
        /// </summary>
        /// <param name="month">Report month (1-12). Defaults to previous calendar month if null.</param>
        /// <param name="year">Report year (e.g. 2025). Defaults to current year if null.</param>
        public static async Task GetBillingReport(VaultOnline vault, int? month = null, int? year = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var now = DateTime.UtcNow;
                int reportYear = year ?? now.Year;
                int reportMonth;
                if (month.HasValue)
                {
                    reportMonth = month.Value;
                }
                else
                {
                    reportMonth = now.Month - 1;
                    if (reportMonth <= 0)
                    {
                        reportMonth = 12;
                        reportYear--;
                    }
                }

                var auth = vault.Auth;

                var mappingUrl = auth.GetBiUrl("mapping/addons");
                var mappingRq = new MappingAddonsRequest();
                var mappingRs = await auth.ExecuteAuthRest<MappingAddonsRequest, MappingAddonsResponse>(mappingUrl, mappingRq);

                var addonNameById = new Dictionary<int, string>();
                foreach (var addon in mappingRs.Addons)
                {
                    addonNameById[addon.Id] = addon.Name;
                }

                var filePlanNameById = new Dictionary<int, string>(DefaultFilePlanNames);
                foreach (var fp in mappingRs.FilePlans)
                {
                    filePlanNameById[fp.Id] = fp.Name;
                }

                var pricingUrl = auth.GetBiUrl("subscription/mc_pricing");
                var pricingRq = new SubscriptionMcPricingRequest();
                var pricingRs = await auth.ExecuteAuthRest<SubscriptionMcPricingRequest, SubscriptionMcPricingResponse>(pricingUrl, pricingRq);

                Console.WriteLine("\n======== MSP Pricing ========");
                foreach (var plan in pricingRs.BasePlans)
                {
                    var name = PlanNames.ContainsKey(plan.Id) ? PlanNames[plan.Id] : $"Plan #{plan.Id}";
                    Console.WriteLine($"  {name}: {plan.Cost.Amount} per {plan.Cost.AmountPer}");
                }
                foreach (var addon in pricingRs.Addons)
                {
                    var name = addonNameById.ContainsKey(addon.Id) ? addonNameById[addon.Id] : $"Addon #{addon.Id}";
                    Console.WriteLine($"  {name}: {addon.Cost.Amount} per {addon.Cost.AmountPer}");
                }
                foreach (var fp in pricingRs.FilePlans)
                {
                    var name = filePlanNameById.ContainsKey(fp.Id) ? filePlanNameById[fp.Id] : $"Storage #{fp.Id}";
                    Console.WriteLine($"  {name}: {fp.Cost.Amount} per {fp.Cost.AmountPer}");
                }

                var snapshotUrl = auth.GetBiUrl("reporting/daily_snapshot");
                var snapshotRq = new ReportingDailySnapshotRequest
                {
                    Month = reportMonth,
                    Year = reportYear
                };
                var snapshotRs = await auth.ExecuteAuthRest<ReportingDailySnapshotRequest, ReportingDailySnapshotResponse>(snapshotUrl, snapshotRq);

                var mcNames = new Dictionary<int, string>();
                foreach (var mcEntry in snapshotRs.McEnterprises)
                {
                    mcNames[mcEntry.Id] = mcEntry.Name;
                }

                Console.WriteLine($"\n======== Billing Report: {reportMonth:D2}/{reportYear} ========");
                Console.WriteLine($"  Total snapshot records: {snapshotRs.Records.Count}");
                Console.WriteLine($"  Managed Companies in report: {mcNames.Count}");

                var byCompany = snapshotRs.Records
                    .GroupBy(r => r.McEnterpriseId)
                    .OrderBy(g => g.Key);

                foreach (var group in byCompany)
                {
                    var companyName = mcNames.ContainsKey(group.Key) ? mcNames[group.Key] : $"MC #{group.Key}";
                    var totalLicenses = group.Max(r => r.MaxLicenseCount);
                    var basePlanId = group.Select(r => r.MaxBasePlanId).Where(id => id > 0).FirstOrDefault();
                    var basePlanName = PlanNames.ContainsKey(basePlanId) ? PlanNames[basePlanId] : $"Plan #{basePlanId}";

                    Console.WriteLine($"\n  {companyName} (ID: {group.Key})");
                    Console.WriteLine($"    Plan:             {basePlanName}");
                    Console.WriteLine($"    Max Licenses:     {totalLicenses}");
                    Console.WriteLine($"    Snapshot Days:    {group.Count()}");

                    var addonSummary = group
                        .SelectMany(r => r.Addons)
                        .GroupBy(a => a.MaxAddonId)
                        .Where(g => g.Key > 0);

                    foreach (var addonGroup in addonSummary)
                    {
                        var addonName = addonNameById.ContainsKey(addonGroup.Key) ? addonNameById[addonGroup.Key] : $"Addon #{addonGroup.Key}";
                        var maxUnits = addonGroup.Max(a => a.Units);
                        Console.WriteLine($"    Addon: {addonName} (max units: {maxUnits})");
                    }
                }

                Console.WriteLine("\n=============================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
