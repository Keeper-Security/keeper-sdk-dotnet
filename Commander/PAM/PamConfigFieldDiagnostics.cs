using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
  /// <summary>
  /// Reports whether PAM config field values live in fields[] vs custom[] (Web Vault reads fields[]).
  /// </summary>
  internal static class PamConfigFieldDiagnostics
  {
    public static void LogPlacement(TypedRecord record, VaultData vault, string context)
    {
      if (record == null)
      {
        return;
      }

      Console.WriteLine($"[pam-config fields] {context}: uid={record.Uid}, type={record.TypeName}, client_modified={record.ClientModified:u}");
      Console.WriteLine($"[pam-config fields] {context}: fields[]={record.Fields.Count}, custom[]={record.Custom.Count}");

      var schemaKeys = GetSchemaFieldKeys(vault, record.TypeName);
      if (schemaKeys != null)
      {
        Console.WriteLine($"[pam-config fields] {context}: record-type schema has {schemaKeys.Count} field slot(s)");
      }

      foreach (var entry in DescribeAllFields(record, vault))
      {
        Console.WriteLine($"[pam-config fields] {context}: {FormatEntry(entry)}");
      }

      var hiddenFromUi = DescribeAllFields(record, vault)
        .Where(x => x.HasValue && x.Section == "custom" && x.MatchesSchema)
        .ToList();
      if (hiddenFromUi.Count > 0)
      {
        Console.WriteLine(
          $"[pam-config fields] {context}: WEB VAULT LIKELY HIDES {hiddenFromUi.Count} value(s) stored in custom[] " +
          "(Commander list still shows them): " +
          string.Join(", ", hiddenFromUi.Select(x => x.DisplayName)));
      }

      var emptySchemaSlots = DescribeAllFields(record, vault)
        .Where(x => x.Section == "fields" && x.MatchesSchema && !x.HasValue)
        .Select(x => x.DisplayName)
        .ToList();
      var valuedCustomDupes = hiddenFromUi.Select(x => x.DisplayName).ToList();
      if (emptySchemaSlots.Count > 0 && valuedCustomDupes.Count > 0
          && emptySchemaSlots.Intersect(valuedCustomDupes, StringComparer.OrdinalIgnoreCase).Any())
      {
        Console.WriteLine(
          $"[pam-config fields] {context}: MISPLACED DATA — empty slot in fields[] but value in custom[] " +
          "(typical .NET create bug; field values may need to be recreated)");
      }
    }

    public static List<Dictionary<string, object>> BuildPlacementJson(TypedRecord record, VaultData vault)
    {
      return DescribeAllFields(record, vault)
        .Select(x => new Dictionary<string, object>
        {
          ["section"] = x.Section,
          ["type"] = x.FieldType,
          ["label"] = x.FieldLabel ?? "",
          ["display_name"] = x.DisplayName,
          ["schema_key"] = x.SchemaKey,
          ["matches_schema"] = x.MatchesSchema,
          ["has_value"] = x.HasValue,
          ["web_vault_visible"] = x.WebVaultVisible,
          ["value_preview"] = x.ValuePreview ?? "",
        })
        .ToList();
    }

    private static HashSet<string> GetSchemaFieldKeys(VaultData vault, string typeName)
    {
      if (vault == null || !vault.TryGetRecordTypeByName(typeName, out var recordType) || recordType.Fields == null)
      {
        return null;
      }

      return new HashSet<string>(
        recordType.Fields.Select(x => x.GetTypedFieldName()),
        StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<FieldPlacementEntry> DescribeAllFields(TypedRecord record, VaultData vault)
    {
      var schemaKeys = GetSchemaFieldKeys(vault, record.TypeName);
      foreach (var field in record.Fields)
      {
        yield return DescribeField(field, "fields", schemaKeys);
      }

      foreach (var field in record.Custom)
      {
        yield return DescribeField(field, "custom", schemaKeys);
      }
    }

    private static FieldPlacementEntry DescribeField(
      ITypedField field,
      string section,
      HashSet<string> schemaKeys)
    {
      var schemaKey = field.GetTypedFieldName();
      var matchesSchema = schemaKeys?.Contains(schemaKey) == true;
      var hasValue = FieldHasValue(field);
      var preview = BuildValuePreview(field);

      return new FieldPlacementEntry
      {
        Section = section,
        FieldType = field.FieldName ?? "",
        FieldLabel = field.FieldLabel ?? "",
        DisplayName = PamConfigScheduleHelper.GetPamFieldDisplayName(field),
        SchemaKey = schemaKey,
        MatchesSchema = matchesSchema,
        HasValue = hasValue,
        WebVaultVisible = section == "fields" && hasValue,
        ValuePreview = preview,
      };
    }

    private static bool FieldHasValue(ITypedField field)
    {
      if (field == null || field.Count == 0)
      {
        return false;
      }

      for (var i = 0; i < field.Count; i++)
      {
        var value = field.GetValueAt(i);
        if (value == null)
        {
          continue;
        }

        if (value is string s && string.IsNullOrWhiteSpace(s))
        {
          continue;
        }

        if (value is FieldSchedule schedule)
        {
          if (!string.IsNullOrWhiteSpace(schedule.Type)
              && !string.Equals(schedule.Type, "ON_DEMAND", StringComparison.OrdinalIgnoreCase))
          {
            return true;
          }

          if (string.Equals(schedule.Type, "ON_DEMAND", StringComparison.OrdinalIgnoreCase))
          {
            return true;
          }

          continue;
        }

        return true;
      }

      return false;
    }

    private static string BuildValuePreview(ITypedField field)
    {
      if (string.Equals(field.FieldName, "schedule", StringComparison.Ordinal))
      {
        var values = PamConfigScheduleHelper.GetDisplayValues(field).ToList();
        return values.Count > 0 ? string.Join(", ", values) : "";
      }

      if (string.Equals(field.FieldName, "secret", StringComparison.Ordinal)
          || string.Equals(field.FieldName, "password", StringComparison.Ordinal))
      {
        return field.Count > 0 ? "***" : "";
      }

      var parts = field.GetTypedFieldInformation().ToList();
      return parts.Count > 0 ? string.Join(", ", parts) : "";
    }

    private static string FormatEntry(FieldPlacementEntry entry)
    {
      var storage = entry.Section == "fields" ? "fields[]" : "custom[]";
      var ui = entry.WebVaultVisible ? "web_ui=visible" : entry.HasValue ? "web_ui=hidden" : "web_ui=empty";
      var schema = entry.MatchesSchema ? "schema=match" : "schema=extra";
      var preview = string.IsNullOrEmpty(entry.ValuePreview) ? "(empty)" : entry.ValuePreview;
      return $"{storage} {entry.DisplayName} [{schema}, {ui}] value={preview}";
    }

    private sealed class FieldPlacementEntry
    {
      public string Section { get; set; }
      public string FieldType { get; set; }
      public string FieldLabel { get; set; }
      public string DisplayName { get; set; }
      public string SchemaKey { get; set; }
      public bool MatchesSchema { get; set; }
      public bool HasValue { get; set; }
      public bool WebVaultVisible { get; set; }
      public string ValuePreview { get; set; }
    }
  }
}
