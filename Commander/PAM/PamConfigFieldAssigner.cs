using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Commander;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Commander.PAM
{
  /// <summary>
  /// Ensures PAM configuration field values are stored in fields[] (Web Vault reads fields[], not custom[]).
  /// </summary>
  internal static class PamConfigFieldPlacement
  {
    public static void EnsureSchemaFields(VaultData vault, TypedRecord record)
    {
      if (vault == null || record == null)
      {
        return;
      }

      vault.AdjustTypedRecord(record);
    }

    /// <summary>
    /// Moves schema-matching values from custom[] into empty fields[] slots before save.
    /// </summary>
    public static void RelocateCustomToFields(VaultData vault, TypedRecord record)
    {
      if (vault == null || record == null || record.Custom.Count == 0)
      {
        return;
      }

      EnsureSchemaFields(vault, record);
      var schemaKeys = GetSchemaKeys(vault, record.TypeName);
      if (schemaKeys == null || schemaKeys.Count == 0)
      {
        return;
      }

      var relocated = new List<ITypedField>();
      foreach (var customField in record.Custom.ToList())
      {
        if (customField.Count == 0)
        {
          continue;
        }

        var key = customField.GetTypedFieldName();
        if (!schemaKeys.Contains(key))
        {
          continue;
        }

        if (!TryGetFieldSlot(record, customField.FieldName, customField.FieldLabel, out var schemaField))
        {
          continue;
        }

        if (FieldHasValue(schemaField))
        {
          continue;
        }

        CopyFieldValues(customField, schemaField);
        relocated.Add(customField);
      }

      foreach (var field in relocated)
      {
        record.Custom.Remove(field);
      }
    }

    private static HashSet<string> GetSchemaKeys(VaultData vault, string typeName)
    {
      if (!vault.TryGetRecordTypeByName(typeName, out var recordType) || recordType.Fields == null)
      {
        return null;
      }

      return new HashSet<string>(
        recordType.Fields.Select(x => x.GetTypedFieldName()),
        StringComparer.OrdinalIgnoreCase);
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

        if (value is string s)
        {
          if (!string.IsNullOrWhiteSpace(s))
          {
            return true;
          }
        }
        else if (value is FieldSchedule schedule)
        {
          if (!string.IsNullOrWhiteSpace(schedule.Type))
          {
            return true;
          }
        }
        else if (value is FieldTypeHost host)
        {
          if (!string.IsNullOrWhiteSpace(host.HostName) || !string.IsNullOrWhiteSpace(host.Port))
          {
            return true;
          }
        }
        else if (value is bool b)
        {
          return true;
        }
        else
        {
          return true;
        }
      }

      return false;
    }

    private static void CopyFieldValues(ITypedField source, ITypedField destination)
    {
      while (destination.Count > 0)
      {
        destination.DeleteValueAt(0);
      }

      for (var i = 0; i < source.Count; i++)
      {
        if (i > 0)
        {
          ((ITypedField)destination).AppendValue();
        }
        else if (destination.Count == 0)
        {
          ((ITypedField)destination).AppendValue();
        }

        var value = source.GetValueAt(i);
        if (value is FieldSchedule schedule)
        {
          destination.SetValueAt(i, CloneSchedule(schedule));
        }
        else if (value is FieldTypeHost host)
        {
          destination.SetValueAt(i, new FieldTypeHost { HostName = host.HostName, Port = host.Port });
        }
        else
        {
          destination.SetValueAt(i, value);
        }
      }
    }

    private static FieldSchedule CloneSchedule(FieldSchedule schedule)
    {
      return new FieldSchedule
      {
        Type = schedule.Type,
        Cron = schedule.Cron,
        TimeZone = schedule.TimeZone,
        Time = schedule.Time,
        Weekday = schedule.Weekday,
        Month = schedule.Month,
        MonthDay = schedule.MonthDay,
        IntervalCount = schedule.IntervalCount,
        EndDate = schedule.EndDate,
        Occurrences = schedule.Occurrences,
        Occurrence = schedule.Occurrence,
      };
    }

    public static bool TryGetFieldSlot(
      TypedRecord record,
      string fieldType,
      string fieldLabel,
      out ITypedField field)
    {
      field = null;
      if (record == null)
      {
        return false;
      }

      if (record.FindTypedField(fieldType, fieldLabel, out field) && record.Fields.Contains(field))
      {
        return true;
      }

      field = record.Fields.FirstOrDefault(f =>
        string.Equals(f.FieldName, fieldType, StringComparison.OrdinalIgnoreCase)
        && string.Equals(f.FieldLabel ?? "", fieldLabel ?? "", StringComparison.OrdinalIgnoreCase));

      if (field != null)
      {
        return true;
      }

      if (!string.IsNullOrEmpty(fieldLabel))
      {
        var schemaKey = new RecordTypeField(fieldType, fieldLabel).GetTypedFieldName();
        field = record.Fields.FirstOrDefault(f =>
          string.Equals(f.GetTypedFieldName(), schemaKey, StringComparison.OrdinalIgnoreCase));
        if (field != null)
        {
          return true;
        }

        field = record.Fields.FirstOrDefault(f =>
          string.Equals(f.FieldLabel ?? "", fieldLabel, StringComparison.OrdinalIgnoreCase));
        if (field != null)
        {
          return true;
        }
      }

      if (string.Equals(fieldType, "pamHostname", StringComparison.OrdinalIgnoreCase)
          || string.Equals(fieldLabel, "pamHostname", StringComparison.OrdinalIgnoreCase))
      {
        field = record.Fields.FirstOrDefault(f =>
          string.Equals(f.FieldName, "pamHostname", StringComparison.OrdinalIgnoreCase));
        if (field != null)
        {
          return true;
        }
      }

      return false;
    }
  }

  /// <summary>
  /// Applies type.label=value strings to typed record schema slots in fields[].
  /// </summary>
  internal static class PamConfigFieldAssigner
  {
    private static readonly Regex PropertyPattern = new(
      @"^([^\[\.]+)(\.[^\[]+)?(\[.*\])?\s*=\s*(.*)$",
      RegexOptions.Compiled);

    public static void AssignProperties(VaultData vault, TypedRecord record, IEnumerable<string> properties)
    {
      if (record == null || properties == null)
      {
        return;
      }

      PamConfigFieldPlacement.EnsureSchemaFields(vault, record);

      foreach (var property in properties)
      {
        if (string.IsNullOrWhiteSpace(property))
        {
          continue;
        }

        var trimmed = property.Trim();
        if (trimmed.StartsWith("schedule.", StringComparison.OrdinalIgnoreCase))
        {
          ApplyScheduleProperty(record, trimmed);
          continue;
        }

        if (trimmed.StartsWith("f.", StringComparison.OrdinalIgnoreCase))
        {
          ApplyCompositeProperty(record, trimmed.Substring(2));
          continue;
        }

        var parsed = ParseProperty(trimmed);
        if (parsed == null)
        {
          continue;
        }

        SetScalarField(record, parsed.FieldName, parsed.FieldLabel, parsed.Value);
      }

      PamConfigFieldPlacement.RelocateCustomToFields(vault, record);
    }

    private static CmdLineRecordField ParseProperty(string property)
    {
      var match = PropertyPattern.Match(property);
      if (!match.Success || match.Groups.Count < 5)
      {
        return null;
      }

      return new CmdLineRecordField
      {
        FieldName = match.Groups[1].Value.Trim(),
        FieldLabel = match.Groups[2].Value.Trim('.').Trim(),
        FieldIndex = match.Groups[3].Value.Trim('[', ']').Trim(),
        Value = Unquote(match.Groups[4].Value.Trim()),
      };
    }

    private static string Unquote(string value)
    {
      if (value.Length >= 2 && value.StartsWith("\"") && value.EndsWith("\""))
      {
        return value.Trim('"').Replace("\\\"", "\"");
      }

      return value;
    }

    private static void ApplyScheduleProperty(TypedRecord record, string property)
    {
      var eq = property.IndexOf('=');
      if (eq < 0)
      {
        return;
      }

      var value = property.Substring(eq + 1).Trim();
      if (string.Equals(value, "On-Demand", StringComparison.OrdinalIgnoreCase))
      {
        PamConfigScheduleHelper.SetOnDemandSchedule(record);
        return;
      }

      if (value.StartsWith("$JSON:", StringComparison.OrdinalIgnoreCase))
      {
        PamConfigScheduleHelper.SetScheduleFromJson(record, value.Substring(6));
      }
    }

    private static void ApplyCompositeProperty(TypedRecord record, string property)
    {
      var eq = property.IndexOf('=');
      if (eq < 0)
      {
        return;
      }

      var fieldName = property.Substring(0, eq).Trim();
      var value = property.Substring(eq + 1).Trim();

      if (!string.Equals(fieldName, "pamHostname", StringComparison.OrdinalIgnoreCase))
      {
        return;
      }

      if (string.IsNullOrEmpty(value))
      {
        ClearField(record, "pamHostname", null);
        return;
      }

      if (value.StartsWith("$JSON:", StringComparison.OrdinalIgnoreCase))
      {
        var json = value.Substring(6);
        var dict = Json.Deserialize<Dictionary<string, object>>(json);
        var host = dict != null && dict.TryGetValue("hostName", out var hn) ? Convert.ToString(hn) ?? "" : "";
        var port = dict != null && dict.TryGetValue("port", out var pt) ? Convert.ToString(pt) ?? "" : "";
        SetPamHostname(record, host, port);
      }
    }

    public static void SetPamHostname(TypedRecord record, string hostName, string port)
    {
      if (!PamConfigFieldPlacement.TryGetFieldSlot(record, "pamHostname", null, out var field))
      {
        throw new InvalidOperationException("Could not find pamHostname field slot in record schema.");
      }

      if (field.Count == 0)
      {
        ((ITypedField)field).AppendValue();
      }

      if (field.GetValueAt(0) is FieldTypeHost host)
      {
        host.HostName = hostName ?? "";
        host.Port = port ?? "";
      }
      else
      {
        field.SetValueAt(0, new FieldTypeHost { HostName = hostName ?? "", Port = port ?? "" });
      }
    }

    public static void SetCheckboxField(TypedRecord record, string label, bool? value)
    {
      if (value == null)
      {
        return;
      }

      if (!PamConfigFieldPlacement.TryGetFieldSlot(record, "checkbox", label, out var field)
          || field is not TypedField<bool> boolField)
      {
        return;
      }

      if (boolField.Count == 0)
      {
        ((ITypedField)boolField).AppendValue();
      }

      boolField.Values[0] = value.Value;
    }

    public static FieldTypeHost GetPamHostname(TypedRecord record)
    {
      if (PamConfigFieldPlacement.TryGetFieldSlot(record, "pamHostname", null, out var field)
          && field.Count > 0
          && field.GetValueAt(0) is FieldTypeHost host)
      {
        return host;
      }

      return null;
    }

    public static void ClearField(TypedRecord record, string fieldName, string fieldLabel)
    {
      if (PamConfigFieldPlacement.TryGetFieldSlot(record, fieldName, fieldLabel, out var field))
      {
        while (field.Count > 0)
        {
          field.DeleteValueAt(0);
        }
      }
    }

    private static void SetScalarField(TypedRecord record, string fieldType, string fieldLabel, string value)
    {
      if (!PamConfigFieldPlacement.TryGetFieldSlot(record, fieldType, fieldLabel, out var field))
      {
        try
        {
          field = VaultDataExtensions.CreateTypedField(fieldType, fieldLabel);
          record.Fields.Add(field);
        }
        catch (Exception ex)
        {
          throw new InvalidOperationException(
            $"Could not find field slot \"{fieldType}.{fieldLabel}\" in record schema. " +
            "Ensure record types are synced before creating PAM configurations.",
            ex);
        }
      }

      if (string.IsNullOrEmpty(value))
      {
        while (field.Count > 0)
        {
          field.DeleteValueAt(0);
        }

        return;
      }

      if (field.Count == 0)
      {
        ((ITypedField)field).AppendValue();
      }

      if (field is TypedField<string> stringField)
      {
        stringField.Values[0] = value;
        return;
      }

      if (field is TypedField<bool> boolField)
      {
        boolField.Values[0] = string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
        return;
      }

      if (field.GetValueAt(0) is IFieldTypeSerialize serializer)
      {
        serializer.SetValueAsString(value);
      }
    }
  }
}
