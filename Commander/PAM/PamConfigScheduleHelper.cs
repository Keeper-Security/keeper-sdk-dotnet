using System;
using System.Collections.Generic;
using System.Text;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Commander.PAM
{
  internal static class PamConfigScheduleHelper
  {
    private const string ScheduleFieldType = "schedule";
    private const string DefaultRotationScheduleLabel = "defaultRotationSchedule";
    private const string DefaultTimeZone = "Etc/UTC";

    public static void ApplyDefaultRotationSchedule(TypedRecord record, PamConfigOptions options, bool isEdit)
    {
      // Omitted --schedule: leave existing value on edit; default On-Demand on create.
      if (options.DefaultSchedule == null)
      {
        if (!isEdit)
        {
          SetOnDemandSchedule(record);
        }

        return;
      }

      var cron = options.DefaultSchedule.Trim();
      if (string.IsNullOrEmpty(cron) || IsOnDemandScheduleValue(cron))
      {
        SetOnDemandSchedule(record);
        return;
      }

      cron = NormalizeRotationCronForStorage(cron);
      var (isValid, message) = RotationUtils.ValidateCronExpression(cron, forRotation: true);
      if (!isValid)
      {
        throw new InvalidOperationException($"Invalid CRON \"{cron}\" Error: {message}");
      }

      SetCronSchedule(record, cron);
    }

    private static bool IsOnDemandScheduleValue(string value)
    {
      return string.Equals(value, "On-Demand", StringComparison.OrdinalIgnoreCase)
             || string.Equals(value, "ON_DEMAND", StringComparison.OrdinalIgnoreCase);
    }

    public static void EnsureDefaultRotationScheduleIfEmpty(TypedRecord record)
    {
      if (!TryGetDefaultRotationScheduleField(record, out var scheduleField))
      {
        return;
      }

      if (scheduleField.Count > 0 && scheduleField.Values[0] != null)
      {
        return;
      }

      if (scheduleField.Count == 0)
      {
        ((ITypedField)scheduleField).AppendValue();
      }

      scheduleField.Values[0] = new FieldSchedule { Type = "ON_DEMAND" };
    }

    public static void SetOnDemandSchedule(TypedRecord record)
    {
      var scheduleField = EnsureDefaultRotationScheduleField(record);
      if (scheduleField.Count == 0)
      {
        ((ITypedField)scheduleField).AppendValue();
      }

      scheduleField.Values[0] = new FieldSchedule { Type = "ON_DEMAND" };
    }

    public static void SetCronSchedule(TypedRecord record, string cron)
    {
      var scheduleField = EnsureDefaultRotationScheduleField(record);
      if (scheduleField.Count == 0)
      {
        ((ITypedField)scheduleField).AppendValue();
      }

      scheduleField.Values[0] = new FieldSchedule
      {
        Type = "CRON",
        Cron = NormalizeRotationCronForStorage(cron),
        TimeZone = DefaultTimeZone,
      };
    }

    public static void SetScheduleFromJson(TypedRecord record, string json)
    {
      var schedule = Json.Deserialize<FieldSchedule>(json);
      if (schedule == null)
      {
        return;
      }

      var scheduleField = EnsureDefaultRotationScheduleField(record);
      if (scheduleField.Count == 0)
      {
        ((ITypedField)scheduleField).AppendValue();
      }

      scheduleField.Values[0] = NormalizeSchedule(schedule);
    }

    public static IEnumerable<string> GetDisplayValues(ITypedField field)
    {
      if (!string.Equals(field.FieldName, ScheduleFieldType, StringComparison.Ordinal))
      {
        return field.GetTypedFieldInformation();
      }

      var values = new List<string>();
      for (var i = 0; i < field.Count; i++)
      {
        if (field.GetValueAt(i) is FieldSchedule schedule)
        {
          var exported = ExportScheduleField(schedule);
          if (!string.IsNullOrEmpty(exported))
          {
            values.Add(exported);
          }
        }
      }

      return values;
    }

    public static string GetPamFieldDisplayName(IRecordTypeField field)
    {
      var type = field.FieldName ?? "";
      var label = field.FieldLabel ?? "";
      if (!string.IsNullOrEmpty(type) && !string.IsNullOrEmpty(label))
      {
        return string.Equals(field.FieldName, ScheduleFieldType, StringComparison.Ordinal)
          ? "Default Schedule"
          : $"({type}).{label}";
      }

      if (!string.IsNullOrEmpty(type))
      {
        return string.Equals(type, ScheduleFieldType, StringComparison.Ordinal) ? "Default Schedule" : $"({type})";
      }

      return label;
    }

    public static bool IsDefaultRotationScheduleField(ITypedField field)
    {
      return string.Equals(field.FieldName, ScheduleFieldType, StringComparison.Ordinal)
             && string.Equals(field.FieldLabel, DefaultRotationScheduleLabel, StringComparison.Ordinal);
    }

    public static string ExportScheduleField(FieldSchedule schedule)
    {
      if (schedule == null || string.IsNullOrWhiteSpace(schedule.Type))
      {
        return null;
      }

      switch (schedule.Type.Trim().ToUpperInvariant())
      {
        case "CRON":
          return ExportCronScheduleField(schedule.Cron);
        case "ON_DEMAND":
          return null;
        case "RUN_ONCE":
          return FormatRunOnce(schedule);
        case "DAILY":
        case "WEEKLY":
        case "MONTHLY_BY_DAY":
        case "MONTHLY_BY_WEEKDAY":
        case "YEARLY":
          return FormatRecurringSchedule(schedule);
        default:
          return schedule.Type;
      }
    }

    private static string ExportCronScheduleField(string cron)
    {
      if (string.IsNullOrWhiteSpace(cron))
      {
        return null;
      }

      return cron.Trim();
    }

    private static string NormalizeRotationCronForStorage(string cron)
    {
      return cron?.Trim();
    }

    private static FieldSchedule NormalizeSchedule(FieldSchedule source)
    {
      if (source == null || string.IsNullOrWhiteSpace(source.Type))
      {
        return source;
      }

      switch (source.Type.Trim().ToUpperInvariant())
      {
        case "CRON":
          return new FieldSchedule
          {
            Type = "CRON",
            Cron = source.Cron?.Trim(),
            TimeZone = string.IsNullOrWhiteSpace(source.TimeZone) ? DefaultTimeZone : source.TimeZone.Trim(),
            EndDate = source.EndDate?.Trim(),
            Occurrences = source.Occurrences,
          };
        case "ON_DEMAND":
          return new FieldSchedule { Type = "ON_DEMAND" };
        default:
          return source;
      }
    }

    private static string FormatRunOnce(FieldSchedule schedule)
    {
      if (string.IsNullOrWhiteSpace(schedule.Time))
      {
        return "RUN_ONCE";
      }

      return string.IsNullOrWhiteSpace(schedule.TimeZone)
        ? schedule.Time
        : $"{schedule.Time} ({schedule.TimeZone})";
    }

    private static string FormatRecurringSchedule(FieldSchedule schedule)
    {
      var parts = new List<string> { schedule.Type };
      if (!string.IsNullOrWhiteSpace(schedule.Time))
      {
        parts.Add($"time={schedule.Time}");
      }

      if (!string.IsNullOrWhiteSpace(schedule.TimeZone))
      {
        parts.Add($"tz={schedule.TimeZone}");
      }

      if (!string.IsNullOrWhiteSpace(schedule.Weekday))
      {
        parts.Add($"weekday={schedule.Weekday}");
      }

      if (!string.IsNullOrWhiteSpace(schedule.Month))
      {
        parts.Add($"month={schedule.Month}");
      }

      if (schedule.MonthDay.HasValue)
      {
        parts.Add($"monthDay={schedule.MonthDay.Value}");
      }

      if (!string.IsNullOrWhiteSpace(schedule.Occurrence))
      {
        parts.Add($"occurrence={schedule.Occurrence}");
      }

      if (schedule.IntervalCount.HasValue)
      {
        parts.Add($"intervalCount={schedule.IntervalCount.Value}");
      }

      if (!string.IsNullOrWhiteSpace(schedule.EndDate))
      {
        parts.Add($"endDate={schedule.EndDate}");
      }

      if (schedule.Occurrences.HasValue)
      {
        parts.Add($"occurrences={schedule.Occurrences.Value}");
      }

      return string.Join(", ", parts);
    }

    private static TypedField<FieldSchedule> EnsureDefaultRotationScheduleField(TypedRecord record)
    {
      if (TryGetDefaultRotationScheduleField(record, out var scheduleField))
      {
        return scheduleField;
      }

      throw new InvalidOperationException(
        "Could not find defaultRotationSchedule field slot in record schema. " +
        "Ensure record types are synced before creating PAM configurations.");
    }

    private static bool TryGetDefaultRotationScheduleField(
      TypedRecord record,
      out TypedField<FieldSchedule> scheduleField)
    {
      scheduleField = null;
      if (!PamConfigFieldPlacement.TryGetFieldSlot(record, ScheduleFieldType, DefaultRotationScheduleLabel, out var field))
      {
        return false;
      }

      scheduleField = field as TypedField<FieldSchedule>;
      return scheduleField != null;
    }
  }
}
