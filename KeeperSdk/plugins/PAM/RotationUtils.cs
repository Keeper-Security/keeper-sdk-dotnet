using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using PamProto = PAM;
using RouterProto = Router;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// PAM record rotation helpers (Auth REST and schedule formatting).
  /// </summary>
  public static class RotationUtils
  {
    public const string DefaultSpecialChars = "!@#$%^?();',.=+[]<>{}-_/\\*&:\"`~|";

    private const string GetRotationInfoEndpoint = "pam/get_rotation_info";
    private const char VersionSeparator = '.';
    private const string RotateActionJobPrefix = "RotateActionJob|";
    private static readonly Regex CronFieldPattern = new Regex(
      @"^(\*|\d+L?|L[W]?|\d+-\d+|\*/\d+|\d+(,\d+)*|\d+-\d+/\d+)$",
      RegexOptions.Compiled);

    /// <summary>
    /// Validates a CRON expression. When <paramref name="forRotation"/> is true, enforces 6-field rotation format.
    /// </summary>
    /// <returns>Tuple of (isValid, message).</returns>
    public static (bool IsValid, string Message) ValidateCronExpression(string expression, bool forRotation = false)
    {
      if (string.IsNullOrWhiteSpace(expression))
      {
        return (false, "CRON: Expression is required");
      }

      var parts = expression.Trim().Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
      if (forRotation)
      {
        if (parts.Length != 6)
        {
          return (false,
            $"CRON: Rotation schedules require all 6 parts incl. seconds - ex. Daily at 04:00:00 cron: 0 0 4 * * ? got {parts.Length} parts");
        }

        if (parts[3] != "?" && parts[5] != "?")
        {
          return (false,
            "CRON: Rotation schedule CRON format - must use ? character in one of these fields: day-of-week, day-of-month");
        }

        parts = (string[])parts.Clone();
        parts[3] = parts[3] == "?" ? "*" : parts[3];
        parts[5] = parts[5] == "?" ? "*" : parts[5];
      }

      if (parts.Length != 5 && parts.Length != 6)
      {
        return (false, $"CRON: Expected 5 or 6 fields, got {parts.Length}");
      }

      string minute;
      string hour;
      string dom;
      string month;
      string dow;
      if (parts.Length == 6)
      {
        if (!ValidateCronField(parts[0], 0, 59))
        {
          return (false, "CRON: Invalid seconds field");
        }

        minute = parts[1];
        hour = parts[2];
        dom = parts[3];
        month = parts[4];
        dow = parts[5];
      }
      else
      {
        minute = parts[0];
        hour = parts[1];
        dom = parts[2];
        month = parts[3];
        dow = parts[4];
      }

      (string field, int min, int max, string name)[] validators =
      {
        (minute, 0, 59, "minute"),
        (hour, 0, 23, "hour"),
        (dom, 1, 31, "day of month"),
        (month, 1, 12, "month"),
        (dow, 0, 7, "day of week"),
      };

      foreach (var (field, min, max, name) in validators)
      {
        if (!ValidateCronField(field, min, max))
        {
          return (false, $"CRON: Invalid {name} field");
        }
      }

      return (true, "Valid cron expression");
    }

    private static bool ValidateCronField(string field, int minVal, int maxVal)
    {
      if (!CronFieldPattern.IsMatch(field))
      {
        return false;
      }

      foreach (var part in Regex.Split(field, @"[,\-/]"))
      {
        if (part == "*" || part.Length == 0)
        {
          continue;
        }

        if (part == "L" || part == "LW")
        {
          continue;
        }

        var stripped = part.TrimEnd('L', 'W');
        if (stripped.Length == 0 || !int.TryParse(stripped, out var number))
        {
          return false;
        }

        if (number < minVal || number > maxVal)
        {
          return false;
        }
      }

      return true;
    }

    public static async Task<RouterProto.RouterRotationInfo> GetRotationInfoAsync(
      IAuthentication auth,
      string recordUid)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (string.IsNullOrWhiteSpace(recordUid))
      {
        throw new ArgumentException("Record UID is required", nameof(recordUid));
      }

      var request = new PamProto.PAMGenericUidRequest
      {
        Uid = ByteString.CopyFrom(recordUid.Trim().Base64UrlDecode()),
      };

      var response = await auth.ExecuteAuthRest(
        GetRotationInfoEndpoint,
        request,
        typeof(RouterProto.RouterRotationInfo));

      if (response is not RouterProto.RouterRotationInfo rotationInfo)
      {
        throw new InvalidOperationException(
          $"Unexpected response type from {GetRotationInfoEndpoint}: {response?.GetType().Name ?? "null"}");
      }

      return rotationInfo;
    }

    public static bool? ResolveRotationEnabled(bool enable, bool disable)
    {
      if (enable)
      {
        return true;
      }

      if (disable)
      {
        return false;
      }

      return null;
    }

    public static byte[] EncryptPasswordComplexity(PasswordGenerationOptions rules, byte[] recordKey)
    {
      if (rules == null)
      {
        throw new ArgumentNullException(nameof(rules));
      }

      if (recordKey == null || recordKey.Length == 0)
      {
        throw new ArgumentException("Record key is required", nameof(recordKey));
      }

      ValidateComplexityRules(rules);
      return CryptoUtils.EncryptAesV2(ToWireJson(rules), recordKey);
    }

    public static bool IsClearedPasswordComplexity(PasswordGenerationOptions rules)
    {
      return rules != null
             && rules.Length == 0
             && rules.Upper == 0
             && rules.Lower == 0
             && rules.Digit == 0
             && rules.Special == 0
             && string.IsNullOrEmpty(rules.SpecialCharacters);
    }

    public static string FormatScheduleDisplay(string scheduleData, bool noSchedule)
    {
      if (noSchedule)
      {
        return "[Manual Rotation]";
      }

      if (string.IsNullOrEmpty(scheduleData))
      {
        return "[empty]";
      }

      var normalized = scheduleData.StartsWith(RotateActionJobPrefix, StringComparison.Ordinal)
        ? scheduleData.Substring(RotateActionJobPrefix.Length)
        : scheduleData;

      var parts = normalized.Split(VersionSeparator);
      return parts.Length switch
      {
        4 => $"{parts[0]} on {parts[1]} at {parts[2]} UTC with interval count of {parts[3]}",
        3 => $"{parts[0]} at {parts[1]} UTC with interval count of {parts[2]}",
        _ => scheduleData,
      };
    }

    public static List<object> ParseScheduleOptions(
      string scheduleJson,
      string scheduleCron,
      bool onDemand,
      bool scheduleFromConfig)
    {
      var count = 0;
      if (!string.IsNullOrWhiteSpace(scheduleJson))
      {
        count++;
      }

      if (!string.IsNullOrWhiteSpace(scheduleCron))
      {
        count++;
      }

      if (onDemand)
      {
        count++;
      }

      if (scheduleFromConfig)
      {
        count++;
      }

      if (count > 1)
      {
        throw new InvalidOperationException(
          "Only one of --schedule-json, --schedule-cron, --on-demand, or --schedule-config may be specified.");
      }

      return ParseScheduleData(scheduleJson, scheduleCron, onDemand, scheduleFromConfig);
    }

    public static List<object> ParseScheduleData(
      string scheduleJson,
      string scheduleCron,
      bool onDemand,
      bool scheduleFromConfig)
    {
      if (onDemand)
      {
        return ToObjectList(new List<Dictionary<string, object>>());
      }

      if (!string.IsNullOrWhiteSpace(scheduleJson))
      {
        return ToObjectList(ParseScheduleEntries(scheduleJson));
      }

      if (!string.IsNullOrWhiteSpace(scheduleCron))
      {
        var cron = scheduleCron.Trim();
        var (valid, error) = ValidateCronExpression(cron, forRotation: true);
        if (!valid)
        {
          throw new ArgumentException(error);
        }

        return ToObjectList(new List<Dictionary<string, object>>
        {
          new Dictionary<string, object>
          {
            ["type"] = "CRON",
            ["cron"] = cron,
            ["tz"] = "Etc/UTC",
          },
        });
      }

      _ = scheduleFromConfig;
      return null;
    }

    public static List<object> ParseScheduleJsonString(string scheduleJson)
    {
      return ToObjectList(ParseScheduleEntries(scheduleJson));
    }

    public static string GetScheduleType(List<object> scheduleData)
    {
      if (scheduleData == null || scheduleData.Count == 0)
      {
        return "On-Demand";
      }

      if (TryGetScheduleEntry(scheduleData[0], out var entry)
          && entry.TryGetValue("type", out var typeValue))
      {
        return typeValue?.ToString() ?? "On-Demand";
      }

      return "On-Demand";
    }

    public static string BuildSchedulePayload(
      string scheduleJson,
      bool onDemand,
      List<object> recordSchedule)
    {
      if (!string.IsNullOrWhiteSpace(scheduleJson))
      {
        return SerializeScheduleData(ParseScheduleJsonString(scheduleJson));
      }

      if (onDemand)
      {
        return "";
      }

      return SerializeScheduleData(recordSchedule);
    }

    private static List<Dictionary<string, object>> ParseScheduleEntries(string scheduleJson)
    {
      var json = NormalizeJsonArgument(scheduleJson);
      if (string.IsNullOrEmpty(json))
      {
        throw new ArgumentException("Schedule JSON is empty.");
      }

      try
      {
        if (json.StartsWith("[", StringComparison.Ordinal))
        {
          return JsonUtils.ParseJson<List<Dictionary<string, object>>>(Encoding.UTF8.GetBytes(json));
        }

        if (json.StartsWith("{", StringComparison.Ordinal))
        {
          var item = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(json));
          return new List<Dictionary<string, object>> { item };
        }
      }
      catch (SerializationException ex)
      {
        throw new ArgumentException(
          $"Invalid schedule JSON: {ex.Message}. "
          + "Provide a JSON array or object, e.g. "
          + "[{{\"type\":\"MONTHLY_BY_DAY\",\"monthDay\":1,\"time\":\"04:00\",\"tz\":\"America/Chicago\"}}]",
          ex);
      }

      throw new ArgumentException(
        "Schedule JSON must start with '[' or '{'. "
        + "Example: [{\"type\":\"MONTHLY_BY_DAY\",\"monthDay\":1,\"time\":\"04:00\",\"tz\":\"America/Chicago\"}]");
    }

    private static List<object> ToObjectList(IList<Dictionary<string, object>> entries)
    {
      if (entries == null || entries.Count == 0)
      {
        return new List<object>();
      }

      return entries.Cast<object>().ToList();
    }

    private static bool TryGetScheduleEntry(object value, out Dictionary<string, object> entry)
    {
      entry = value as Dictionary<string, object>;
      return entry != null;
    }

    private static string NormalizeJsonArgument(string value)
    {
      var json = value?.Trim() ?? "";
      while (json.Length >= 2
             && ((json[0] == '\'' && json[json.Length - 1] == '\'')
                 || (json[0] == '"' && json[json.Length - 1] == '"')))
      {
        json = json.Substring(1, json.Length - 2).Trim();
      }

      return json;
    }

    public static string SerializeScheduleData(List<object> scheduleData)
    {
      if (scheduleData == null)
      {
        return "";
      }

      if (scheduleData.Count == 0)
      {
        return "";
      }

      var entries = new List<Dictionary<string, object>>();
      foreach (var item in scheduleData)
      {
        if (TryGetScheduleEntry(item, out var entry))
        {
          entries.Add(entry);
        }
      }

      if (entries.Count == 0)
      {
        return "";
      }

      return Encoding.UTF8.GetString(JsonUtils.DumpJson(entries, indent: false));
    }

    public static PasswordGenerationOptions ParsePasswordComplexityRules(string complexity)
    {
      if (complexity == null)
      {
        return null;
      }

      if (complexity.Length == 0)
      {
        return new PasswordGenerationOptions();
      }

      var parts = complexity.Split(new[] { ',' }, 6);
      if (parts.Length < 5 || !parts.Take(5).All(p => int.TryParse(p.Trim(), out _)))
      {
        throw new ArgumentException(
          "Invalid rules to generate password. Format is \"length, upper, lower, digits, symbols\". Ex: 32,5,5,5,5[,SPECIAL CHARS]");
      }

      var specialChars = DefaultSpecialChars;
      if (parts.Length == 6)
      {
        var builder = new StringBuilder();
        foreach (var ch in DefaultSpecialChars)
        {
          if (parts[5].IndexOf(ch) >= 0)
          {
            builder.Append(ch);
          }
        }

        specialChars = builder.ToString();
      }

      return new PasswordGenerationOptions
      {
        Length = int.Parse(parts[0].Trim()),
        Upper = int.Parse(parts[1].Trim()),
        Lower = int.Parse(parts[2].Trim()),
        Digit = int.Parse(parts[3].Trim()),
        Special = int.Parse(parts[4].Trim()),
        SpecialCharacters = specialChars,
      };
    }

    public static PasswordGenerationOptions ParsePasswordComplexityJson(byte[] json)
    {
      if (json == null || json.Length == 0)
      {
        return null;
      }

      try
      {
        return FromWireDictionary(JsonUtils.ParseJson<Dictionary<string, object>>(json));
      }
      catch (SerializationException ex)
      {
        throw new ArgumentException($"Invalid password complexity JSON: {ex.Message}", ex);
      }
    }

    public static bool TryDecryptPasswordComplexity(
      byte[] encrypted,
      byte[] recordKey,
      out PasswordGenerationOptions rules)
    {
      rules = null;
      if (encrypted == null || encrypted.Length == 0)
      {
        return true;
      }

      if (recordKey == null || recordKey.Length == 0)
      {
        return false;
      }

      try
      {
        rules = FromWireJson(CryptoUtils.DecryptAesV2(encrypted, recordKey));
        return true;
      }
      catch (Exception ex)
      {
        Trace.TraceWarning("PAM: failed to decrypt password complexity: {0}", ex.Message);
        return false;
      }
    }

    public static PasswordGenerationOptions DecryptPasswordComplexity(byte[] encrypted, byte[] recordKey)
    {
      return TryDecryptPasswordComplexity(encrypted, recordKey, out var rules)
        ? rules
        : null;
    }

    public static string FormatPasswordComplexityDisplay(PasswordGenerationOptions rules)
    {
      if (rules == null)
      {
        return "";
      }

      var chars = rules.SpecialCharacters ?? DefaultSpecialChars;
      return $"{rules.Length},{rules.Upper},{rules.Lower},{rules.Digit},{rules.Special},{chars}";
    }

    public static Dictionary<string, object> PasswordComplexityToDetail(PasswordGenerationOptions rules)
    {
      if (rules == null)
      {
        return null;
      }

      return new Dictionary<string, object>
      {
        ["length"] = rules.Length,
        ["caps"] = rules.Upper,
        ["lowercase"] = rules.Lower,
        ["digits"] = rules.Digit,
        ["special"] = rules.Special,
        ["specialChars"] = rules.SpecialCharacters ?? DefaultSpecialChars,
      };
    }

    private static void ValidateComplexityRules(PasswordGenerationOptions rules)
    {
      if (rules.Length < 0
          || rules.Upper < 0
          || rules.Lower < 0
          || rules.Digit < 0
          || rules.Special < 0)
      {
        throw new ArgumentException("Password complexity values must be non-negative.");
      }
    }

    private static byte[] ToWireJson(PasswordGenerationOptions rules)
    {
      return JsonUtils.DumpJson(PasswordComplexityToDetail(rules), indent: false);
    }

    private static PasswordGenerationOptions FromWireJson(byte[] json)
    {
      return FromWireDictionary(JsonUtils.ParseJson<Dictionary<string, object>>(json));
    }

    private static PasswordGenerationOptions FromWireDictionary(Dictionary<string, object> rules)
    {
      if (rules == null || rules.Count == 0)
      {
        return new PasswordGenerationOptions();
      }

      return new PasswordGenerationOptions
      {
        Length = ReadInt(rules, "length"),
        Upper = ReadInt(rules, "caps"),
        Lower = ReadInt(rules, "lowercase"),
        Digit = ReadInt(rules, "digits"),
        Special = ReadInt(rules, "special"),
        SpecialCharacters = rules.TryGetValue("specialChars", out var specialChars)
          ? specialChars?.ToString() ?? DefaultSpecialChars
          : DefaultSpecialChars,
      };
    }

    private static int ReadInt(Dictionary<string, object> values, string key)
    {
      if (!values.TryGetValue(key, out var raw) || raw == null)
      {
        return 0;
      }

      return raw switch
      {
        int i => i,
        long l => (int)l,
        _ => int.TryParse(raw.ToString(), out var parsed) ? parsed : 0,
      };
    }
  }
}
