using System;
using System.Collections.Generic;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// PAM vault record type names used by rotation and configuration commands.
  /// </summary>
  public static class PamRecordTypes
  {
    public static readonly HashSet<string> Rotation = Create(
      "pamUser",
      "pamDirectory",
      "pamDatabase",
      "pamMachine",
      "pamRemoteBrowser");

    public static readonly HashSet<string> Resource = Create(
      "pamMachine",
      "pamDatabase",
      "pamDirectory",
      "pamRemoteBrowser");

    public static readonly HashSet<string> Script = Create(
      "pamUser",
      "pamDirectory");

    public static readonly HashSet<string> Configuration = Create(
      "pamAwsConfiguration",
      "pamAzureConfiguration",
      "pamGcpConfiguration",
      "pamDomainConfiguration",
      "pamNetworkConfiguration",
      "pamOciConfiguration");

    private static HashSet<string> Create(params string[] types)
    {
      return new HashSet<string>(types, StringComparer.Ordinal);
    }
  }
}
