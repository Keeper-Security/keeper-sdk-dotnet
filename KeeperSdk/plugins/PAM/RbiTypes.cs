using System.Collections.Generic;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Options for <see cref="RbiUtils.EditRbiAsync"/>.
  /// Tri-state string fields accept on / off / default (null skips).
  /// </summary>
  public class PamRbiEditOptions
  {
    /// <summary>pamRemoteBrowser record UID or title.</summary>
    public string Record { get; set; }

    /// <summary>PAM Configuration UID or title.</summary>
    public string Configuration { get; set; }

    /// <summary>Enable RBI on the resource graph (maps to allowedSettings.connections).</summary>
    public string RemoteBrowserIsolation { get; set; }

    /// <summary>Session recording permission: on / off / default.</summary>
    public string ConnectionsRecording { get; set; }

    /// <summary>recordingIncludeKeys: on / off / default.</summary>
    public string KeyEvents { get; set; }

    /// <summary>login or pamUser record for HTTP autofill credentials.</summary>
    public string AutofillCredentials { get; set; }

    /// <summary>allowUrlManipulation.</summary>
    public string AllowUrlNavigation { get; set; }

    /// <summary>ignoreInitialSslCert.</summary>
    public string IgnoreServerCert { get; set; }

    /// <summary>allowFileUploads.</summary>
    public string AllowFileUploads { get; set; }

    /// <summary>allowFileDownloads.</summary>
    public string AllowFileDownloads { get; set; }

    /// <summary>URL allow-list patterns (joined with newlines).</summary>
    public IList<string> AllowedUrls { get; set; }

    /// <summary>Resource URL allow-list patterns (joined with newlines).</summary>
    public IList<string> AllowedResourceUrls { get; set; }

    /// <summary>Autofill target selectors (joined with newlines).</summary>
    public IList<string> AutofillTargets { get; set; }

    /// <summary>Allow clipboard copy (inverted to disableCopy).</summary>
    public string AllowCopy { get; set; }

    /// <summary>Allow clipboard paste (inverted to disablePaste).</summary>
    public string AllowPaste { get; set; }

    /// <summary>disableAudio.</summary>
    public string DisableAudio { get; set; }

    /// <summary>Audio channel count.</summary>
    public int? AudioChannels { get; set; }

    /// <summary>Audio bit depth (8 or 16) stored as audioBps.</summary>
    public int? AudioBitDepth { get; set; }

    /// <summary>Audio sample rate in Hz.</summary>
    public int? AudioSampleRate { get; set; }

    /// <summary>none / user / resource / default.</summary>
    public string SessionPersistence { get; set; }

    /// <summary>Suppress PAM config warning output.</summary>
    public bool Silent { get; set; }
  }

  /// <summary>
  /// Result of an RBI edit.
  /// </summary>
  public class PamRbiEditResult
  {
    public string RecordUid { get; set; }
    public string ConfigUid { get; set; }
    public bool RecordUpdated { get; set; }
    public bool GraphUpdated { get; set; }
    public IList<string> Messages { get; set; } = new List<string>();
  }
}
