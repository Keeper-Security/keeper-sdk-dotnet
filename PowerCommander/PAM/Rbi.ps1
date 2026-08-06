#requires -Version 5.1

function script:toPamStringListOrNull {
    Param ([string[]] $Values)

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return $null
    }

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }
        foreach ($part in $value.Split(@(','), [System.StringSplitOptions]::None)) {
            [void]$list.Add($part)
        }
    }

    if ($list.Count -eq 0) {
        return $null
    }
    return , $list
}

function Set-KeeperPamRbi {
    <#
        .Synopsis
        Configure PAM Remote Browser Isolation (RBI) settings.

        .Description
        Edits RBI permissions, recording, URL allowlists, autofill, clipboard, and audio
        settings for a pamRemoteBrowser record.

        .Parameter Record
        pamRemoteBrowser record UID or title. Alias: -r.

        .Parameter Configuration
        PAM Configuration UID or title. Alias: -c.

        .Parameter RemoteBrowserIsolation
        RBI permission on the resource: on, off, or default.

        .Parameter ConnectionsRecording
        Session recording permission: on, off, or default.

        .Parameter KeyEvents
        Key events (recordingIncludeKeys): on, off, or default. Alias: -k.

        .Parameter AllowUrlNavigation
        Allow navigation via direct URL manipulation: on, off, or default.

        .Parameter IgnoreServerCert
        Ignore server certificate errors: on, off, or default.

        .Parameter AllowFileUploads
        Allow file uploads in RBI sessions: on, off, or default.

        .Parameter AllowFileDownloads
        Allow file downloads in RBI sessions: on, off, or default.

        .Parameter AllowedUrls
        Allowed URL patterns (comma-separated or array; appends). Use empty string to clear.

        .Parameter AllowedResourceUrls
        Allowed resource URL patterns (comma-separated or array; appends). Use empty string to clear.

        .Parameter AutofillCredentials
        login or pamUser record UID/title for RBI autofill. Alias: -a.

        .Parameter AutofillTargets
        Autofill target selectors (comma-separated or array; appends). Use empty string to clear.

        .Parameter AllowCopy
        Allow copying to clipboard: on, off, or default.

        .Parameter AllowPaste
        Allow pasting from clipboard: on, off, or default. Alias: -p.

        .Parameter DisableAudio
        Disable audio for RBI sessions: on, off, or default.

        .Parameter AudioChannels
        Number of audio channels: 1 (mono) or 2 (stereo).

        .Parameter AudioBitDepth
        Audio bit depth: 8 or 16.

        .Parameter AudioSampleRate
        Audio sample rate in Hz (e.g. 44100, 48000).

        .Parameter SessionPersistence
        RBI session persistence: none, user, resource, or default.

        .Parameter Silent
        Suppress the final update confirmation line. Alias: -s.

        .Example
        Set-KeeperPamRbi -Record "<uid>" -RemoteBrowserIsolation on -AllowCopy off
        Set-KeeperPamRbi -r "My Browser" -c "AWS Config" -AllowedUrls "https://*.example.com"
        pam-rbi-edit -r "<uid>" -AllowFileDownloads on -SessionPersistence user
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [Alias('c')]
        [string] $Configuration,

        [Parameter()]
        [Alias('rbi', 'remote-browser-isolation')]
        [ValidateSet('on', 'off', 'default')]
        [string] $RemoteBrowserIsolation,

        [Parameter()]
        [Alias('cr', 'connections-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('k', 'key-events')]
        [ValidateSet('on', 'off', 'default')]
        [string] $KeyEvents,

        [Parameter()]
        [Alias('nav', 'allow-url-navigation')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowUrlNavigation,

        [Parameter()]
        [Alias('isc', 'ignore-server-cert')]
        [ValidateSet('on', 'off', 'default')]
        [string] $IgnoreServerCert,

        [Parameter()]
        [Alias('allow-file-uploads')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowFileUploads,

        [Parameter()]
        [Alias('allow-file-downloads')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowFileDownloads,

        [Parameter()]
        [Alias('au', 'allowed-urls')]
        [string[]] $AllowedUrls,

        [Parameter()]
        [Alias('aru', 'allowed-resource-urls')]
        [string[]] $AllowedResourceUrls,

        [Parameter()]
        [Alias('a', 'autofill-credentials')]
        [string] $AutofillCredentials,

        [Parameter()]
        [Alias('at', 'autofill-targets')]
        [string[]] $AutofillTargets,

        [Parameter()]
        [Alias('cpy', 'allow-copy')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowCopy,

        [Parameter()]
        [Alias('p', 'allow-paste')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowPaste,

        [Parameter()]
        [Alias('da', 'disable-audio')]
        [ValidateSet('on', 'off', 'default')]
        [string] $DisableAudio,

        [Parameter()]
        [Alias('ac', 'audio-channels')]
        [ValidateSet(1, 2)]
        [int] $AudioChannels,

        [Parameter()]
        [Alias('bd', 'audio-bit-depth')]
        [ValidateSet(8, 16)]
        [int] $AudioBitDepth,

        [Parameter()]
        [Alias('sr', 'audio-sample-rate')]
        [int] $AudioSampleRate,

        [Parameter()]
        [Alias('sp', 'session-persistence')]
        [ValidateSet('none', 'user', 'resource', 'default')]
        [string] $SessionPersistence,

        [Parameter()]
        [Alias('s')]
        [switch] $Silent
    )

    if ([string]::IsNullOrWhiteSpace($Record)) {
        Write-Output 'Record is required. Usage: Set-KeeperPamRbi -Record <UID> [-Configuration UID] [options]'
        return
    }

    $vault = getPamRotationVault

    $options = New-Object KeeperSecurity.Plugins.PAM.PamRbiEditOptions
    $options.Record = $Record.Trim()
    $options.Configuration = $Configuration
    $options.RemoteBrowserIsolation = $RemoteBrowserIsolation
    $options.ConnectionsRecording = $ConnectionsRecording
    $options.KeyEvents = $KeyEvents
    $options.AutofillCredentials = $AutofillCredentials
    $options.AllowUrlNavigation = $AllowUrlNavigation
    $options.IgnoreServerCert = $IgnoreServerCert
    $options.AllowFileUploads = $AllowFileUploads
    $options.AllowFileDownloads = $AllowFileDownloads
    $options.AllowedUrls = toPamStringListOrNull -Values $AllowedUrls
    $options.AllowedResourceUrls = toPamStringListOrNull -Values $AllowedResourceUrls
    $options.AutofillTargets = toPamStringListOrNull -Values $AutofillTargets
    $options.AllowCopy = $AllowCopy
    $options.AllowPaste = $AllowPaste
    $options.DisableAudio = $DisableAudio
    $options.SessionPersistence = $SessionPersistence
    $options.Silent = $Silent.IsPresent

    if ($PSBoundParameters.ContainsKey('AudioChannels')) {
        $options.AudioChannels = $AudioChannels
    }
    if ($PSBoundParameters.ContainsKey('AudioBitDepth')) {
        $options.AudioBitDepth = $AudioBitDepth
    }
    if ($PSBoundParameters.ContainsKey('AudioSampleRate')) {
        $options.AudioSampleRate = $AudioSampleRate
    }

    try {
        $result = [KeeperSecurity.Plugins.PAM.RbiUtils]::EditRbiAsync(
            $vault, $options).GetAwaiter().GetResult()
    }
    catch [KeeperSecurity.Plugins.PAM.PamException] {
        Write-Output $_.Exception.Message
        return
    }
    catch [System.InvalidOperationException] {
        Write-Output $_.Exception.Message
        return
    }

    foreach ($message in $result.Messages) {
        Write-Output $message
    }

    if ($Silent.IsPresent) {
        return
    }

    if ($result.RecordUpdated -or $result.GraphUpdated) {
        Write-Output ("RBI settings updated for {0}" -f $result.RecordUid)
    }
}

New-Alias -Name pam-rbi-edit -Value Set-KeeperPamRbi -ErrorAction SilentlyContinue
