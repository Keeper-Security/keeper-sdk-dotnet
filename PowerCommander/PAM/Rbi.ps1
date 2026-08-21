#requires -Version 5.1

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
        RBI permission on the resource: on, off, or default. Alias: -rbi.

        .Parameter ConnectionsRecording
        Session recording permission: on, off, or default. Alias: -cr.

        .Parameter KeyEvents
        Key events (recordingIncludeKeys): on, off, or default. Alias: -k.

        .Parameter AllowUrlNavigation
        Allow navigation via direct URL manipulation: on, off, or default. Alias: -nav.

        .Parameter IgnoreServerCert
        Ignore server certificate errors: on, off, or default. Alias: -isc.

        .Parameter AllowFileUploads
        Allow file uploads in RBI sessions: on, off, or default. Alias: -fu.

        .Parameter AllowFileDownloads
        Allow file downloads in RBI sessions: on, off, or default. Alias: -fd.

        .Parameter AllowedUrls
        Allowed URL patterns (comma-separated or array; replaces existing). Use empty string to clear. Alias: -au.

        .Parameter AllowedResourceUrls
        Allowed resource URL patterns (comma-separated or array; replaces existing). Use empty string to clear. Alias: -aru.

        .Parameter AutofillCredentials
        login or pamUser record UID/title for RBI autofill. Alias: -a.

        .Parameter AutofillTargets
        Autofill target selectors (comma-separated or array; replaces existing). Use empty string to clear. Alias: -at.

        .Parameter AllowCopy
        Allow copying to clipboard: on, off, or default. Alias: -cpy.

        .Parameter AllowPaste
        Allow pasting from clipboard: on, off, or default. Alias: -p.

        .Parameter DisableAudio
        Disable audio for RBI sessions: on, off, or default. Alias: -da.

        .Parameter AudioChannels
        Number of audio channels: 1 (mono) or 2 (stereo). Alias: -ac.

        .Parameter AudioBitDepth
        Audio bit depth: 8 or 16. Alias: -bd.

        .Parameter AudioSampleRate
        Audio sample rate in Hz (e.g. 44100, 48000). Alias: -sr.

        .Parameter SessionPersistence
        RBI session persistence: none, user, resource, or default. Alias: -sp.

        .Parameter Silent
        Suppress the final update confirmation line. Alias: -s.

        .Example
        Set-KeeperPamRbi -Record "<uid>" -RemoteBrowserIsolation on -AllowCopy off
        Set-KeeperPamRbi -r "My Browser" -c "AWS Config" -AllowedUrls "https://*.example.com"
        pam-rbi-edit -r "<uid>" -AllowFileDownloads on -SessionPersistence user
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [Alias('c')]
        [string] $Configuration,

        [Parameter()]
        [Alias('rbi')]
        [ValidateSet('on', 'off', 'default')]
        [string] $RemoteBrowserIsolation,

        [Parameter()]
        [Alias('cr')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('k')]
        [ValidateSet('on', 'off', 'default')]
        [string] $KeyEvents,

        [Parameter()]
        [Alias('nav')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowUrlNavigation,

        [Parameter()]
        [Alias('isc')]
        [ValidateSet('on', 'off', 'default')]
        [string] $IgnoreServerCert,

        [Parameter()]
        [Alias('fu')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowFileUploads,

        [Parameter()]
        [Alias('fd')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowFileDownloads,

        [Parameter()]
        [Alias('au')]
        [string[]] $AllowedUrls,

        [Parameter()]
        [Alias('aru')]
        [string[]] $AllowedResourceUrls,

        [Parameter()]
        [Alias('a')]
        [string] $AutofillCredentials,

        [Parameter()]
        [Alias('at')]
        [string[]] $AutofillTargets,

        [Parameter()]
        [Alias('cpy')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowCopy,

        [Parameter()]
        [Alias('p')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AllowPaste,

        [Parameter()]
        [Alias('da')]
        [ValidateSet('on', 'off', 'default')]
        [string] $DisableAudio,

        [Parameter()]
        [Alias('ac')]
        [ValidateSet(1, 2)]
        [int] $AudioChannels,

        [Parameter()]
        [Alias('bd')]
        [ValidateSet(8, 16)]
        [int] $AudioBitDepth,

        [Parameter()]
        [Alias('sr')]
        [int] $AudioSampleRate,

        [Parameter()]
        [Alias('sp')]
        [ValidateSet('none', 'user', 'resource', 'default')]
        [string] $SessionPersistence,

        [Parameter()]
        [Alias('s')]
        [switch] $Silent
    )

    if ([string]::IsNullOrWhiteSpace($Record)) {
        Write-Error -Message 'Record is required. Usage: Set-KeeperPamRbi -Record <UID> [-Configuration UID] [options]' -ErrorAction Stop
    }

    $vault = getVault
    $options = New-Object KeeperSecurity.Plugins.PAM.PamRbiEditOptions
    $options.Record = $Record.Trim()
    $options.Silent = $Silent.IsPresent

    # SDK treats null as "not provided"; PowerShell unbound strings are "".
    # Only assign flags the caller actually passed so single-flag edits work.
    $propertiesToMap = @(
        'Configuration', 'RemoteBrowserIsolation', 'ConnectionsRecording', 'KeyEvents',
        'AutofillCredentials', 'AllowUrlNavigation', 'IgnoreServerCert',
        'AllowFileUploads', 'AllowFileDownloads', 'AllowCopy', 'AllowPaste',
        'DisableAudio', 'SessionPersistence', 'AudioChannels', 'AudioBitDepth', 'AudioSampleRate'
    )
    $listProperties = @('AllowedUrls', 'AllowedResourceUrls', 'AutofillTargets')
    foreach ($prop in $propertiesToMap) {
        if ($PSBoundParameters.ContainsKey($prop)) {
            $options.$prop = $PSBoundParameters[$prop]
        }
    }
    foreach ($prop in $listProperties) {
        if ($PSBoundParameters.ContainsKey($prop)) {
            $options.$prop = toPamStringListOrNull -Values $PSBoundParameters[$prop]
        }
    }

    $result = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.RbiUtils]::EditRbiAsync(
            $vault, $options).GetAwaiter().GetResult()
    }
    if ($null -eq $result) {
        return
    }

    writePamEditResult -Result $result -Silent $Silent.IsPresent `
        -UpdatedMessage ("RBI settings updated for {0}" -f $result.RecordUid)
}

New-Alias -Name pam-rbi-edit -Value Set-KeeperPamRbi -ErrorAction SilentlyContinue
