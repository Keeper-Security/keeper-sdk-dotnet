#requires -Version 5.1

function Set-KeeperPamConnection {
    <#
        .Synopsis
        Configure PAM connection settings on a resource or configuration record.

        .Description
        Edits connection protocol, credentials, recording, and related permissions for a PAM
        machine, database, directory, remote browser, or PAM configuration record.

        .Parameter Record
        PAM resource or configuration record UID or title. Alias: -r.

        .Parameter Configuration
        PAM Configuration UID or title. Alias: -c.

        .Parameter AdminUser
        PAM User UID/title for admin credential. Alias: -a.

        .Parameter LaunchUser
        PAM User UID/title for launch credential.

        .Parameter ClearLaunchUser
        Remove launch credential from the resource.

        .Parameter Protocol
        Connection protocol (ssh, rdp, mysql, postgresql, sql-server, ...). Empty clears. Alias: -p.

        .Parameter Connections
        Connections permission: on, off, or default.

        .Parameter ConnectionsRecording
        Session recording permission: on, off, or default.

        .Parameter TypescriptRecording
        TypeScript recording permission: on, off, or default.

        .Parameter ConnectionsOverridePort
        Port override for connections. Empty clears.

        .Parameter KeyEvents
        Key events (recordingIncludeKeys): on, off, or default. Alias: -k.

        .Parameter Scrollback
        Terminal scrollback size. Empty clears.

        .Parameter RotateOnTermination
        Rotate launch credentials on session end: on or off.

        .Parameter Silent
        Suppress the final update confirmation line. Alias: -s.

        .Example
        Set-KeeperPamConnection -Record "<uid>" -Protocol ssh -Connections on
        Set-KeeperPamConnection -r "My Server" -c "AWS Config" -AdminUser "admin-user" -LaunchUser "launch-user"
        pam-connection-edit -r "<uid>" -Protocol rdp -ConnectionsRecording on
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
        [Alias('a')]
        [string] $AdminUser,

        [Parameter()]
        [Alias('lu')]
        [string] $LaunchUser,

        [Parameter()]
        [switch] $ClearLaunchUser,

        [Parameter()]
        [Alias('p')]
        [ValidateSet('', 'http', 'kubernetes', 'mysql', 'postgresql', 'rdp', 'sql-server', 'ssh', 'telnet', 'vnc')]
        [string] $Protocol,

        [Parameter()]
        [Alias('cn')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Connections,

        [Parameter()]
        [Alias('cr')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('tr')]
        [ValidateSet('on', 'off', 'default')]
        [string] $TypescriptRecording,

        [Parameter()]
        [Alias('cop')]
        [string] $ConnectionsOverridePort,

        [Parameter()]
        [Alias('k')]
        [ValidateSet('on', 'off', 'default')]
        [string] $KeyEvents,

        [Parameter()]
        [Alias('sb')]
        [string] $Scrollback,

        [Parameter()]
        [ValidateSet('on', 'off')]
        [string] $RotateOnTermination,

        [Parameter()]
        [Alias('s')]
        [switch] $Silent
    )

    if ([string]::IsNullOrWhiteSpace($Record)) {
        Write-Output 'Record is required. Usage: Set-KeeperPamConnection -Record <record> [-Configuration UID] [options]'
        return
    }

    $vault = getPamRotationVault
    $options = New-Object KeeperSecurity.Plugins.PAM.PamConnectionEditOptions
    $options.Record = $Record.Trim()
    $options.ClearLaunchUser = $ClearLaunchUser.IsPresent
    $options.Silent = $Silent.IsPresent

    if ($PSBoundParameters.ContainsKey('Configuration')) { $options.Configuration = $Configuration }
    if ($PSBoundParameters.ContainsKey('AdminUser')) { $options.AdminUser = $AdminUser }
    if ($PSBoundParameters.ContainsKey('LaunchUser')) { $options.LaunchUser = $LaunchUser }
    if ($PSBoundParameters.ContainsKey('Protocol')) { $options.Protocol = $Protocol }
    if ($PSBoundParameters.ContainsKey('Connections')) { $options.Connections = $Connections }
    if ($PSBoundParameters.ContainsKey('ConnectionsRecording')) { $options.ConnectionsRecording = $ConnectionsRecording }
    if ($PSBoundParameters.ContainsKey('TypescriptRecording')) { $options.TypescriptRecording = $TypescriptRecording }
    if ($PSBoundParameters.ContainsKey('ConnectionsOverridePort')) { $options.ConnectionsOverridePort = $ConnectionsOverridePort }
    if ($PSBoundParameters.ContainsKey('KeyEvents')) { $options.KeyEvents = $KeyEvents }
    if ($PSBoundParameters.ContainsKey('Scrollback')) { $options.Scrollback = $Scrollback }
    if ($PSBoundParameters.ContainsKey('RotateOnTermination')) { $options.RotateOnTermination = $RotateOnTermination }

    # SDK requires connections=on before protocol/port/key-events/scrollback can be applied.
    if (-not $PSBoundParameters.ContainsKey('Connections')) {
        $needsConnectionsOn = $PSBoundParameters.ContainsKey('Protocol') `
            -or $PSBoundParameters.ContainsKey('ConnectionsOverridePort') `
            -or $PSBoundParameters.ContainsKey('KeyEvents') `
            -or $PSBoundParameters.ContainsKey('Scrollback')
        if ($needsConnectionsOn) {
            $options.Connections = 'on'
        }
    }

    try {
        $result = [KeeperSecurity.Plugins.PAM.ConnectionUtils]::EditConnectionAsync(
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

    writePamEditResult -Result $result -Silent $Silent.IsPresent `
        -UpdatedMessage ("Connection settings updated for {0}" -f $result.RecordUid)
}

New-Alias -Name pam-connection-edit -Value Set-KeeperPamConnection -ErrorAction SilentlyContinue
