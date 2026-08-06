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
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [Alias('c')]
        [string] $Configuration,

        [Parameter()]
        [Alias('a', 'admin-user')]
        [string] $AdminUser,

        [Parameter()]
        [Alias('lu', 'launch-user')]
        [string] $LaunchUser,

        [Parameter()]
        [Alias('clear-launch-user')]
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
        [Alias('cr', 'connections-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('tr', 'typescript-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $TypescriptRecording,

        [Parameter()]
        [Alias('cop', 'connections-override-port')]
        [string] $ConnectionsOverridePort,

        [Parameter()]
        [Alias('k', 'key-events')]
        [ValidateSet('on', 'off', 'default')]
        [string] $KeyEvents,

        [Parameter()]
        [Alias('sb')]
        [string] $Scrollback,

        [Parameter()]
        [Alias('rotate-on-termination')]
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
    $options.Configuration = $Configuration
    $options.AdminUser = $AdminUser
    $options.LaunchUser = $LaunchUser
    $options.ClearLaunchUser = $ClearLaunchUser.IsPresent
    $options.Protocol = $Protocol
    $options.Connections = $Connections
    $options.ConnectionsRecording = $ConnectionsRecording
    $options.TypescriptRecording = $TypescriptRecording
    $options.ConnectionsOverridePort = $ConnectionsOverridePort
    $options.KeyEvents = $KeyEvents
    $options.Scrollback = $Scrollback
    $options.RotateOnTermination = $RotateOnTermination
    $options.Silent = $Silent.IsPresent

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

    foreach ($message in $result.Messages) {
        Write-Output $message
    }

    if ($Silent.IsPresent) {
        return
    }

    if ($result.RecordUpdated -or $result.GraphUpdated) {
        Write-Output ("Connection settings updated for {0}" -f $result.RecordUid)
    }
}

New-Alias -Name pam-connection-edit -Value Set-KeeperPamConnection -ErrorAction SilentlyContinue
