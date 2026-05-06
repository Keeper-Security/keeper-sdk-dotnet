function Resolve-KeeperEpmDeployment {
    <#
    .Synopsis
        Resolve deployment(s) by UID or name (case-insensitive). Returns matching deployment(s) as an array.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )
    $id = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($id)) { return @() }

    $deployment = $Plugin.Deployments.GetEntity($id)
    if ($null -ne $deployment) { return @($deployment) }

    $lName = $id.ToLowerInvariant()
    return @($Plugin.Deployments.GetAll() | Where-Object { $_.Name -and $_.Name.ToLowerInvariant() -eq $lName })
}

function script:Resolve-KeeperEpmSingleDeployment {
    param(
        [Parameter(Mandatory = $true)][string]$Identifier,
        [Parameter(Mandatory = $true)][object]$Plugin
    )
    $deployments = @(Resolve-KeeperEpmDeployment -Identifier $Identifier -Plugin $Plugin)
    if ($deployments.Count -eq 0) {
        Write-Error -Message "Deployment '$Identifier' not found." -ErrorAction Stop
    }
    if ($deployments.Count -gt 1) {
        Write-Warning "Multiple deployments found with name `"$Identifier`":"
        foreach ($d in $deployments) {
            Write-Warning "  UID: $($d.DeploymentUid)  Name: $($d.Name)"
        }
        Write-Error -Message "Deployment name `"$Identifier`" is not unique. Use Deployment UID." -ErrorAction Stop
    }
    return $deployments[0]
}

function Get-KeeperEpmDeploymentList {
    <#
    .Synopsis
        List all EPM deployments.
    .Description
        Takes no parameters. Lists deployment UID, name, disabled state, created/modified timestamps, and agent count.
    #>
    [CmdletBinding()]
    Param ()

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployments = @($plugin.Deployments.GetAll())
    if ($deployments.Count -eq 0) {
        Write-Output "No deployments found."
        return
    }

    $deployments = $deployments | Sort-Object -Property Name
    $rows = foreach ($dep in $deployments) {
        $agentCount = @($plugin.DeploymentAgents.GetLinksForSubject($dep.DeploymentUid)).Count
        $created = [DateTimeOffset]::FromUnixTimeMilliseconds($dep.Created).ToString("yyyy-MM-dd HH:mm:ss")
        $updated = [DateTimeOffset]::FromUnixTimeMilliseconds($dep.Modified).ToString("yyyy-MM-dd HH:mm:ss")
        [PSCustomObject]@{
            'Deployment UID' = $dep.DeploymentUid
            'Name'           = $dep.Name
            'Disabled'       = if ($dep.Disabled) { 'True' } else { 'False' }
            'Created'        = $created
            'Modified'       = $updated
            'Agent Count'    = $agentCount
        }
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmDeployment {
    <#
    .Synopsis
        View a single EPM deployment by UID or name.
    .Parameter DeploymentUidOrName
        Deployment UID or deployment name (case-insensitive).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $DeploymentUidOrName
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployment = Resolve-KeeperEpmSingleDeployment -Identifier $DeploymentUidOrName -Plugin $plugin

    $created = [DateTimeOffset]::FromUnixTimeMilliseconds($deployment.Created).ToString("yyyy-MM-dd HH:mm:ss")
    $modified = [DateTimeOffset]::FromUnixTimeMilliseconds($deployment.Modified).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "Deployment: $($deployment.Name)"
    Write-Output "  UID: $($deployment.DeploymentUid)"
    Write-Output "  Status: $(if ($deployment.Disabled) { 'Disabled' } else { 'Active' })"
    Write-Output "  Created: $created"
    Write-Output "  Modified: $modified"
}

function Add-KeeperEpmDeployment {
    <#
    .Synopsis
        Add a new EPM deployment.
    .Parameter Name
        Deployment display name.
    .Parameter Force
        If set, allow adding a deployment whose name already exists.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $nameValue = $Name.Trim()
    if ([string]::IsNullOrEmpty($nameValue)) {
        Write-Error -Message "Deployment name is required for 'add' command." -ErrorAction Stop
    }

    if (-not $Force) {
        $lName = $nameValue.ToLowerInvariant()
        $hasName = $plugin.Deployments.GetAll() | Where-Object { $_.Name -and $_.Name.ToLowerInvariant() -eq $lName }
        if ($hasName) {
            Write-Error -Message "Deployment `"$nameValue`" already exists." -ErrorAction Stop
        }
    }

    $addDeployment = New-Object KeeperSecurity.Plugins.EPM.DeploymentDataInput
    $addDeployment.Name = $nameValue

    $addStatus = $plugin.ModifyDeployments(
        [KeeperSecurity.Plugins.EPM.DeploymentDataInput[]]@($addDeployment),
        $null,
        $null
    ).GetAwaiter().GetResult()

    if ($addStatus.AddErrors -and $addStatus.AddErrors.Count -gt 0) {
        $err = $addStatus.AddErrors[0]
        Write-Error -Message "Failed to add deployment `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
    }
    if ($addStatus.Add -and $addStatus.Add.Count -gt 0) {
        Write-Output "Deployment '$nameValue' added."
    } else {
        Write-Warning "No deployment was added. Check server response."
    }
    writeEpmModifyStatus -Status $addStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Update-KeeperEpmDeployment {
    <#
    .Synopsis
        Update an existing EPM deployment.
    .Parameter DeploymentUidOrName
        Deployment UID or deployment name (case-insensitive).
    .Parameter Name
        New deployment display name.
    .Parameter Enable
        Use 'on' or 'off' to enable or disable the deployment.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $DeploymentUidOrName,
        [Parameter()]
        [string] $Name,
        [Parameter()]
        [ValidateSet('on', 'off')]
        [string] $Enable
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployment = Resolve-KeeperEpmSingleDeployment -Identifier $DeploymentUidOrName -Plugin $plugin

    $updateDeployment = New-Object KeeperSecurity.Plugins.EPM.DeploymentDataInput
    $updateDeployment.DeploymentUid = $deployment.DeploymentUid
    $updateDeployment.Name = if ($Name) { $Name.Trim() } else { $deployment.Name }
    if (-not [string]::IsNullOrWhiteSpace($Enable)) {
        $enableLower = $Enable.Trim().ToLowerInvariant()
        if ($enableLower -eq 'on') { $updateDeployment.Disabled = $false }
        elseif ($enableLower -eq 'off') { $updateDeployment.Disabled = $true }
    }

    $updateStatus = $plugin.ModifyDeployments(
        $null,
        [KeeperSecurity.Plugins.EPM.DeploymentDataInput[]]@($updateDeployment),
        $null
    ).GetAwaiter().GetResult()

    if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
        $err = $updateStatus.UpdateErrors[0]
        Write-Error -Message "Failed to update deployment `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
    }
    if ($updateStatus.Update -and $updateStatus.Update.Count -gt 0) {
        Write-Output "Deployment '$($deployment.DeploymentUid)' updated."
    } else {
        Write-Warning "No deployment was updated. Check server response."
    }

    writeEpmModifyStatus -Status $updateStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Remove-KeeperEpmDeployment {
    <#
    .Synopsis
        Remove an EPM deployment.
    .Parameter DeploymentUidOrName
        Deployment UID or deployment name (case-insensitive).
    .Parameter Force
        If set, skip confirmation prompt before delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $DeploymentUidOrName,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployment = Resolve-KeeperEpmSingleDeployment -Identifier $DeploymentUidOrName -Plugin $plugin

    $deploymentUid = $deployment.DeploymentUid
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("deployment '$($deployment.Name)'", "Delete")) {
        return
    }

    $removeStatus = $plugin.ModifyDeployments(
        $null,
        $null,
        [string[]]@($deploymentUid)
    ).GetAwaiter().GetResult()

    if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
        $err = $removeStatus.RemoveErrors[0]
        Write-Error -Message "Failed to delete deployment `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
    }
    if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
        Write-Output "Deployment '$deploymentUid' deleted."
    } else {
        Write-Warning "No deployment was deleted. Check server response."
    }

    writeEpmModifyStatus -Status $removeStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Get-KeeperEpmDeploymentDownload {
    <#
    .Synopsis
        Get deployment token and agent download URLs.
    .Description
        Outputs deployment token and Windows/MacOS/Linux download URLs. Optionally writes to a file.
    .Parameter DeploymentUidOrName
        Deployment UID or deployment name (case-insensitive).
    .Parameter File
        Optional path to write token and download lines (tab-separated) as UTF-8.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $DeploymentUidOrName,
        [Parameter()]
        [string] $File
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployment = Resolve-KeeperEpmSingleDeployment -Identifier $DeploymentUidOrName -Plugin $plugin

    if (-not $deployment.PrivateKey -or $deployment.PrivateKey.Length -eq 0) {
        Write-Error -Message "Deployment '$($deployment.DeploymentUid)' does not have a private key." -ErrorAction Stop
    }

    $ent = getEnterprise
    $hostName = if ($ent -and $ent.loader -and $ent.loader.Auth -and $ent.loader.Auth.Endpoint -and $ent.loader.Auth.Endpoint.Server) {
        $ent.loader.Auth.Endpoint.Server
    } else {
        'keepersecurity.com'
    }

    Write-Warning "The deployment token contains a private key. Treat it as a secret and do not share it insecurely."

    $privateKeyB64 = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($deployment.PrivateKey)
    $token = "${hostName}:$($deployment.DeploymentUid):$privateKeyB64"

    $path = ''
    $windows = ''
    $macos = ''
    $linux = ''
    $manifestHost = $hostName
    if ($manifestHost.Contains('.')) {
        $parts = $manifestHost.Split('.')
        if ($parts.Length -ge 2) {
            $manifestHost = $parts[$parts.Length - 2] + '.' + $parts[$parts.Length - 1]
        }
    }

    $manifestUrl = "https://${manifestHost}/pam/pedm/package-manifest.json"
    try {
        $response = Invoke-WebRequest -Uri $manifestUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $manifest = $response.Content | ConvertFrom-Json
        if ($manifest.Core -and $manifest.Core.Count -gt 0) {
            $selected = $manifest.Core | Where-Object { $_.Version -eq 'Latest' } | Select-Object -First 1
            if (-not $selected) { $selected = $manifest.Core[0] }
            $path = $selected.Path
            if (-not [string]::IsNullOrEmpty($path) -and -not $path.EndsWith('/')) { $path += '/' }
            $windows = $selected.WindowsZip
            $macos = $selected.MacOsZip
            $linux = $selected.LinuxZip
        }
    } catch {
        Write-Warning "Failed to fetch manifest from $manifestUrl"
    }

    $fileLines = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrEmpty($path)) {
        $platforms = @(
            @{ Label = 'Windows'; File = $windows }
            @{ Label = 'MacOS';   File = $macos }
            @{ Label = 'Linux';   File = $linux }
        )
        $hasAny = $false
        foreach ($p in $platforms) {
            if (-not [string]::IsNullOrEmpty($p.File)) {
                $url = $path + $p.File
                Write-Output "$($p.Label) download URL`t$url"
                $fileLines.Add("$($p.Label) download URL`t$url")
                $hasAny = $true
            }
        }
        if ($hasAny) {
            $fileLines.Add('')
        }
    }
    Write-Output "Deployment Token`t$token"
    $fileLines.Add("Deployment Token`t$token")

    if (-not [string]::IsNullOrWhiteSpace($File)) {
        $fileLines -join [Environment]::NewLine | Set-Content -Path $File -Encoding UTF8
        Write-Output "Deployment token and download URLs written to: $File"
    }
}

New-Alias -Name kepm-deployment-list    -Value Get-KeeperEpmDeploymentList     -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-view    -Value Get-KeeperEpmDeployment         -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-add     -Value Add-KeeperEpmDeployment         -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-edit    -Value Update-KeeperEpmDeployment      -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-delete  -Value Remove-KeeperEpmDeployment      -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-download -Value Get-KeeperEpmDeploymentDownload -ErrorAction SilentlyContinue
