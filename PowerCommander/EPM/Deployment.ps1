function Resolve-KeeperEpmDeployment {
    <#
    .Synopsis
        Resolve a deployment by UID or name (case-insensitive). Returns $null if not found or not unique.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )
    $id = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($id)) { return $null }

    $deployment = $Plugin.Deployments.GetEntity($id)
    if ($null -ne $deployment) { return $deployment }

    $lName = $id.ToLowerInvariant()
    $deployments = @($Plugin.Deployments.GetAll() | Where-Object { $_.Name -and $_.Name.ToLowerInvariant() -eq $lName })
    if ($deployments.Count -eq 0) { return $null }
    if ($deployments.Count -gt 1) {
        Write-Warning "Deployment name `"$id`" is not unique. Use Deployment UID."
        return $null
    }
    return $deployments[0]
}

function Get-KeeperEpmDeploymentList {
    <#
    .Synopsis
        List all EPM deployments (mirrors Commander "epm-deployment list").
    .Description
        Lists deployment UID, name, disabled state, created/modified timestamps, and agent count.
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
            'Updated'        = $updated
            'Agent Count'    = $agentCount
        }
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmDeployment {
    <#
    .Synopsis
        View a single EPM deployment by UID or name (mirrors Commander "epm-deployment view").
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

    $deployment = Resolve-KeeperEpmDeployment -Identifier $DeploymentUidOrName -Plugin $plugin
    if (-not $deployment) {
        Write-Error -Message "Deployment '$DeploymentUidOrName' not found." -ErrorAction Stop
    }

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
        Add a new EPM deployment (mirrors Commander "epm-deployment add").
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter()]
        [string] $SpiffeCert,
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

    $spiffeCertBase64 = $null
    if (-not [string]::IsNullOrWhiteSpace($SpiffeCert)) {
        $spiffeValue = $SpiffeCert.Trim()
        if (Test-Path -LiteralPath $spiffeValue -PathType Leaf) {
            try {
                $ext = [System.IO.Path]::GetExtension($spiffeValue).ToLowerInvariant()
                if ($ext -eq '.cer' -or $ext -eq '.der') {
                    $certBytes = [System.IO.File]::ReadAllBytes($spiffeValue)
                } else {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($spiffeValue)
                    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                }
                $spiffeCertBase64 = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($certBytes)
            } catch {
                Write-Error -Message "Failed to load SPIFFE certificate from file `"$spiffeValue`": $($_.Exception.Message)" -ErrorAction Stop
            }
        } else {
            $spiffeCertBase64 = $spiffeValue
        }
    }

    $addDeployment = New-Object KeeperSecurity.Plugins.EPM.DeploymentDataInput
    $addDeployment.Name = $nameValue
    $addDeployment.SpiffeCert = $spiffeCertBase64

    $addStatus = $plugin.ModifyDeployments(
        [object[]]@($addDeployment),
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
        Write-Warning "No deployment was added. Check server response for errors."
    }
    writeEpmModifyStatus $addStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult()
}

function Update-KeeperEpmDeployment {
    <#
    .Synopsis
        Update an existing EPM deployment (mirrors Commander "epm-deployment update").
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $DeploymentUidOrName,
        [Parameter()]
        [string] $Name,
        [Parameter()]
        [string] $Disabled,
        [Parameter()]
        [string] $SpiffeCert
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $deployment = Resolve-KeeperEpmDeployment -Identifier $DeploymentUidOrName -Plugin $plugin
    if (-not $deployment) {
        Write-Error -Message "Deployment '$DeploymentUidOrName' not found." -ErrorAction Stop
    }

    $updateDeployment = New-Object KeeperSecurity.Plugins.EPM.DeploymentDataInput
    $updateDeployment.DeploymentUid = $deployment.DeploymentUid
    $updateDeployment.Name = if ($Name) { $Name.Trim() } else { $deployment.Name }
    $parsedDisabled = parseEpmBool $Disabled
    if ($null -ne $parsedDisabled) { $updateDeployment.Disabled = $parsedDisabled }
    $updateDeployment.SpiffeCert = $SpiffeCert

    $updateStatus = $plugin.ModifyDeployments(
        $null,
        [object[]]@($updateDeployment),
        $null
    ).GetAwaiter().GetResult()

    Write-Output "Deployment '$($deployment.DeploymentUid)' updated."
    writeEpmModifyStatus $updateStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult()
}

function Remove-KeeperEpmDeployment {
    <#
    .Synopsis
        Remove an EPM deployment (mirrors Commander "epm-deployment remove").
    #>
    [CmdletBinding()]
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

    $deployment = Resolve-KeeperEpmDeployment -Identifier $DeploymentUidOrName -Plugin $plugin
    if (-not $deployment) {
        Write-Error -Message "Deployment `"$DeploymentUidOrName`" does not exist." -ErrorAction Stop
    }

    $deploymentUid = $deployment.DeploymentUid
    if (-not $Force) {
        $answer = Read-Host "Do you want to delete 1 deployment(s)? [y/n]"
        if ([string]::IsNullOrWhiteSpace($answer) -or -not $answer.Trim().StartsWith('y', [StringComparison]::InvariantCultureIgnoreCase)) {
            return
        }
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
    writeEpmModifyStatus $removeStatus
    $plugin.SyncDown($false).GetAwaiter().GetResult()
}

function Get-KeeperEpmDeploymentDownload {
    <#
    .Synopsis
        Get deployment token and agent download URLs.
    .Description
        Outputs deployment token and Windows/MacOS/Linux download URLs. Optionally writes to a file.
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

    $deployment = Resolve-KeeperEpmDeployment -Identifier $DeploymentUidOrName -Plugin $plugin
    if (-not $deployment) {
        Write-Error -Message "Deployment '$DeploymentUidOrName' not found." -ErrorAction Stop
    }

    if (-not $deployment.PrivateKey -or $deployment.PrivateKey.Length -eq 0) {
        Write-Error -Message "Deployment '$($deployment.DeploymentUid)' does not have a private key." -ErrorAction Stop
    }

    $ent = getEnterprise
    $hostName = if ($ent -and $ent.loader -and $ent.loader.Auth -and $ent.loader.Auth.Endpoint -and $ent.loader.Auth.Endpoint.Server) {
        $ent.loader.Auth.Endpoint.Server
    } else {
        'keepersecurity.com'
    }

    $privateKeyB64 = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($deployment.PrivateKey)
    $token = "${hostName}:$($deployment.DeploymentUid):$privateKeyB64"

    $path = ''
    $windows = ''
    $macos = ''
    $linux = ''
    $hostname = $hostName
    if ($hostname.Contains('.')) {
        $parts = $hostname.Split('.')
        if ($parts.Length -ge 2) {
            $hostname = $parts[$parts.Length - 2] + '.' + $parts[$parts.Length - 1]
        }
    }

    $manifestUrl = "https://${hostname}/pam/pedm/package-manifest.json"
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
        if (-not [string]::IsNullOrEmpty($windows)) {
            $windowsUrl = $path + $windows
            Write-Output "Windows download URL`t$windowsUrl"
            $fileLines.Add("Windows download URL`t$windowsUrl")
        }
        if (-not [string]::IsNullOrEmpty($macos)) {
            $macosUrl = $path + $macos
            Write-Output "MacOS download URL`t$macosUrl"
            $fileLines.Add("MacOS download URL`t$macosUrl")
        }
        if (-not [string]::IsNullOrEmpty($linux)) {
            $linuxUrl = $path + $linux
            Write-Output "Linux download URL`t$linuxUrl"
            $fileLines.Add("Linux download URL`t$linuxUrl")
        }
        if ($windows -or $macos -or $linux) {
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
New-Alias -Name kepm-deployment-add     -Value Add-KeeperEpmDeployment         -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-edit    -Value Update-KeeperEpmDeployment      -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-delete  -Value Remove-KeeperEpmDeployment      -ErrorAction SilentlyContinue
New-Alias -Name kepm-deployment-download -Value Get-KeeperEpmDeploymentDownload -ErrorAction SilentlyContinue
