function script:Resolve-KeeperEpmCollection {
    <#
    .Synopsis
        Resolve collection(s) by UID or name (case-insensitive). Returns matching collection(s) as an array.
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

    $collection = $Plugin.Collections.GetEntity($id)
    if ($null -ne $collection) { return @($collection) }

    $nameMatches = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $Plugin.Collections.GetAll()) {
        if (-not $c.CollectionData -or $c.CollectionData.Length -eq 0) { continue }
        try {
            $jsonStr = [System.Text.Encoding]::UTF8.GetString($c.CollectionData)
            $data = $jsonStr | ConvertFrom-Json
            if ($data.PSObject.Properties['Name'] -and $data.Name -and $data.Name.Equals($id, [System.StringComparison]::OrdinalIgnoreCase)) {
                $nameMatches.Add($c)
            }
        } catch {
            Write-Debug "Failed to parse CollectionData for $($c.CollectionUid): $($_.Exception.Message)"
        }
    }
    return @($nameMatches)
}

function script:Resolve-KeeperEpmSingleCollection {
    <#
    .Synopsis
        Resolve a single collection by UID or name. Errors if not found or not unique.
    #>
    Param (
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][object] $Plugin
    )
    $collections = @(Resolve-KeeperEpmCollection -Identifier $Identifier -Plugin $Plugin)
    if ($collections.Count -eq 0) {
        Write-Error -Message "Collection '$Identifier' not found." -ErrorAction Stop
    }
    if ($collections.Count -gt 1) {
        Write-Warning "Multiple collections found with name `"$Identifier`":"
        foreach ($c in $collections) {
            $name = Get-KeeperEpmCollectionName -Collection $c
            Write-Warning "  UID: $($c.CollectionUid)  Name: $name"
        }
        Write-Error -Message "Collection name `"$Identifier`" is not unique. Use Collection UID." -ErrorAction Stop
    }
    return $collections[0]
}

function script:Get-KeeperEpmCollectionName {
    Param ([object] $Collection)
    if (-not $Collection.CollectionData -or $Collection.CollectionData.Length -eq 0) { return '' }
    try {
        $jsonStr = [System.Text.Encoding]::UTF8.GetString($Collection.CollectionData)
        $data = $jsonStr | ConvertFrom-Json
        if ($data.PSObject.Properties['Name'] -and $data.Name) { return [string]$data.Name }
    } catch {
        Write-Debug "Failed to parse CollectionData: $($_.Exception.Message)"
    }
    return ''
}

function script:ConvertFrom-KeeperEpmLinkType {
    Param ([string] $LinkType)
    $v = $LinkType.Trim().ToLowerInvariant()
    switch ($v) {
        'agent'      { return $script:CltAgent }
        'policy'     { return $script:CltPolicy }
        'collection' { return $script:CltCollection }
        default      { return $null }
    }
}

function Get-KeeperEpmCollectionList {
    <#
    .Synopsis
        List all EPM collections.
    .Parameter CollectionType
        Optional collection type number to filter results (1=OS Build, 2=Application, 3=User Account, 4=Group Account, 202=OS Version).
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [int] $CollectionType = -1
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collections = @($plugin.Collections.GetAll())

    $hasTypeFilter = $PSBoundParameters.ContainsKey('CollectionType')
    if ($hasTypeFilter) {
        $collections = @($collections | Where-Object { $_.CollectionType -eq $CollectionType })
    }

    if ($collections.Count -eq 0) {
        if ($hasTypeFilter) {
            $typeName = getEpmCollectionTypeName -CollectionType $CollectionType
            Write-Output "No collections found for type: $typeName (Type $CollectionType)"
        } else {
            Write-Output "No collections found."
        }
        return
    }

    $collections = $collections | Sort-Object -Property CollectionType, CollectionUid
    $rows = foreach ($coll in $collections) {
        $typeName = getEpmCollectionTypeName -CollectionType $coll.CollectionType
        $name = Get-KeeperEpmCollectionName -Collection $coll
        [PSCustomObject]@{
            'Collection UID'  = $coll.CollectionUid
            'Collection Type' = $typeName
            'Name'            = $name
        }
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmCollection {
    <#
    .Synopsis
        View a single EPM collection by UID or name.
    .Parameter CollectionUidOrName
        Collection UID or name (case-insensitive).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $CollectionUidOrName
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collection = Resolve-KeeperEpmSingleCollection -Identifier $CollectionUidOrName -Plugin $plugin

    $created = [DateTimeOffset]::FromUnixTimeMilliseconds($collection.Created).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "Collection: $($collection.CollectionUid)"
    Write-Output "  Type: $(getEpmCollectionTypeName -CollectionType $collection.CollectionType)"
    Write-Output "  Created: $created"

    if ($collection.CollectionData -and $collection.CollectionData.Length -gt 0) {
        try {
            $jsonStr = [System.Text.Encoding]::UTF8.GetString($collection.CollectionData)
            $data = $jsonStr | ConvertFrom-Json
            if ($data.PSObject.Properties['Name'] -and $data.Name) {
                Write-Output "  Name: $($data.Name)"
            }
            foreach ($prop in $data.PSObject.Properties) {
                if ($prop.Name -eq 'Name') { continue }
                $val = $prop.Value
                if ($val -is [System.Management.Automation.PSCustomObject]) {
                    Write-Output "  $($prop.Name):"
                    foreach ($inner in $val.PSObject.Properties) {
                        Write-Output "    $($inner.Name): $($inner.Value)"
                    }
                } elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    Write-Output "  $($prop.Name): [$($val -join ', ')]"
                } else {
                    Write-Output "  $($prop.Name): $val"
                }
            }
        } catch {
            try {
                $dataJson = [System.Text.Encoding]::UTF8.GetString($collection.CollectionData)
                Write-Output "  Data: $dataJson"
            } catch {
                Write-Output "  Data: (binary data, $($collection.CollectionData.Length) bytes)"
            }
        }
    }
}

function Add-KeeperEpmCollection {
    <#
    .Synopsis
        Add a new EPM collection.
    .Parameter CollectionUid
        Optional collection UID. If omitted, one is generated automatically.
    .Parameter CollectionType
        Collection type (required). 1=OS Build, 2=Application, 3=User Account, 4=Group Account, 202=OS Version.
    .Parameter Data
        Collection data as a JSON string.
    .Parameter DataFile
        Path to a file containing collection data JSON.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [string] $CollectionUid,
        [Parameter(Mandatory = $true)]
        [int] $CollectionType,
        [Parameter()]
        [string] $Data,
        [Parameter()]
        [string] $DataFile
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collUid = if ($CollectionUid) { $CollectionUid.Trim() }
    if ([string]::IsNullOrEmpty($collUid)) {
        $collUid = [KeeperSecurity.Utils.CryptoUtils]::GenerateUid()
        Write-Output "Generated Collection UID: $collUid"
    }

    if ($CollectionType -eq 0) {
        Write-Error -Message "Collection type is required for 'add' command. Use -CollectionType (e.g., 2 for Application)." -ErrorAction Stop
    }

    $dataJson = readEpmJsonText -Json $Data -FilePath $DataFile
    if ([string]::IsNullOrEmpty($dataJson)) { $dataJson = '{}' }

    $collectionData = New-Object KeeperSecurity.Plugins.EPM.CollectionData
    $collectionData.CollectionUid = $collUid
    $collectionData.CollectionType = $CollectionType
    $collectionData.CollectionDataJson = $dataJson

    try {
        $addStatus = $plugin.ModifyCollections(
            [KeeperSecurity.Plugins.EPM.CollectionData[]]@($collectionData),
            $null,
            $null
        ).GetAwaiter().GetResult()

        if ($addStatus.AddErrors -and $addStatus.AddErrors.Count -gt 0) {
            $err = $addStatus.AddErrors[0]
            Write-Error -Message "Failed to add collection `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($addStatus.Add -and $addStatus.Add.Count -gt 0) {
            Write-Output "Collection '$collUid' added."
        } else {
            Write-Warning "No collection was added. Check server response."
        }
        writeEpmModifyStatus -Status $addStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error adding collection: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Update-KeeperEpmCollection {
    <#
    .Synopsis
        Update an existing EPM collection.
    .Parameter CollectionUidOrName
        Collection UID or name (case-insensitive).
    .Parameter CollectionType
        New collection type (optional). If omitted, keeps existing type.
    .Parameter Data
        Collection data as a JSON string.
    .Parameter DataFile
        Path to a file containing collection data JSON.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $CollectionUidOrName,
        [Parameter()]
        [int] $CollectionType = -1,
        [Parameter()]
        [string] $Data,
        [Parameter()]
        [string] $DataFile
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collection = Resolve-KeeperEpmSingleCollection -Identifier $CollectionUidOrName -Plugin $plugin

    $dataJson = readEpmJsonText -Json $Data -FilePath $DataFile
    if ([string]::IsNullOrEmpty($dataJson)) {
        if ($collection.CollectionData -and $collection.CollectionData.Length -gt 0) {
            $dataJson = [System.Text.Encoding]::UTF8.GetString($collection.CollectionData)
        } else {
            $dataJson = '{}'
        }
    }

    $typeValue = if ($PSBoundParameters.ContainsKey('CollectionType') -and $CollectionType -ne 0) { $CollectionType } else { $collection.CollectionType }

    $collectionData = New-Object KeeperSecurity.Plugins.EPM.CollectionData
    $collectionData.CollectionUid = $collection.CollectionUid
    $collectionData.CollectionType = $typeValue
    $collectionData.CollectionDataJson = $dataJson

    try {
        $updateStatus = $plugin.ModifyCollections(
            $null,
            [KeeperSecurity.Plugins.EPM.CollectionData[]]@($collectionData),
            $null
        ).GetAwaiter().GetResult()

        if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
            $err = $updateStatus.UpdateErrors[0]
            Write-Error -Message "Failed to update collection `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($updateStatus.Update -and $updateStatus.Update.Count -gt 0) {
            Write-Output "Collection '$($collection.CollectionUid)' updated."
        } else {
            Write-Warning "No collection was updated. Check server response."
        }
        writeEpmModifyStatus -Status $updateStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error updating collection: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmCollection {
    <#
    .Synopsis
        Remove an EPM collection by UID or name.
    .Parameter CollectionUidOrName
        Collection UID or name (case-insensitive).
    .Parameter Force
        If set, skip confirmation prompt before delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $CollectionUidOrName,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collection = Resolve-KeeperEpmSingleCollection -Identifier $CollectionUidOrName -Plugin $plugin

    $collName = Get-KeeperEpmCollectionName -Collection $collection
    $displayName = if ($collName) { $collName } else { $collection.CollectionUid }
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("collection '$displayName'", "Delete")) {
        return
    }

    try {
        $removeStatus = $plugin.ModifyCollections(
            $null,
            $null,
            [string[]]@($collection.CollectionUid)
        ).GetAwaiter().GetResult()

        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            $err = $removeStatus.RemoveErrors[0]
            Write-Error -Message "Failed to remove collection `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
            Write-Output "Collection '$($collection.CollectionUid)' removed."
        } else {
            Write-Warning "No collection was removed. Check server response."
        }
        writeEpmModifyStatus -Status $removeStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error removing collection: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Connect-KeeperEpmCollection {
    <#
    .Synopsis
        Link a collection to agent(s), policy(ies), or other collection(s).
    .Parameter CollectionUidOrName
        Collection UID or name (case-insensitive).
    .Parameter LinkType
        Type of link: agent, policy, or collection.
    .Parameter LinkUid
        One or more UIDs or names to link.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $CollectionUidOrName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('agent', 'policy', 'collection')]
        [string] $LinkType,
        [Parameter(Mandatory = $true)]
        [string[]] $LinkUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collection = Resolve-KeeperEpmSingleCollection -Identifier $CollectionUidOrName -Plugin $plugin

    $linkTypeValue = ConvertFrom-KeeperEpmLinkType -LinkType $LinkType

    $links = [System.Collections.Generic.List[string]]::new()

    foreach ($uid in $LinkUid) {
        $trimmed = if ($uid) { $uid.Trim() }
        if ([string]::IsNullOrEmpty($trimmed)) { continue }

        switch ($linkTypeValue) {
            $script:CltAgent {
                $agentMatches = @(Resolve-KeeperEpmAgent -Identifier $trimmed -Plugin $plugin)
                if ($agentMatches.Count -eq 0) {
                    Write-Warning "Agent '$trimmed' not found."
                    continue
                }
                if ($agentMatches.Count -gt 1) {
                    Write-Warning "Multiple agents match name '$trimmed'. Use Agent UID."
                    continue
                }
                $links.Add($agentMatches[0].AgentUid)
            }
            $script:CltPolicy {
                $policyMatches = @(Resolve-KeeperEpmPolicy -Identifier $trimmed -Plugin $plugin)
                if ($policyMatches.Count -eq 0) {
                    Write-Warning "Policy '$trimmed' not found."
                    continue
                }
                if ($policyMatches.Count -gt 1) {
                    Write-Warning "Multiple policies match name '$trimmed'. Use Policy UID."
                    continue
                }
                $links.Add($policyMatches[0].PolicyUid)
            }
            $script:CltCollection {
                $collMatches = @(Resolve-KeeperEpmCollection -Identifier $trimmed -Plugin $plugin)
                if ($collMatches.Count -eq 0) {
                    Write-Warning "Collection '$trimmed' not found."
                    continue
                }
                if ($collMatches.Count -gt 1) {
                    Write-Warning "Multiple collections match name '$trimmed'. Use Collection UID."
                    continue
                }
                $links.Add($collMatches[0].CollectionUid)
            }
        }
    }

    if ($links.Count -eq 0) {
        Write-Error -Message "No valid links found." -ErrorAction Stop
    }

    $setLinks = [System.Collections.Generic.List[KeeperSecurity.Plugins.EPM.CollectionLink]]::new()
    foreach ($linkUidValue in $links) {
        $cl = New-Object KeeperSecurity.Plugins.EPM.CollectionLink
        $cl.CollectionUid = $collection.CollectionUid
        $cl.LinkUid = $linkUidValue
        $cl.LinkType = $linkTypeValue
        $setLinks.Add($cl)
    }

    try {
        $status = $plugin.SetCollectionLinks($setLinks, $null).GetAwaiter().GetResult()

        $hasErrors = $false
        if ($status.AddErrors -and $status.AddErrors.Count -gt 0) {
            foreach ($err in $status.AddErrors) {
                Write-Error -Message "Failed to connect collection link `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                $hasErrors = $true
            }
        }
        if ($status.Add -and $status.Add.Count -gt 0) {
            Write-Output "$($status.Add.Count) link(s) connected."
        } elseif (-not $hasErrors) {
            Write-Warning "No links were connected. Check server response."
        }
        writeEpmModifyStatus -Status $status
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error connecting collection: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Disconnect-KeeperEpmCollection {
    <#
    .Synopsis
        Unlink agent(s), policy(ies), or collection(s) from a collection.
    .Parameter CollectionUidOrName
        Collection UID or name (case-insensitive).
    .Parameter LinkUid
        One or more link UIDs to disconnect.
    .Parameter Force
        Skip confirmation prompt.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $CollectionUidOrName,
        [Parameter(Mandatory = $true)]
        [string[]] $LinkUid,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collection = Resolve-KeeperEpmSingleCollection -Identifier $CollectionUidOrName -Plugin $plugin

    $existingLinks = @($plugin.CollectionLinks.GetLinksForSubject($collection.CollectionUid))
    $toUnlink = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $LinkUid) {
        $t = if ($u) { $u.Trim() }
        if (-not [string]::IsNullOrEmpty($t)) { $toUnlink.Add($t) | Out-Null }
    }

    $unsetLinks = [System.Collections.Generic.List[KeeperSecurity.Plugins.EPM.CollectionLink]]::new()
    foreach ($link in $existingLinks) {
        if ($toUnlink.Contains($link.LinkUid)) {
            $cl = New-Object KeeperSecurity.Plugins.EPM.CollectionLink
            $cl.CollectionUid = $collection.CollectionUid
            $cl.LinkUid = $link.LinkUid
            $cl.LinkType = $link.LinkType
            $unsetLinks.Add($cl)
            $toUnlink.Remove($link.LinkUid) | Out-Null
        }
    }

    if ($toUnlink.Count -gt 0) {
        Write-Warning "$($toUnlink.Count) link(s) cannot be removed from collection: $CollectionUidOrName"
    }

    if ($unsetLinks.Count -eq 0) { return }

    if (-not $Force -and -not $PSCmdlet.ShouldProcess("$($unsetLinks.Count) link(s) from collection '$CollectionUidOrName'", "Disconnect")) {
        return
    }

    try {
        $status = $plugin.SetCollectionLinks($null, $unsetLinks).GetAwaiter().GetResult()

        $hasErrors = $false
        if ($status.RemoveErrors -and $status.RemoveErrors.Count -gt 0) {
            foreach ($err in $status.RemoveErrors) {
                Write-Error -Message "Failed to disconnect collection link `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                $hasErrors = $true
            }
        }
        if ($status.Remove -and $status.Remove.Count -gt 0) {
            Write-Output "$($status.Remove.Count) link(s) disconnected."
        } elseif (-not $hasErrors) {
            Write-Warning "No links were disconnected. Check server response."
        }
        writeEpmModifyStatus -Status $status
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error disconnecting collection: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmCollectionsByType {
    <#
    .Synopsis
        Remove all EPM collections of a given type (wipe-out).
    .Parameter CollectionType
        Collection type to wipe (1=OS Build, 2=Application, 3=User Account, 4=Group Account, 202=OS Version).
    .Parameter Force
        Skip confirmation prompt.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [int] $CollectionType,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $collectionUids = @($plugin.Collections.GetAll() | Where-Object { $_.CollectionType -eq $CollectionType } | ForEach-Object { $_.CollectionUid })

    if ($collectionUids.Count -eq 0) {
        $typeName = getEpmCollectionTypeName -CollectionType $CollectionType
        Write-Output "No collections found for type: $typeName ($CollectionType)"
        return
    }

    $typeName = getEpmCollectionTypeName -CollectionType $CollectionType
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("$($collectionUids.Count) $typeName collection(s)", "Delete")) {
        return
    }

    try {
        $removeStatus = $plugin.ModifyCollections(
            $null,
            $null,
            [string[]]$collectionUids
        ).GetAwaiter().GetResult()

        $hasErrors = $false
        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            foreach ($err in $removeStatus.RemoveErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to remove collection `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                    $hasErrors = $true
                }
            }
        }
        if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
            Write-Output "$($removeStatus.Remove.Count) collection(s) removed."
        } elseif (-not $hasErrors) {
            Write-Warning "No collections were removed. Check server response."
        }
        writeEpmModifyStatus -Status $removeStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error removing collections: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name kepm-collection-list       -Value Get-KeeperEpmCollectionList       -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-view       -Value Get-KeeperEpmCollection           -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-add        -Value Add-KeeperEpmCollection           -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-edit       -Value Update-KeeperEpmCollection        -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-delete     -Value Remove-KeeperEpmCollection        -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-connect    -Value Connect-KeeperEpmCollection       -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-disconnect -Value Disconnect-KeeperEpmCollection    -ErrorAction SilentlyContinue
New-Alias -Name kepm-collection-wipeout    -Value Remove-KeeperEpmCollectionsByType -ErrorAction SilentlyContinue
