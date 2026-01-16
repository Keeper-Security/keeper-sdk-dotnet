function New-KeeperEnterpriseNode {
    <#
    .SYNOPSIS
    Creates Enterprise Node

    .PARAMETER ParentNode
    Parent Node name or ID

    .PARAMETER NodeName
    Node name
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $ParentNode,        
        [Parameter(Position = 0, Mandatory = $true)] $NodeName
    )

    [Enterprise]$enterprise = getEnterprise

    [KeeperSecurity.Enterprise.EnterpriseNode] $parent = $null
    if ($ParentNode) {
        $parent = resolveSingleNode $ParentNode
    } else {
        $parent = $enterprise.enterpriseData.RootNode
    }

    $n = [KeeperSecurity.Enterprise.EnterpriseExtensions]::CreateNode($enterprise.enterpriseData, $NodeName, $parent).GetAwaiter().GetResult()
    Write-Information "Added node `"$($n.DisplayName)`""
}
New-Alias -Name kena -Value New-KeeperEnterpriseNode

function Edit-KeeperEnterpriseNode {
    <#
    .SYNOPSIS
    Updates an existing Enterprise Node

    .PARAMETER Node
    Node name or ID to update

    .PARAMETER NewNodeName
    New name for the node

    .PARAMETER ParentNode
    New parent Node name or ID (to move the node)

    .PARAMETER RestrictVisibility
    Enable node isolation (restricts visibility to users outside the node)

    .EXAMPLE
    Edit-KeeperEnterpriseNode -Node "OldName" -NewNodeName "NewName"
    Renames a node

    .EXAMPLE
    Edit-KeeperEnterpriseNode -Node "TestNode" -ParentNode "NewParent"
    Moves a node to a different parent

    .EXAMPLE
    kenu "SecureNode" -RestrictVisibility
    Enables node isolation for a node
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Node,
        [Parameter()][string] $NewNodeName,
        [Parameter()][string] $ParentNode,
        [Parameter()][Switch] $RestrictVisibility
    )

    [Enterprise]$enterprise = getEnterprise

    $nodeToUpdate = resolveSingleNode $Node
    if (-not $nodeToUpdate) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    [KeeperSecurity.Enterprise.EnterpriseNode] $parent = $null
    if ($ParentNode) {
        $parent = resolveSingleNode $ParentNode
    } else {
        if ($nodeToUpdate.ParentNodeId -gt 0) {
            [KeeperSecurity.Enterprise.EnterpriseNode] $existingParent = $null
            if ($enterprise.enterpriseData.TryGetNode($nodeToUpdate.ParentNodeId, [ref]$existingParent)) {
                $parent = $existingParent
            } else {
                $parent = $enterprise.enterpriseData.RootNode
            }
        } else {
            $parent = $enterprise.enterpriseData.RootNode
        }
    }

    $hasChanges = $false
    if (-not [string]::IsNullOrEmpty($NewNodeName)) {
        $nodeToUpdate.DisplayName = $NewNodeName
        $hasChanges = $true
    }

    if ($hasChanges -or $ParentNode -or $RestrictVisibility.IsPresent) {
        if ($hasChanges -or $ParentNode) {
            try {
                [KeeperSecurity.Enterprise.EnterpriseExtensions]::UpdateNode($enterprise.enterpriseData, $nodeToUpdate, $parent).GetAwaiter().GetResult() | Out-Null
                Write-Output "Node `"$($nodeToUpdate.DisplayName)`" updated."
            }
            catch {
                Write-Error -Message "Failed to update node `"$($nodeToUpdate.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
            }
        }

        if ($RestrictVisibility.IsPresent) {
            try {
                [KeeperSecurity.Enterprise.EnterpriseExtensions]::SetRestrictVisibility($enterprise.enterpriseData, $nodeToUpdate.Id).GetAwaiter().GetResult() | Out-Null
                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null 
                
                $nodeToUpdate = resolveSingleNode $nodeToUpdate.Id
                $isolationStatus = if ($nodeToUpdate.RestrictVisibility) { 'ON' } else { 'OFF' }
                Write-Output "Node Isolation: $isolationStatus"
            }
            catch {
                Write-Error -Message "Failed to set node isolation for `"$($nodeToUpdate.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
            }
        }
    } else {
        Write-Warning "No changes specified. Use -NewNodeName, -ParentNode, or -RestrictVisibility to update the node."
    }
}
New-Alias -Name kenu -Value Edit-KeeperEnterpriseNode

function Remove-KeeperEnterpriseNode {
    <#
    .SYNOPSIS
    Deletes an existing Enterprise Node

    .PARAMETER Node
    Node name or ID to delete

    .PARAMETER Force
    Skip confirmation prompt

    .DESCRIPTION
    Permanently deletes an enterprise node. The node must be empty (no users, teams, or sub-nodes) before it can be deleted.
    This operation cannot be undone.

    .EXAMPLE
    Remove-KeeperEnterpriseNode -Node "TestNode"
    Deletes a node with confirmation prompt

    .EXAMPLE
    Remove-KeeperEnterpriseNode -Node "TestNode" -Force
    Deletes a node without confirmation

    .EXAMPLE
    kend "OldNode" -Force
    Uses the alias to delete a node without confirmation
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Node,
        [Parameter()][Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise

    $nodeToDelete = resolveSingleNode $Node
    if (-not $nodeToDelete) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    if ($nodeToDelete.Id -eq $enterprise.enterpriseData.RootNode.Id) {
        Write-Error -Message "Cannot delete the root node" -ErrorAction Stop
    }

    $nodeName = $nodeToDelete.DisplayName
    
    if ($Force -or $PSCmdlet.ShouldProcess($nodeName, "Delete Enterprise Node")) {
        try {
            [KeeperSecurity.Enterprise.EnterpriseExtensions]::DeleteNode($enterprise.enterpriseData, $nodeToDelete.Id).GetAwaiter().GetResult() | Out-Null
            Write-Output "Node `"$nodeName`" deleted successfully."
        }
        catch {
            Write-Error -Message "Failed to delete node `"$nodeName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
    else {
        Write-Output "Node deletion cancelled."
    }
}
New-Alias -Name kend -Value Remove-KeeperEnterpriseNode

function Set-KeeperEnterpriseNodeCustomInvitation {
    <#
    .SYNOPSIS
    Sets a custom invitation template for an Enterprise Node

    .PARAMETER Node
    Node name or ID

    .PARAMETER JsonFilePath
    Path to JSON file containing invitation template (subject, header, body, buttonLabel)

    .DESCRIPTION
    Sets a custom invitation template for an enterprise node from a JSON file.
    The JSON file should contain the following properties:
    - Subject: Email subject line
    - Header: Header text for the invitation
    - Body: Body text for the invitation
    - ButtonLabel: Label for the action button

    .EXAMPLE
    Set-KeeperEnterpriseNodeCustomInvitation -Node "Sales" -JsonFilePath "C:\invitation.json"
    Sets custom invitation template for the Sales node

    .EXAMPLE
    Set-KeeperNodeCustomInvitation "Marketing" "C:\templates\marketing-invite.json"
    Uses the alias to set custom invitation template
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Node,
        [Parameter(Position = 1, Mandatory = $true)][string] $JsonFilePath
    )

    [Enterprise]$enterprise = getEnterprise

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    if (-not (Test-Path -Path $JsonFilePath -PathType Leaf)) {
        Write-Error -Message "JSON file not found: $JsonFilePath" -ErrorAction Stop
    }

    try {
        [KeeperSecurity.Enterprise.EnterpriseExtensions]::SetEnterpriseCustomInvitation($enterprise.enterpriseData, $targetNode.Id, $JsonFilePath).GetAwaiter().GetResult() | Out-Null
        Write-Output "Custom invitation set for node `"$($targetNode.DisplayName)`""
    }
    catch {
        Write-Error -Message "Failed to set custom invitation for node `"$($targetNode.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
    }
}
New-Alias -Name Set-KeeperNodeCustomInvitation -Value Set-KeeperEnterpriseNodeCustomInvitation

function Get-KeeperEnterpriseNodeCustomInvitation {
    <#
    .SYNOPSIS
    Gets the custom invitation template for an Enterprise Node

    .PARAMETER Node
    Node name or ID

    .DESCRIPTION
    Retrieves the custom invitation template configured for an enterprise node.
    Returns an object with Subject, Header, Body, and ButtonLabel properties.

    .EXAMPLE
    Get-KeeperEnterpriseNodeCustomInvitation -Node "Sales"
    Gets the custom invitation template for the Sales node

    .EXAMPLE
    Get-KeeperNodeCustomInvitation "Marketing"
    Uses the alias to get custom invitation template

    .EXAMPLE
    $invitation = Get-KeeperEnterpriseNodeCustomInvitation -Node "Sales"
    $invitation.Subject
    Retrieves and displays the invitation subject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Node
    )

    [Enterprise]$enterprise = getEnterprise

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    try {
        $invitation = [KeeperSecurity.Enterprise.EnterpriseExtensions]::GetEnterpriseCustomInvitation($enterprise.enterpriseData, $targetNode.Id).GetAwaiter().GetResult()
        
        Write-Host "Custom invitation for node `"$($targetNode.DisplayName)`":"
        Write-Host "Subject: $($invitation.Subject)"
        Write-Host "Header: $($invitation.Header)"
        Write-Host "Body: $($invitation.Body)"
        Write-Host "Button Label: $($invitation.ButtonLabel)"
        
        return $invitation
    }
    catch {
        Write-Error -Message "Failed to get custom invitation for node `"$($targetNode.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
    }
}
New-Alias -Name Get-KeeperNodeCustomInvitation -Value Get-KeeperEnterpriseNodeCustomInvitation

function Set-KeeperEnterpriseNodeCustomLogo {
    <#
    .SYNOPSIS
    Uploads a custom logo for an Enterprise Node

    .PARAMETER Node
    Node name or ID

    .PARAMETER LogoType
    Logo type (e.g., "enterprise", "email")

    .PARAMETER LogoPath
    Path to the logo image file (JPEG, PNG, or GIF, max 500KB)

    .DESCRIPTION
    Uploads a custom logo for an enterprise node. The logo file must be:
    - Image format: JPEG, PNG, or GIF
    - Maximum size: 500 KB
    - Dimensions: Between 10x10 and 320x320 pixels

    The upload process includes validation, upload to cloud storage, and verification.

    .EXAMPLE
    Set-KeeperEnterpriseNodeCustomLogo -Node "Sales" -LogoType "enterprise" -LogoPath "C:\logo.png"
    Uploads an enterprise logo for the Sales node

    .EXAMPLE
    Set-KeeperNodeCustomLogo "Marketing" "email" "C:\email-logo.jpg"
    Uses the alias to upload an email logo for the Marketing node
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Node,
        [Parameter(Position = 1, Mandatory = $true)][string] $LogoType,
        [Parameter(Position = 2, Mandatory = $true)][string] $LogoPath
    )

    [Enterprise]$enterprise = getEnterprise

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    if (-not (Test-Path -Path $LogoPath -PathType Leaf)) {
        Write-Error -Message "Logo file not found: $LogoPath" -ErrorAction Stop
    }

    try {
        $response = [KeeperSecurity.Enterprise.EnterpriseExtensions]::UploadEnterpriseCustomLogo($enterprise.enterpriseData, $targetNode.Id, $LogoType, $LogoPath).GetAwaiter().GetResult()
        Write-Output "Custom logo uploaded for node `"$($targetNode.DisplayName)`""
        return $response
    }
    catch {
        Write-Error -Message "Failed to upload custom logo for node `"$($targetNode.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
    }
}
New-Alias -Name Set-KeeperNodeCustomLogo -Value Set-KeeperEnterpriseNodeCustomLogo
