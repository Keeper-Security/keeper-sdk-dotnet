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
    }

    if (-not [string]::IsNullOrEmpty($NewNodeName)) {
        $nodeToUpdate.DisplayName = $NewNodeName
    }

    try {
        [KeeperSecurity.Enterprise.EnterpriseExtensions]::UpdateNode($enterprise.enterpriseData, $nodeToUpdate, $parent).GetAwaiter().GetResult() | Out-Null
        Write-Output "Node `"$($nodeToUpdate.DisplayName)`" updated."
    }
    catch {
        Write-Error -Message "Failed to update node `"$($nodeToUpdate.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
    }

    if ($RestrictVisibility.IsPresent) {
        try {
            [KeeperSecurity.Enterprise.EnterpriseExtensions]::SetRestrictVisibility($enterprise.enterpriseData, $nodeToUpdate.Id).GetAwaiter().GetResult() | Out-Null
            $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null 
            
            $nodeToUpdate = resolveSingleNode $nodeToUpdate.Id
            Write-Output "Node Isolation: $($nodeToUpdate.RestrictVisibility ? 'ON' : 'OFF')"
        }
        catch {
            Write-Error -Message "Failed to set node isolation for `"$($nodeToUpdate.DisplayName)`": $($_.Exception.Message)" -ErrorAction Stop
        }
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

