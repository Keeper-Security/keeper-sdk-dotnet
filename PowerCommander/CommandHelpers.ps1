#requires -Version 5.1

function Get-KeeperExceptionMessage {
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception] $Exception
    )

    if ($Exception -is [System.Management.Automation.MethodInvocationException] -and $null -ne $Exception.InnerException) {
        return $Exception.InnerException.Message
    }

    return $Exception.Message
}
