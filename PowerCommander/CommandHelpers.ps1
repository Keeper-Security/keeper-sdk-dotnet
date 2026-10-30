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

function Write-KeeperShareFailure {
    param(
        [Parameter(Mandatory = $true)]
        [System.Exception] $Exception,
        [string] $Context,
        [switch] $Stop
    )

    $Message = Get-KeeperExceptionMessage -Exception $Exception
    if ($Message -notlike '*is the owner of this * and already has full access. Share permissions cannot be granted, changed, or revoked for the owner.') {
        if ($Context) {
            $Message = "${Context}: $Message"
        }

        if ($Stop) {
            Write-Error -Message $Message -ErrorAction Stop
        }
        else {
            Write-Error -Message $Message
        }

        return $false
    }

    Write-Host $Message -ForegroundColor Red
    return $true
}
