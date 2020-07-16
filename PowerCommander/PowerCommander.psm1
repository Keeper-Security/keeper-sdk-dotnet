#requires -Version 5.0

using namespace KeeperSecurity.Sdk 
using namespace System.Threading
using namespace System.Threading.Tasks

class TerminalUI : UI.IAuthUI {
    [Task[string]]GetMasterPassword([string]$username) 
    {
        Write-Host "`nMaster Password`n"

        [string] $masterPassword = ''
        $securedPassword = Read-Host -Prompt 'Enter Master Password' -AsSecureString 
        if ($securedPassword.Length -gt 0) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedPassword)
			$masterPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }

        return [Task]::FromResult($masterPassword)
    }

	[Task[UI.TwoFactorCode]]GetTwoFactorCode(
        [UI.TwoFactorChannel]$channel, 
        [UI.ITwoFactorChannelInfo[]]$channels, 
        [CancellationToken]$token ) 
    {
        Write-Host "`nTwo Factor Authentication`n"

		[Task[UI.TwoFactorCode]] $source = $null
		$code = Read-Host -Prompt 'Enter Code'
		if ($code) {
			$rs = New-Object -TypeName UI.TwoFactorCode($channel, $code, [UI.TwoFactorDuration]::Forever)
			$source = [Task]::FromResult($rs)
		}
		
		return $source
	}

    [Task[bool]] WaitForDeviceApproval(
        [UI.IDeviceApprovalChannelInfo[]]$channels,
        [CancellationToken]$token) 
    {
        Write-Host "`nDevice Approval`n"

        foreach ($channelInfo in $channels) {
            [UI.DeviceApprovalChannel]$channel = $channelInfo.Channel
            if ($channel -eq [UI.DeviceApprovalChannel]::Email) {
                Write-Host "'email' to resend email"
            }
            elseif ($channel -eq [UI.DeviceApprovalChannel]::KeeperPush) {
                Write-Host "'push' to send Keeper Push notification"
            }
            elseif ($channel -eq [UI.DeviceApprovalChannel]::TwoFactorAuth) {
                Write-Host "'tfa_code' to send 2FA code"
                Write-Host "<code> provided by your 2FA application"
            }
        }

        Write-Host "<Enter> to resume, 'q' to cancel"

        [bool]$cancelled = $false
        [bool]$result = $true

        do {
            $action = Read-Host -Prompt 'Device Approval Action'

            if ($cancelled) {break}
            if ($action -eq 'q') {
                $result = $false
                break
            }
            if ($action.Length -eq 0) {break}

            if ($action -in "email", "push", "tfa_code") {
                [UI.DeviceApprovalChannel]$pushChannel = [UI.DeviceApprovalChannel]::Email
                if ($action -eq "push") {
                    $pushChannel = [UI.DeviceApprovalChannel]::KeeperPush
                }
                elseif ($action -eq "tfa_code") {
                    $pushChannel = [UI.DeviceApprovalChannel]::TwoFactorAuth                    
                }
                foreach($channelInfo in $channels) {
                    if ($channelInfo.Channel -eq $pushChannel) {
                        [UI.IDeviceApprovalPushInfo] $pi = $channelInfo
                        $_ = $pi.InvokeDeviceApprovalPushAction.Invoke([UI.TwoFactorDuration]::Forever).GetAwaiter().GetResult()        
                        Write-Host 'Press <Enter> when device is approved'
                        break                        
                    }                    
                }
            }
            else {
                foreach($channelInfo in $channels) {
                    if ($channelInfo.Channel -eq [UI.DeviceApprovalChannel]::TwoFactorAuth) {
                        [UI.IDeviceApprovalOtpInfo] $oi = $channelInfo
                        $_ = $oi.InvokeDeviceApprovalOtpAction.Invoke($action, [UI.TwoFactorDuration]::Forever).GetAwaiter().GetResult()
                        $cancelled = $true
                        break                        
                    }                    
                }
            }
        } while ($cancelled -eq $false)      
       
        return [Task]::FromResult($result)
    }
}

function initialize {
	$storage = New-Object JsonConfigurationStorage
	$ui = New-Object TerminalUI
	$Script:Auth = New-Object Auth($ui, $storage)
}
initialize
