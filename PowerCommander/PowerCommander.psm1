#requires -Version 5.0

using namespace KeeperSecurity.Sdk 
using namespace System.Threading
using namespace System.Threading.Tasks

class TerminalUI : UI.IAuthUI, UI.IAuthInfoUI {
    RegionChanged([string]$newRegion) 
    {
        Write-Host "`nRegion changed:", $newRegion
    }

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
		$code = Read-Host -Prompt 'Enter 2FA Code'
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
                Write-Host "'email' to send email"
            }
            elseif ($channel -eq [UI.DeviceApprovalChannel]::KeeperPush) {
                Write-Host "'push' to send Keeper Push notification"
            }
            elseif ($channel -eq [UI.DeviceApprovalChannel]::TwoFactorAuth) {
                Write-Host "'tfa' to send 2FA code"
                Write-Host "<code> provided by your 2FA application"
            }
        }

        Write-Host "<Enter> to resume, 'q' to cancel"

        [bool]$result = $true
        $action = Read-Host -Prompt 'Device Approval Action'

        if ($action -eq 'q') {
            $result = $false
        }
        elseif ($action -in "email", "push", "tfa") {
            [UI.DeviceApprovalChannel]$pushChannel = [UI.DeviceApprovalChannel]::Email
            if ($action -eq "push") {
                $pushChannel = [UI.DeviceApprovalChannel]::KeeperPush
            }
            elseif ($action -eq "tfa") {
                $pushChannel = [UI.DeviceApprovalChannel]::TwoFactorAuth                    
            }
            foreach($channelInfo in $channels) {
                if ($channelInfo.Channel -eq $pushChannel) {
                    [UI.IDeviceApprovalPushInfo] $pi = $channelInfo
                    if ( $pi -is [UI.IDeviceApprovalDuration]) {
                        [UI.IDeviceApprovalDuration] $dur = $pi
                        $dur.Duration = [UI.TwoFactorDuration]::Every30Days
                    }
                    $_ = $pi.InvokeDeviceApprovalPushAction.Invoke().GetAwaiter().GetResult()
                    if ($channelInfo -is [UI.IDeviceApprovalOtpInfo]) {
                        Write-Host "'<code>' provide your code"
                    }
                    Write-Host "<Enter> when device is approved"
                    $code = Read-Host -Prompt 'Code'
                    if ($code) {
                        if ($channelInfo -is [UI.IDeviceApprovalOtpInfo]) {
                            $oi = $channelInfo
                            if ( $pi -is [UI.IDeviceApprovalDuration]) {
                                [UI.IDeviceApprovalDuration] $dur = $pi
                                $dur.Duration = [UI.TwoFactorDuration]::Every30Days
                            }
                            $_ = $oi.InvokeDeviceApprovalOtpAction.Invoke($code).GetAwaiter().GetResult()
                        }
                    }
                }                    
            }
        }
        elseif ($action) {
            foreach($channelInfo in $channels) {
                if ($channelInfo.Channel -eq [UI.DeviceApprovalChannel]::TwoFactorAuth) {
                    [UI.IDeviceApprovalOtpInfo] $oi = $channelInfo
                    if ( $oi -is [UI.IDeviceApprovalDuration]) {
                        [UI.IDeviceApprovalDuration] $dur = $oi
                        $dur.Duration = [UI.TwoFactorDuration]::Every30Days
                    }
                    $_ = $oi.InvokeDeviceApprovalOtpAction.Invoke($action).GetAwaiter().GetResult()
                }                    
            }
        }
       
        return [Task]::FromResult($result)
    }
}

function initialize {
	$storage = New-Object JsonConfigurationStorage
	$ui = New-Object TerminalUI
	$Script:Auth = New-Object Auth($ui, $storage)
}
initialize
