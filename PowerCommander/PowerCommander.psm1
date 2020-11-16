#requires -Version 5.0

using namespace KeeperSecurity 
using namespace System.Threading
using namespace System.Threading.Tasks

class TerminalUI : Authentication.IAuthUI, Authentication.IAuthInfoUI {
    RegionChanged([string]$newRegion) 
    {
        Write-Host "`nRegion changed:", $newRegion
    }

    [Task[bool]]WaitForUserPassword([Authentication.IPasswordInfo]$passwordInfo, [CancellationToken]$token) 
    {
        Write-Host "`nMaster Password`n"
		[bool]$result = $true
        [string] $masterPassword = ''

        $securedPassword = Read-Host -Prompt 'Enter Master Password' -AsSecureString 
        if ($securedPassword.Length -gt 0) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedPassword)
			$masterPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			try {
				$_ = $passwordInfo.InvokePasswordActionDelegate.Invoke($masterPassword).GetAwaiter().GetResult()
			}
			catch  {
		        Write-Host $_Exception.message
			}
        } else {
			$result = $false
		}
        return [Task]::FromResult($result)
    }

	[Task[bool]]WaitForTwoFactorCode([Authentication.ITwoFactorChannelInfo[]]$channels, [CancellationToken]$token ) 
    {
        Write-Host "`nTwo Factor Authentication`n"

		[bool]$result = $true
		[Authentication.ITwoFactorChannelInfo] $channel = $channels
        if ( $channel -is [Authentication.ITwoFactorPushInfo]) {
			if ($channel.SupportedActions.Length -eq 1) {
				try {
					$_ = $channel.InvokeTwoFactorPushAction.Invoke($channel.SupportedActions[0]).GetAwaiter().GetResult()
				}
				catch {
					Write-Debug $_Exception.message
				}
			}
		}

		$code = Read-Host -Prompt 'Enter 2FA Code'
		if ($code) {
			try {
				$_ = $channel.InvokeTwoFactorCodeAction.Invoke().GetAwaiter().GetResult()
			}
			catch {
		        Write-Host $_Exception.message
			}
		} else {
	        $result = $false
		}
        return [Task]::FromResult($result)
	}

    [Task[bool]] WaitForDeviceApproval([Authentication.IDeviceApprovalChannelInfo[]]$channels, [CancellationToken]$token) 
    {
        Write-Host "`nDevice Approval`n"

        foreach ($channelInfo in $channels) {
            [Authentication.DeviceApprovalChannel]$channel = $channelInfo.Channel
            if ($channel -eq [Authentication.DeviceApprovalChannel]::Email) {
                Write-Host "'email' to send email"
            }
            elseif ($channel -eq [Authentication.DeviceApprovalChannel]::KeeperPush) {
                Write-Host "'push' to send Keeper Push notification"
            }
            elseif ($channel -eq [Authentication.DeviceApprovalChannel]::TwoFactorAuth) {
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
            [Authentication.DeviceApprovalChannel]$pushChannel = [Authentication.DeviceApprovalChannel]::Email
            if ($action -eq "push") {
                $pushChannel = [Authentication.DeviceApprovalChannel]::KeeperPush
            }
            elseif ($action -eq "tfa") {
                $pushChannel = [Authentication.DeviceApprovalChannel]::TwoFactorAuth                    
            }
            foreach($channelInfo in $channels) {
                if ($channelInfo.Channel -eq $pushChannel) {
                    [Authentication.IDeviceApprovalPushInfo] $pi = $channelInfo
                    if ( $pi -is [Authentication.IDeviceApprovalDuration]) {
                        [Authentication.IDeviceApprovalDuration] $dur = $pi
                        $dur.Duration = [Authentication.TwoFactorDuration]::Every30Days
                    }
                    $_ = $pi.InvokeDeviceApprovalPushAction.Invoke().GetAwaiter().GetResult()
                    if ($channelInfo -is [Authentication.IDeviceApprovalOtpInfo]) {
                        Write-Host "'<code>' provide your code"
                    }
                    Write-Host "<Enter> when device is approved"
                    $code = Read-Host -Prompt 'Code'
                    if ($code) {
                        if ($channelInfo -is [Authentication.IDeviceApprovalOtpInfo]) {
                            $oi = $channelInfo
                            if ( $pi -is [Authentication.IDeviceApprovalDuration]) {
                                [Authentication.IDeviceApprovalDuration] $dur = $pi
                                $dur.Duration = [Authentication.TwoFactorDuration]::Every30Days
                            }
                            $_ = $oi.InvokeDeviceApprovalOtpAction.Invoke($code).GetAwaiter().GetResult()
                        }
                    }
                }                    
            }
        }
        elseif ($action) {
            foreach($channelInfo in $channels) {
                if ($channelInfo.Channel -eq [Authentication.DeviceApprovalChannel]::TwoFactorAuth) {
                    [Authentication.IDeviceApprovalOtpInfo] $oi = $channelInfo
                    if ( $oi -is [Authentication.IDeviceApprovalDuration]) {
                        [Authentication.IDeviceApprovalDuration] $dur = $oi
                        $dur.Duration = [Authentication.TwoFactorDuration]::Every30Days
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
