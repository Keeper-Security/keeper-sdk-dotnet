#requires -Version 5.0

using namespace KeeperSecurity.Sdk
using namespace System.Threading.Tasks

class TerminalUI : UI.IAuthUI {

	[Task[bool]]Confirmation([string]$information) {
		$choices = @()
		$choices += New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'
		$choices += New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'
		$decision = $global:Host.UI.PromptForChoice('Confirm', $information, $choices, 1)
		return [Task[bool]]::FromResult($decision -eq 0);
	}
	
	[Task[UI.TwoFactorCode]]GetTwoFactorCode([UI.TwoFactorCodeChannel] $channel) {
		[Task[UI.TwoFactorCode]] $source = $null
		$code = Read-Host -Prompt 'Enter Code'
		if ($code) {
			$rs = New-Object -TypeName UI.TwoFactorCode($code, [UI.TwoFactorCodeDuration]::Forever)
			$source = [Task]::FromResult($rs)
		}
		
		return $source
	}

	[Task[string]]GetNewPassword([PasswordRuleMatcher]$matcher) 
	{
		[string] $password1 = ''
		[string] $password2 = ''
		while (-not $password1) {
			$SecurePassword = Read-Host -Prompt 'New Master Password'.PadLeft(24) -AsSecureString
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
			$password1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			if ($password1 -and $matcher) {
				$failedRules = $matcher.MatchFailedRules($password1)
				if ($failedRules -and $failedRules.Count > 0) {
					foreach($r in $failedRules) {
						Write-Host $r
					}
					$password1 = ''
				}
			}
		}

		while (-not $password2) {
			$SecurePassword = Read-Host -Prompt 'Password Again'.PadLeft(24) -AsSecureString
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
			$password2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			if ($password1 -ne $password2) {
				Write-Host 'Passwords do not match.'
				$password2 = ''
			}
		}

		return [Task[string]]::FromResult($password1)
	}
}

function initialize {
	$storage = New-Object JsonConfigurationStorage('config.json')
	$ui = New-Object TerminalUI
	$Script:Auth = New-Object Auth($ui, $storage)
}
initialize
