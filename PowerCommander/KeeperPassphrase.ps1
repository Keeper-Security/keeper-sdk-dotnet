#requires -Version 5.1

function New-KeeperPassphraseOptions {
    Param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]] $PassphraseRuleValues = @()
    )

    $options = New-Object KeeperSecurity.Utils.PassphraseGenerationOptions

    if (-not $PassphraseRuleValues -or $PassphraseRuleValues.Count -eq 0) {
        return $options
    }

    $parts = if ($PassphraseRuleValues.Count -eq 1 -and $PassphraseRuleValues[0].Contains(',')) {
        $PassphraseRuleValues[0].Split(',')
    } else {
        $PassphraseRuleValues
    }

    if ($parts.Count -gt 4) {
        throw "PassphraseRuleValues accepts at most 4 values: WordCount,Separator,UseCaps,UseDigits. Got $($parts.Count)."
    }

    $minWordCount = [KeeperSecurity.Utils.PassphraseGenerator]::MinWordCount
    $maxWordCount = [KeeperSecurity.Utils.PassphraseGenerator]::MaxWordCount

    if ($parts.Count -ge 1 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
        $wordCount = 0
        if (-not [int]::TryParse($parts[0].Trim(), [ref]$wordCount)) {
            throw "PassphraseRuleValues WordCount must be between $minWordCount and $maxWordCount. Got '$($parts[0])'."
        }
        try {
            $options.WordCount = [KeeperSecurity.Utils.PassphraseGenerator]::ValidateWordCount($wordCount)
        } catch {
            throw "PassphraseRuleValues WordCount must be between $minWordCount and $maxWordCount. Got '$($parts[0])'."
        }
    }

    if ($parts.Count -ge 2) {
        $options.Separator = [KeeperSecurity.Utils.PassphraseGenerator]::ValidateSeparator($parts[1])
    }

    if ($parts.Count -ge 3) {
        switch ($parts[2].Trim().ToLower()) {
            { $_ -in '1', 'true', 'yes', 'y' } { $options.UseCaps = $true; break }
            { $_ -in '0', 'false', 'no', 'n', '' } { $options.UseCaps = $false; break }
            default { throw "PassphraseRuleValues UseCaps must be true or false. Got '$($parts[2])'." }
        }
    }

    if ($parts.Count -ge 4) {
        switch ($parts[3].Trim().ToLower()) {
            { $_ -in '1', 'true', 'yes', 'y' } { $options.UseDigits = $true; break }
            { $_ -in '0', 'false', 'no', 'n', '' } { $options.UseDigits = $false; break }
            default { throw "PassphraseRuleValues UseDigits must be true or false. Got '$($parts[3])'." }
        }
    }

    return $options
}

function Set-KeeperPassphraseField {
    Param(
        [Parameter(Mandatory = $true)]
        $FieldDict,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]] $PassphraseRuleValues
    )

    try {
        if ($PassphraseRuleValues -and $PassphraseRuleValues.Count -gt 0) {
            $passphraseOptions = New-KeeperPassphraseOptions -PassphraseRuleValues $PassphraseRuleValues
        } else {
            $passphraseOptions = New-KeeperPassphraseOptions
        }
        $FieldDict['password'] = [KeeperSecurity.Utils.PassphraseGenerator]::GeneratePassphrase($passphraseOptions)
        return $true
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
