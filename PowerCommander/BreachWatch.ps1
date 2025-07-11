#requires -Version 5.1

function Get-KeeperBreachWatchList {
    [CmdletBinding()]
    param(
        [Parameter()][Switch]$OwnedOnly,
        [Parameter()][Switch]$All,
        [Parameter()][Switch]$Numbered,
        [Parameter()][string]$VaultContextVar = "Global:KeeperVaultContext"
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $recordUids = $vault.BreachWatchRecords() |
        Where-Object { $_.Status -in @("Weak", "Breached") } |
        Select-Object -ExpandProperty RecordUid

    $records = $vault.KeeperRecords |
        Where-Object {
            $recordUids -contains $_.Uid -and
            (-not $OwnedOnly -or $_.Owner)
        }

    if ($records.Count -gt 0) {
        $table = New-Object System.Collections.Generic.List[object]
        $index = 1

        foreach ($r in $records | Sort-Object Title) {
            $row = if ($Numbered) {
                [PSCustomObject]@{
                    "S.No"       = $index++
                    "Record UID" = $r.Uid
                    "Title"      = $r.Title
                    "Description"= [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordPublicInformation($r)
                }
            } else {
                [PSCustomObject]@{
                    "Record UID" = $r.Uid
                    "Title"      = $r.Title
                    "Description"= [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordPublicInformation($r)
                }
            }
            $table.Add($row)
        }

        $total = $table.Count
        if (-not $All.IsPresent -and $total -gt 32) {
            $table = $table[0..29]
        }

        $table | Format-Table -AutoSize

        if ($table.Count -lt $total) {
            Write-Host ""
            Write-Host "$($total - $table.Count) records skipped."
        }
    } else {
        Write-Host "No breached records detected"
    }

    $scannedUids = $vault.BreachWatchRecords() | Select-Object -ExpandProperty RecordUid
    $notScanned = $vault.KeeperRecords |
        Where-Object { $_.Owner -and ($scannedUids -notcontains $_.Uid) -and $_.GetType() -ne [KeeperSecurity.Vault.ApplicationRecord] }

    $hasPasswordsToScan = $false
    foreach ($record in $notScanned) {
        $loadedRecord = $null
        if ($vault.TryLoadKeeperRecord($record.Uid, [ref]$loadedRecord)) {
            $pw = Get-KeeperRecordPassword -Record $loadedRecord -Silent
            if ($pw) {
                $hasPasswordsToScan = $true
                break
            }
        }
    }

    if ($hasPasswordsToScan) {
        Write-Host "`nSome passwords in your vault have not been scanned.`nUse `"breachwatch scan`" to check against the Dark Web database."
    }
}

Set-Alias -Name kbw -Value Get-KeeperBreachWatchList
