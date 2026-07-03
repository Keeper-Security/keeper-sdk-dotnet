# Pester tests for sdk-540 enterprise team/user/role enhancements.
# Run: Invoke-Pester -Path ./PowerCommander/EnterpriseTeamUserRole.tests.ps1

BeforeAll {
    $moduleRoot = $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'PowerCommander.psd1') -Force
}

AfterAll {
    Remove-Module PowerCommander -Force -ErrorAction SilentlyContinue
}

Describe 'Enterprise team/user/role exports' {
    It 'Exports new read cmdlets and aliases' {
        'Get-KeeperEnterpriseUserTeam', 'Get-KeeperEnterpriseTeamRole' | ForEach-Object {
            Get-Command $_ -Module PowerCommander | Should -Not -BeNullOrEmpty
        }
        (Get-Alias keut -ErrorAction SilentlyContinue).Definition | Should -Be 'Get-KeeperEnterpriseUserTeam'
        (Get-Alias ketr -ErrorAction SilentlyContinue).Definition | Should -Be 'Get-KeeperEnterpriseTeamRole'
    }

    It 'Does not export consolidated duplicate write cmdlets' {
        'Add-KeeperEnterpriseUserTeam', 'Remove-KeeperEnterpriseUserTeam',
        'Add-KeeperEnterpriseTeamRole', 'Remove-KeeperEnterpriseTeamRole' | ForEach-Object {
            Get-Command $_ -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    It 'Keeps release team update/delete cmdlets and aliases' {
        'Update-KeeperEnterpriseTeam', 'Remove-KeeperEnterpriseTeam' | ForEach-Object {
            Get-Command $_ -Module PowerCommander | Should -Not -BeNullOrEmpty
        }
        (Get-Alias kete -ErrorAction SilentlyContinue).Definition | Should -Be 'Update-KeeperEnterpriseTeam'
        (Get-Alias ketdel -ErrorAction SilentlyContinue).Definition | Should -Be 'Remove-KeeperEnterpriseTeam'
    }

    It 'Preserves -Emails alias on Add-KeeperEnterpriseTeamMember' {
        (Get-Command Add-KeeperEnterpriseTeamMember).Parameters['User'].Aliases | Should -Contain 'Emails'
    }
}

Describe 'Enterprise helper functions' {
    It 'resolveUser implements [int] and numeric-string ID lookup' {
        $content = Get-Content (Join-Path $PSScriptRoot 'EnterpriseHelpers.ps1') -Raw
        $content | Should -Match '\$user -is \[int\]'
        $content | Should -Match '\$user -match ''\^\\d\+\$'''
    }

    It 'Test-EnterpriseRoleIsAdmin is true when role has a managed node' {
        InModuleScope PowerCommander {
            $roleData = [PSCustomObject]@{}
            $roleData | Add-Member -MemberType ScriptMethod -Name GetManagedNodes -Value {
                return @([PSCustomObject]@{ RoleId = 42; ManagedNodeId = 1 })
            }
            Test-EnterpriseRoleIsAdmin -RoleData $roleData -RoleId 42 | Should -Be $true
            Test-EnterpriseRoleIsAdmin -RoleData $roleData -RoleId 99 | Should -Be $false
        }
    }
}
