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

    It 'Keeps -Emails as a first-class parameter on team member cmdlets' {
        (Get-Command Add-KeeperEnterpriseTeamMember).Parameters.ContainsKey('Emails') | Should -Be $true
        (Get-Command Remove-KeeperEnterpriseTeamMember).Parameters.ContainsKey('Emails') | Should -Be $true
        (Get-Command Add-KeeperEnterpriseTeamMember).Parameters.ContainsKey('Users') | Should -Be $true
        (Get-Command Add-KeeperEnterpriseTeamMember).Parameters['Users'].Aliases | Should -Contain 'User'
    }

    It 'Defines EnterpriseTeamTarget and EnterpriseTeamMembershipRequest types' {
        InModuleScope PowerCommander {
            [EnterpriseTeamTarget] | Should -Not -BeNullOrEmpty
            [EnterpriseTeamMembershipRequest] | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Enterprise helper functions' {
    It 'resolveUser implements [int] and numeric-string ID lookup' {
        $content = Get-Content (Join-Path $PSScriptRoot 'EnterpriseHelpers.ps1') -Raw
        $content | Should -Match '\$user -is \[int\]'
        $content | Should -Match '\$user -match ''\^\\d\+\$'''
    }

    It 'Get-EnterpriseTeamMemberInputs merges -Emails and -User' {
        InModuleScope PowerCommander {
            $inputs = Get-EnterpriseTeamMemberInputs -EmailInputs @('a@example.com') -UserInputs @('42')
            $inputs.Count | Should -Be 2
            $inputs[0] | Should -Be 'a@example.com'
            $inputs[1] | Should -Be '42'
        }
    }

    It 'Get-EnterpriseTeamMemberInputs does not warn when only -Emails is provided' {
        InModuleScope PowerCommander {
            $inputs = Get-EnterpriseTeamMemberInputs -EmailInputs @('a@example.com') -WarningAction SilentlyContinue
            $inputs | Should -Be @('a@example.com')
        }
    }

    It 'Resolve-EnterpriseTeamTarget returns EnterpriseTeamTarget instances' {
        $content = Get-Content (Join-Path $PSScriptRoot 'EnterpriseHelpers.ps1') -Raw
        $content | Should -Match '\[EnterpriseTeamTarget\]::FromActiveTeam'
        $content | Should -Match '\[EnterpriseTeamTarget\]::FromQueuedTeam'
    }

    It 'Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders maps to SDK TeamUserType' {
        InModuleScope PowerCommander {
            Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders -HideSharedFolders 'on' |
                Should -Be ([int][Enterprise.TeamUserType]::AdminOnly)
            Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders -HideSharedFolders 'off' |
                Should -Be ([int][Enterprise.TeamUserType]::Admin)
        }
    }

    It 'Get-EnterpriseSdkWarningCallback returns Action[string] for PS 5.1 SDK calls' {
        InModuleScope PowerCommander {
            $cb = Get-EnterpriseSdkWarningCallback
            $cb | Should -Not -BeNullOrEmpty
            $cb.GetType().FullName | Should -Match 'Action`1\[\[System\.String'
        }
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
