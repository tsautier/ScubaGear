$OrchestratorPath = '../../../../PowerShell/ScubaGear/Modules/Orchestrator.psm1'
$ScubaConfigPath = '../../../../PowerShell/ScubaGear/Modules/ScubaConfig/ScubaConfig.psm1'
$ConnectionPath = '../../../../PowerShell/ScubaGear/Modules/Connection/Connection.psm1'

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $OrchestratorPath) -Function 'Invoke-SCuBA' -Force
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $ScubaConfigPath)

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $ConnectionPath) -Function Disconnect-SCuBATenant

# This construct did not work
# . (Join-Path -Path $PSScriptRoot -ChildPath '../PsTestUtils.ps1')
# Using this instead
$TestUtilsPath = "../PsTestUtils.psm1"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $TestUtilsPath)


InModuleScope Orchestrator {
    Describe -Tag 'Orchestrator' -Name 'Invoke-Scuba with Config' {
        BeforeAll {
            function Remove-Resources {}
            Mock -ModuleName Orchestrator Remove-Resources {}
            function Import-Resources {}
            Mock -ModuleName Orchestrator Import-Resources {}
            function Invoke-Connection {}
            Mock -ModuleName Orchestrator Invoke-Connection { @() }
            function Get-TenantDetail {}
            Mock -ModuleName Orchestrator Get-TenantDetail { '{"DisplayName": "displayName"}' }
            function Invoke-ProviderList {}
            Mock -ModuleName Orchestrator Invoke-ProviderList {}
            function Invoke-RunRego {}
            Mock -ModuleName Orchestrator Invoke-RunRego {}

            Mock -ModuleName Orchestrator Invoke-ReportCreation {}
            function Disconnect-SCuBATenant {}
            Mock -ModuleName Orchestrator Disconnect-SCuBATenant {}

            Mock -CommandName New-Item {}
            Mock -CommandName Copy-Item {}
        }
        Context 'Test Compare-Hash utility used by Invoke-Scuba -ConfigFilePath tests' {
            BeforeAll {
            }
            It 'Test Compare-Hash missing key in first hash' {
                $a = @{a='a'}
                $b = @{a='a';b='b'}
                [array]$ret = Compare-Hash $a $b
                $ret[0] | Should -BeExactly 'hash1 missing key: b'
                $ret[1] | Should -BeFalse
            }
            It 'Test Compare-Hashes missing key in second hash' {
                $a = @{a='a';b='b'}
                $b = @{a='a'}
                [array]$ret = Compare-Hash $a $b
                $ret[0] | Should -BeExactly 'hash2 missing key: b'
                $ret[1] | Select-Object -Index 1 | Should -BeFalse
            }
            It 'Test Compare-Hash different keys by 1' {
                $a = @{a='a'}
                $b = @{b='b'}
                [array]$ret = Compare-Hash $a $b
                $ret[0] | Should -BeExactly 'hash2 missing key: a'
                $ret[1] | Should -BeExactly 'hash1 missing key: b'
                $ret[2] | Should -BeFalse
            }
            It 'Test Compare-Hash multiple different keys' {
                $a = @{a='a'; b='b'; c='c'}
                $b = @{a='a'; y='y'; z='z'}
                [array]$ret = Compare-Hash $a $b
                $ret[0] | Should -Bein 'hash2 missing key: c b','hash2 missing key: b c'
                $ret[1] | Should -BeIn 'hash1 missing key: y z','hash1 missing key: z y'
                $ret[2] | Should -BeFalse
            }
            It 'Test Compare-Hash different values' {
                $a = @{a='b'}
                $b = @{a='a'}
                [array]$ret = Compare-Hash $a $b
                $ret[0]| Should -BeExactly 'key a values differ b and a'
                $ret[1] | Select-Object -Index 1  | Should -BeFalse
            }
            It 'Test Compare-Hash multiple differrent values' {
                $a = @{a='a';b='b'}
                $b = @{a='y';b='z'}
                [array]$ret = Compare-Hash $a $b
                $ret[0] | Should -BeExactly 'key a values differ a and y'
                $ret[1] | Should -BeExactly 'key b values differ b and z'
                $ret[2] | Select-Object -Index 1  | Should -BeFalse
            }
        }
        Context 'Testing Invoke-Scuba with -ConfigFilePath arg and parameter override' {
            BeforeAll {
                $ConfigFile = ( Join-Path -Path $PSScriptRoot  -ChildPath "orchestrator_config_test.yaml" )
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'SplatParamsRef')]
                $SplatParamsRef = @{
                    ConfigFilePath = $ConfigFile
                }
                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef= [ScubaConfig]::GetInstance().Configuration.Clone()

                function OverrideTest( $ModKey, $ModValue) {
                    $SplatParams = $SplatParamsRef.Clone()
                    $SplatParams[$ModKey] = $ModValue
                    Invoke-Scuba @SplatParams
                    $ConfTest = [ScubaConfig]::GetInstance().Configuration
                    # Verify there is a difference with the override
                    $retTestForFalse = Compare-Hash $ScubaConfRef $ConfTest | Select-Object -Last 1
                    # Verify there are no other differences
                    $ConfTest[$Modkey] = $ScubaConfRef[$Modkey]
                    $retTestForTrue = Compare-Hash $ScubaConfRef $ConfTest |  Select-Object -Last 1
                    return ( -Not ( $retTestForFalse ) -and ( $retTestForTrue ))
                }

            }
            It "Verify overide parameter ""<parameter>"" with value ""<value>""" -ForEach @(
                @{ Parameter = "M365Environment";       Value = "gcc"                           }
                @{ Parameter = "ProductNames";          Value = "teams"                         }
                @{ Parameter = "OPAPath";               Value = ".."                            }
                @{ Parameter = "Login";                 Value = $false                          }
                @{ Parameter = "DisconnectOnExit";      Value = $true                           }
                @{ Parameter = "OutPath";               Value = $true                           }
                @{ Parameter = "OutFolderName";         Value = "M365BaselineConformance_mod"   }
                @{ Parameter = "OutProviderFileName";   Value = "ProviderSettingsExport_mod"    }
                @{ Parameter = "OutRegoFileName";       Value = "TestResults_mod"               }
                @{ Parameter = "OutReportName";         Value = "BaselineReports_mod"           }
                @{ Parameter = "Organization";          Value = "mod.sub.domain.com"            }
                @{ Parameter = "AppID";                 Value = "0123456789badbad"              }
                @{ Parameter = "CertificateThumbprint"; Value = "BADBAD9786543210"              }
                ){
                    OverrideTest $Parameter $Value | Should -Be $true
                }

        }
    }
}
AfterAll {
    Remove-Module Orchestrator -ErrorAction SilentlyContinue
}