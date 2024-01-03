$OrchestratorPath = '../../../../PowerShell/ScubaGear/Modules/Orchestrator.psm1'
$ScubaConfigPath = '../../../../PowerShell/ScubaGear/Modules/ScubaConfig/ScubaConfig.psm1'
$TestUtilsPath = "../PsTestUtils.psm1"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $OrchestratorPath) -Function 'Invoke-SCuBA' -Force
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath $ScubaConfigPath)
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
        Context 'Testing Invoke-Scuba with -ConfigFilePath arg and parameter override' {
            BeforeAll {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'SplatParams')]
                $ConfigFile = ( Join-Path -Path $PSScriptRoot  -ChildPath "orchestrator_config_test.yaml" )
                $SplatParamsRef = @{
                    ConfigFilePath = $ConfigFile
#                    M365Environment = 'gcc'
                }
                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef= [ScubaConfig]::GetInstance().Configuration.Clone()

                function Override-Test( $ModKey, $ModValue) {
                    $SplatParams = $SplatParamsRef.Clone()
                    $SplatParams[$ModKey] = $ModValue
                    Invoke-Scuba @SplatParams
                    $ConfTest = [ScubaConfig]::GetInstance().Configuration
                    # Verify there is a difference with the override
                    $retTestForFalse = Compare-Hashes $ScubaConfRef $ConfTest | Select-Object -Last 1
                    # Verify there are no other differences
                    $ConfTest[$Modkey] = $ScubaConfRef[$Modkey]
                    $retTestForTrue = Compare-Hashes $ScubaConfRef $ConfTest |  Select-Object -Last 1
                    return ( -Not ( $retTestForFalse ) -and ( $retTestForTrue ))
                }

            }
            It 'Verify override:  M365Environment -> gcc' {
                Override-Test  'M365Environment' 'gcc' | Should -be $true
            }
            It 'Verify override:  ProductNames -> teams' {
                Override-Test  'ProductNames' 'teams' | Should -be $true
            }
            It 'Verify override:  OPAPath -> ..' {
                Override-Test  'OPAPath' '..' | Should -be $true
            }
            It 'Verify override: Login -> $false' {
                Override-Test  'Login' $false | Should -be $true
            }
            It 'Verify override:  DisconnectOnExit -> $true -> ..' {
                Override-Test  'DisconnectOnExit' $true | Should -be $true
            }
            It 'Verify override:  OutPath -> ..' {
                Override-Test  'OutPath' '..' | Should -be $true
            }
            It 'Verify override:  OutFolderName -> M365BaselineConformance_mod' {
                Override-Test  'OutFolderName' 'M365BaselineConformance_mod' | Should -be $true
            }
            It 'Verify override:  OutProviderFileName -> ProviderSettingsExport_mod' {
                Override-Test  'OutProviderFileName' 'ProviderSettingsExport_mod' | Should -be $true
            }
            It 'Verify override:  OutRegoFileName -> TestResults_mod' {
                Override-Test  'OutRegoFileName' 'TestResults_mod' | Should -be $true
            }
            It 'Verify override:  OutReportName -> BaselineReports_mod' {
                Override-Test  'OutReportName' 'BaselineReports_mod' | Should -be $true
            }
            It 'Verify override:  Organization -> mod.sub.domain.com' {
                Override-Test  'Organization' 'mod.sub.domain.com'  | Should -be $true
            }
            It 'Verify override:  AppID ->  0123456789abcdef' {
                Override-Test  'AppID' ' 0123456789abcdef'  | Should -be $true
            }
            It 'Verify override:  CertificateThumbprint ->  FEDCBA9786543210' {
                Override-Test  'CertificateThumbprint' 'FEDCBA9786543210'  | Should -be $true
            }
        }
    }
}
AfterAll {
    Remove-Module Orchestrator -ErrorAction SilentlyContinue
}