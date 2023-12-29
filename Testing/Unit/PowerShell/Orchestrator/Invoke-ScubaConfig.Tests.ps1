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
                $SplatParams = @{
                    ConfigFilePath = $ConfigFile
                    M365Environment = 'gcc'
                }
            }
            It 'Verify override:  Compare-Hash should fail' {
                {Invoke-Scuba @SplatParams} | Should -Not -Throw
                $ScubaConfTest = [ScubaConfig]::GetInstance().Configuration.Clone()

                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef = [ScubaConfig]::GetInstance().Configuration

                $difference_test_pass = ( -Not ( Compare-Hashes $ScubaConfRef $ScubaConfTest ))
                $difference_test_pass

            }
            It 'Verify modified config matches expected value: Compare-Hash should pass ' {
                {Invoke-Scuba @SplatParams} | Should -Not -Throw
                $ScubaConfTest = [ScubaConfig]::GetInstance().Configuration.Clone()

                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef = [ScubaConfig]::GetInstance().Configuration

                # Modifiy the expected value to reflect override
                $ScubaConfRef.M365Enviroment = 'gcc'

                $other_properties_pass = ( Compare-Hashes $ScubaConfRef $ScubaConfTest )
                $other_properties_pass

            }
        }
    }
}
AfterAll {
    Remove-Module Orchestrator -ErrorAction SilentlyContinue
}