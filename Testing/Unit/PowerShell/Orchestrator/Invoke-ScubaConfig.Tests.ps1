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
                # Save ( clone ) the modified configuratiobn ( Invoke-Scuba updatas this )
                $ScubaConfTest = [ScubaConfig]::GetInstance().Configuration.Clone()

                # Now reload the original from the config file 
                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef = [ScubaConfig]::GetInstance().Configuration

                # A difference should be detected here.
                $CompareResult = Compare-Hashes $ScubaConfRef $ScubaConfTest | Select-Object -Last 1
                $CompareResult | Should -be $false

            }
            It 'Verify modified config matches expected value: Compare-Hash should pass ' {
                {Invoke-Scuba @SplatParams} | Should -Not -Throw
                #   Again save (clone)the modifield configuuration 
                $ScubaConfTest = [ScubaConfig]::GetInstance().Configuration.Clone()

                [ScubaConfig]::GetInstance().LoadConfig($ConfigFile)
                $ScubaConfRef = [ScubaConfig]::GetInstance().Configuration

                # Modifiy the expected value to reflect override
                $ScubaConfRef.M365Environment = 'gcc'

                $CompareResult = Compare-Hashes $ScubaConfRef1 $ScubaConfTest1 | Select-Object -Last 1
                $CompareResult | Should -be $true

            }
        }
    }
}
AfterAll {
    Remove-Module Orchestrator -ErrorAction SilentlyContinue
}