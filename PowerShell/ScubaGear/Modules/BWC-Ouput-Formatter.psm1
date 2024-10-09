
function Out-CSPA {
  <#
    .Description
    Outputs the CSPA result in web app format
    .Functionality
    Internal
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $CSVFileName,

    [Parameter(Mandatory = $true)]
    [string]
    $OutputPath,

    [Parameter(Mandatory = $false)]
    [string[]]
    $DesiredColumns = @("Control", "Requirement", "RequirementMet")
  )

  Import-Csv $CSVFileName | Select-Object $DesiredColumns | Export-Csv -Path $OutputPath -NoTypeInformation
}