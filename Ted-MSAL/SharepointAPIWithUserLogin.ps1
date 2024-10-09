# These are the command line parameters
param (
  [Parameter(Mandatory = $true)]
  [string]$ClientId,

  [Parameter(Mandatory = $true)]
  [string]$TenantDomainPrefix
)

# Note to user: make sure that the required .NET assembly files are in the same folder where the script is executing
# The code below loads the .NET classes necessary for creating MSAL objects
# If you uncomment the $assembly.FullName lines you can see which version of each assembly is present for debugging
$currentDir = $PSScriptRoot
try {
    $assembly = [Reflection.Assembly]::LoadFrom("$currentDir\Microsoft.IdentityModel.Abstractions.dll")
    # $assembly.FullName
    $assembly = [Reflection.Assembly]::LoadFrom("$currentDir\Microsoft.Identity.Client.dll")
    # $assembly.FullName
} catch {
    Write-Warning "Make sure the files Microsoft.IdentityModel.Abstractions.dll and Microsoft.Identity.Client.dll are in the current folder"
    throw
    return
}

# Setup some necessary variables
# $ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # This is the id of the MS Graph Powershell command line app
$Tenant = "$TenantDomainPrefix.onmicrosoft.com"
$Authority = "https://login.microsoftonline.com/$Tenant"
$redirectUri = "http://localhost"

# The PublicClientApplicationBuilder is simply a helper class that sets up some parameters
$ClientApplicationBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId)
$ClientApplicationBuilder = $ClientApplicationBuilder.WithAuthority($Authority)
$ClientApplicationBuilder = $ClientApplicationBuilder.WithRedirectUri($redirectUri)
# Build an instance of the IConfidentialClientApplication interface which is then used to get the token 
$ConfidentialClientApp = $ClientApplicationBuilder.Build()


#####################################################################
##### This first section provides an example for calling a Sharepoint REST API.
##### It will output a JSON document containing the Sharepoint tenant configuration settings.
#####
# Acquire a token for Sharepoint
$SharepointAdminSite = "https://$TenantDomainPrefix-admin.sharepoint.com"
[string[]] $SharepointScopes = @("$SharepointAdminSite/.default")

try {
    $sharepointAuthToken = $ConfidentialClientApp.AcquireTokenInteractive($SharepointScopes).ExecuteAsync().GetAwaiter().GetResult()
    Write-Host "Sharepoint Access Token Acquired: $($sharepointAuthToken.AccessToken)"
} catch {
    Write-Host "Failed to acquire token: $($_.Exception.Message)"
    return
}

$SharepointConfigEndpoint = "$SharepointAdminSite/_vti_bin/client.svc/ProcessQuery"
$SharepointBody = @'
  <Request AddExpandoFieldTypeSuffix="true" SchemaVersion="15.0.0.0" LibraryVersion="16.0.0.0" ApplicationName=".NET Library" xmlns="http://schemas.microsoft.com/sharepoint/clientquery/2009">
    <Actions>
      <ObjectPath Id="2" ObjectPathId="1" />
      <Query Id="3" ObjectPathId="1">
        <Query SelectAllProperties="true">
          <Properties>
            <Property Name="HideDefaultThemes" ScalarProperty="true" />
          </Properties>
        </Query>
      </Query>
    </Actions>
    <ObjectPaths>
      <Constructor Id="1" TypeId="{268004ae-ef6b-4e9b-8425-127220d84719}" />
    </ObjectPaths>
  </Request>
'@

# Call a Sharepoint API to fetch configuration data and pass the acquired token in the header
$headers =  @{
    "Authorization" = "Bearer $($sharepointAuthToken.AccessToken)"
    "Accept-Encoding" = "gzip, deflate"
    "Content-Type" = "text/xml"
    "User-Agent" = "ScubaGear"
}

try {
    $response = Invoke-RestMethod -Uri $SharepointConfigEndpoint -Headers $headers -Method Post -Body $SharepointBody
    Write-Host "Sharepoint API Call Successful. Response:"
    $response | ConvertTo-Json
} catch {
    Write-Host "Sharepoint API call failed: $($_.Exception.Message)"
}
#####################################################################


####################################################################
##### This second section provides an example for calling an MS Graph REST API.
##### It will output a JSON document containing a list of the users in the tenant.
#####
# Acquire a token for Microsoft Graph
# [string[]] $GraphScopes = @("https://graph.microsoft.com/.default")
# try {
#     $graphAuthToken = $ConfidentialClientApp.AcquireTokenForClient($GraphScopes).ExecuteAsync().GetAwaiter().GetResult()
#     # Write-Host "Graph Access Token Acquired: $($graphAuthToken.AccessToken)"
# } catch {
#     Write-Host "Failed to acquire token: $($_.Exception.Message)"
#     return
# }

# # Call a Graph API to fetch the users and pass the acquired token in the header
# $GraphApiEndpoint = "https://graph.microsoft.com/v1.0/users"
# $headers = @{
#     "Authorization" = "Bearer $($graphAuthToken.AccessToken)"
#     "Content-Type"  = "application/json"
# }

# try {
#     $response = Invoke-RestMethod -Uri $GraphApiEndpoint -Headers $headers -Method Get
#     Write-Host "Graph API Call Successful. Response:"
#     $response | ConvertTo-Json
# } catch {
#     Write-Host "Graph API call failed: $($_.Exception.Message)"
# }
####################################################################
