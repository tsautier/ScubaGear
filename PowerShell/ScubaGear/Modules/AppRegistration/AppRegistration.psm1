function New-SCuBAApplication {
    <#
    .SYNOPSIS
    Automatically create an application in the Microsoft Identity Platform with the proper permissions to run ScubaGear.
    .Description
    This function automatically creates a Microsoft IdP application with the permissions and roles need for each product. 
    .Parameter ProductNames
    A list of one or more M365 shortened product names that this function will assing the application permissions to.
    - Azure Active Directory: aad
    - Defender for Office 365: defender
    - Exchange Online: exo
    - MS Power Platform: powerplatform
    - SharePoint Online: sharepoint
    - MS Teams: teams.
    By default all product permissions will be assigned.
    .Parameter M365Environment
    This parameter is used to differentiate commercial/government environments.
    Valid values include "commercial", "gcc", "gcchigh", or "dod".
    - For M365 tenants with E3/E5 licenses enter the value **"commercial"**.
    - For M365 Government Commercial Cloud tenants with G3/G5 licenses enter the value **"gcc"**.
    - For M365 Government Commercial Cloud High tenants enter the value **"gcchigh"**.
    - For M365 Department of Defense tenants enter the value **"dod"**.
    Default value is 'commercial'.
    .Example
    New-SCuBAApplication -DisplayName ScubaGearApplication
    .Example
    New-SCuBAApplication -DisplayName ScubaGearApplication
    .Functionality
    Public
    #>
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DisplayName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("aad", "defender", "exo", "powerplatform", "sharepoint", "teams", IgnoreCase = $true)]
    [string[]]
    $ProductNames = @("teams", "exo", "defender", "aad", "sharepoint", "powerplatform"),

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $true)]
    [string]
    $M365Environment = 'commercial',

    [Parameter(Mandatory = $false)]
    [switch]
    $OmitCertCreation
    )
    # sanitization
    $ProductNames = $ProductNames | Sort-Object -Unique

    try {
        Write-Verbose "Connecting to MS Graph PowerShell with App Registration Permissions"
        Connect-ToGraphWithAppPerms
    }
    catch {
        throw $_
    }

    Write-Verbose "Building the RequiredResourceAccess permissions array"
    $ResourceAppAccessIds = Get-SCuBAAppScopes -ProductNames $ProductNames -M365Environment $M365Environment

    Write-Verbose "Creating the Microsoft IdP Application"
    $NewApplicationParams = @{
        'DisplayName' = $DisplayName
        'RequiredResourceAccess' = $ResourceAppAccessIds
        'ErrorAction' = 'Stop'
    }
    try {
        $ScubaApplication = New-MgBetaApplication @NewApplicationParams
        $AppId = $ScubaApplication.AppId
        $AppObjectId = $ScubaApplication.Id
        Write-Verbose "Application created with AppId: $($AppId)"
        # Get the SP ID of the we created
        $AppServicePrincipal = Get-MgBetaServicePrincipal -Filter "appId eq '$($AppId)'"
        # Create the SP if there is none found
        if (-not $AppServicePrincipal) {
            $AppServicePrincipal = New-MgBetaServicePrincipal -AppId $AppId
        }
        Write-Verbose "Application Service Principal Id $($AppServicePrincipal.Id)"
    }
    catch {
        throw $_
    }


    Write-Verbose "Granting admin consent for requested OAuth 2.0 Scopes"
    try {
        $SCuBASPAccessAssignParams = @{
            AppId = $AppId
            AppServicePrincipalId = $AppServicePrincipal.Id
            ProductNames = $ProductNames
            M365Environment = $M365Environment
        }
        New-SCuBAServicePrincipalRoleAccessAssignment @SCuBASPAccessAssignParams
    }
    catch {
        throw $_
    }

    Write-Verbose "Assigning Required roles to the applications"
    try {
        $AppRolesIds = Get-SCuBAAppRoles -ProductNames $ProductNames
        foreach ($RoleId in $AppRolesIds) {
            New-MgBetaRoleManagementDirectoryRoleAssignment -PrincipalId $AppServicePrincipal.Id -RoleDefinitionId $RoleId -DirectoryScopeId "/" | Out-Null
        }
    }
    catch {
        throw $_
    }

    Write-Verbose "Registering app to Power Platform"
    try {
        Connect-ToPowerPlatform -M365Environment $M365Environment | Out-Null
        New-PowerAppManagementApp -ApplicationId $AppId | Out-Null
    }
    catch {
        throw $_
    }

    Write-Verbose "Creating and uploading self-signed certificate to the application"
    try {
        if (-not $OmitCertCreation) {
            $CertName = New-SCuBACertificate
            $CertPath = Join-Path -Path "." -ChildPath "$($CertName).cer"
            $CertThumbprint = (Get-FileHash -Path $CertPath -Algorithm SHA1).Hash

            $KeyBase64 = [convert]::ToBase64String((Get-Content -Path $CertPath -Encoding byte))
            $CertificateParameters = @{
                keyCredentials = @(
                    @{
                        type = "AsymmetricX509Cert"
                        usage = "Verify"
                        key = [System.Text.Encoding]::ASCII.GetBytes($KeyBase64)
                        displayName = $CertName
                    }
                )
            }
            Update-MgBetaApplication -ApplicationId $AppObjectId -BodyParameter $CertificateParameters -ErrorAction 'Stop'
        }
    }
    catch {
        throw $_
    }

    try {
        $OrgInfo = Get-MgBetaOrganization -ErrorAction "Stop"
        $InitialDomain = $OrgInfo.VerifiedDomains | Where-Object {$_.isInitial}
        $OrganizationDomain = $InitialDomain.Name
    }
    catch {
        $OrganizationDomain = "UnableToRetrieve"
    }

    $Instructions = @"
Successfully created the authorized custom SCuBA application: $($DisplayName)
Run the ScubaGear via App-only authentication using the following parameters:
AppId= $($AppId)
CertificateThumbprint= $($CertThumbprint)
Organization= $($OrganizationDomain)

Example ScubaGear run with the above parameters using App-only authentication
--------------------------------------------
Invoke-SCuBA -ProductNames * -M365Environment "$($M365Environment)" -CertificateThumbprint "$($CertThumbprint)" -AppID "$($AppId)" -Organization $($OrganizationDomain)
"@
    Write-Output $Instructions
}

function Update-SCuBAApplicationPermissions {
    # Connect to MS Graph if not already connected
    $GraphConnected = Get-MgBetaOrganization -ErrorAction SilentlyContinue
    if (-not $GraphConnected) {
        Connect-SCuBAGraphWithAppPerms
    }
}
function New-SCuBACertificate {
    <#
    .SYNOPSIS
    Automatically creates a self signed certificate for ScubaGear use
    .Description
    Creates a certificates in the client's "Cert:\CurrentUser\My" and outputs both a cert information file plus the public *.cer certitificate file 
    .Parameter FilePath
    The path where the information file and public .cer file will be written to.
    .Example
    New-SCuBACertificate
    .Example
    New-SCuBACertificate -FilePath ./files/certificates
    .Functionality
    Public
    #>
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $FilePath = "."
    )

    $CertName = "ScubaCert_" + ([System.IO.Path]::GetRandomFileName()).split(".")[0]
    $CertParams = @{
        Subject = $CertName
        KeySpec = "KeyExchange"
        CertStoreLocation = "Cert:\CurrentUser\My"
    }

    $MyCert = New-SelfSignedCertificate @CertParams
    Write-Verbose "Created SCuBA Certificate: $($CertName)"
    $CertInformation = Join-Path -Path $FilePath -ChildPath "$($CertName)Information.txt" -ErrorAction 'Stop'
    $MyCert | Out-File -FilePath $CertInformation
    $CertPath = Join-Path -Path $FilePath -ChildPath "$($CertName).cer"
    Export-Certificate -Cert $MyCert -Type CERT -FilePath $CertPath | Out-Null
    $CertName
}

function Update-SCuBAAppCertificate {

}

function Get-SCuBAAppScopes {
    <#
    .SYNOPSIS
    Automatically create an application in the Microsoft Identity Platform with the proper permissions to run ScubaGear.
    .Description
    This function automatically creates a Microsoft IdP application with the permissions and roles need for each product. 
    .Parameter ProductNames
    A list of one or more M365 shortened product names that this function will assing the application permissions to.
    - Azure Active Directory: aad
    - Defender for Office 365: defender
    - Exchange Online: exo
    - MS Power Platform: powerplatform
    - SharePoint Online: sharepoint
    - MS Teams: teams.
    By default all product permissions will be assigned.
    .Parameter M365Environment
    This parameter is used to differentiate commercial/government environments.
    Valid values include "commercial", "gcc", "gcchigh", or "dod".
    - For M365 tenants with E3/E5 licenses enter the value **"commercial"**.
    - For M365 Government Commercial Cloud tenants with G3/G5 licenses enter the value **"gcc"**.
    - For M365 Government Commercial Cloud High tenants enter the value **"gcchigh"**.
    - For M365 Department of Defense tenants enter the value **"dod"**.
    Default value is 'commercial'.
    .Example
    New-SCuBAApplication -DisplayName ScubaGearApplication
    .Example
    New-SCuBAApplication -DisplayName ScubaGearApplication
    .Functionality
    Public
    #>
    [CmdletBinding()]
    param (

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("aad", "defender", "exo", "powerplatform", "sharepoint", "teams", IgnoreCase = $true)]
    [string[]]
    $ProductNames,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $true)]
    [string]
    $M365Environment
    )

    $ResourceAppAccessIds = @()
    $EXOPermissionsRequired = $true
    $AADPermissionsRequired = $true
    foreach ($Product in $ProductNames) {
        $M365EnvironmentPermsParams = @{
            'ProductName' = $Product
            'M365Environment' = $M365Environment
        }
        switch ($Product) {
            "aad" {
                $ResourceAppAccessIds += Get-SCuBAM365EnvironmentPermissions @M365EnvironmentPermsParams
                $AADPermissionsRequired = $false
            }
            {($_ -eq "exo") -or ($_ -eq "defender")} {
                if ($EXOPermissionsRequired) {
                    $ResourceAppAccessIds += Get-SCuBAM365EnvironmentPermissions @M365EnvironmentPermsParams
                    $EXOPermissionsRequired = $false
                }
            }
            "sharepoint" {
                $ResourceAppAccessIds += Get-SCuBAM365EnvironmentPermissions @M365EnvironmentPermsParams
                # This is needed because a Graph cmdlet is used to assist in authenticating to SharePoint
                if ($AADPermissionsRequired) {
                    $ResourceAppAccessIds += @{
                        # MS Graph
                        ResourceAppId = "00000003-0000-0000-c000-000000000000"
                        ResourceAccess = @(
                            {
                                # Directory.Read.All
                                Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
                                Type = "Role"
                            }
                        )
                    }
                    $AADPermissionsRequired = $false
                }
            }
            default {
                # Teams and PowerPlatform do not need any app permissions for ScubaGear
                continue
            }
        }
    }
    $ResourceAppAccessIds
}

function Get-SCuBAAppRoles {
    <#
    .SYNOPSIS
    Automatically create an application in the Microsoft Identity Platform with the proper permissions to run ScubaGear.
    .Description
    This function automatically creates a Microsoft IdP application with the permissions and roles need for each product. 
    .Parameter ProductNames
    A list of one or more M365 shortened product names that this function will assing the application permissions to.
    - Azure Active Directory: aad
    - Defender for Office 365: defender
    - Exchange Online: exo
    - MS Power Platform: powerplatform
    - SharePoint Online: sharepoint
    - MS Teams: teams.
    By default all product permissions will be assigned.
    .Example
    
    .Example
    
    .Functionality
    Public
    #>
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("aad", "defender", "exo", "powerplatform", "sharepoint", "teams", IgnoreCase = $true)]
        [string[]]
        $ProductNames
    )

    $RoleTemplateIds = @()
    $GlobalReaderRequired = $true
    foreach ($Product in $ProductNames) {
        switch ($Product) {
            { ($_ -eq "exo") -or ($_ -eq "defender") -or ($_ -eq "teams") } {
                if ($GlobalReaderRequired) {
                    $RoleTemplateIds += $RolePermissions[$Product]
                    $GlobalReaderRequired = $false
                }
            }
            default {
                # Only Global Reader is currently needed.
                continue
            }
        }
    }
    $RoleTemplateIds
}

function Connect-ToGraphWithAppPerms {
    $GraphScopes = @(
        'Application.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All',
        'Directory.Read.All',
        'AppRoleAssignment.ReadWrite.All'
    )
    $GraphParams = @{
        'ErrorAction' = 'Stop';
        'Scopes' = $GraphScopes;
    }
    Connect-MgGraph @GraphParams | Out-Null
}

function Connect-ToPowerPlatform {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $true)]
        [string]
        $M365Environment
    )
    $AddPowerAppsParams = @{
        'ErrorAction' = 'Stop';
    }
    switch ($M365Environment) {
        "commercial" {
            $AddPowerAppsParams += @{'Endpoint'='prod';}
        }
        "gcc" {
            $AddPowerAppsParams += @{'Endpoint'='usgov';}
        }
        "gcchigh" {
            $AddPowerAppsParams += @{'Endpoint'='usgovhigh';}
        }
        "dod" {
            $AddPowerAppsParams += @{'Endpoint'='dod';}
        }
    }
    Add-PowerAppsAccount @AddPowerAppsParams | Out-Null
}

function Get-SCuBAM365EnvironmentPermissions {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("aad", "defender", "exo", "powerplatform", "sharepoint", "teams", IgnoreCase = $true)]
        [string]
        $ProductName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $true)]
        [string]
        $M365Environment
    )
    if ($M365Environment -in ('commercial', 'gcc')) {
        $CommercialAppPermissions[$Product]
    }
    else {
        $USGovAppPermissions[$Product]
    }
}

function New-SCuBAServicePrincipalRoleAccessAssignment {
    <#
    .SYNOPSIS
    Automatically create an application in the Microsoft Identity Platform with the proper permissions to run ScubaGear.
    .Description
    This function automatically creates a Microsoft IdP application with the permissions and roles need for each product. 
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $AppId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $AppServicePrincipalId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("aad", "defender", "exo", "powerplatform", "sharepoint", "teams", IgnoreCase = $true)]
    [string[]]
    $ProductNames,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $true)]
    [string]
    $M365Environment
    )

    $SPAssignmentParams = @()
    $EXOPermissionsRequired = $true
    $AADPermissionsRequired = $true
    foreach ($Productkey in $CommercialAppPermissions.Keys) {
        $ProductPerm = $CommercialAppPermissions[$ProductKey]

        # skip if no Resource Access permissions needed for this product
        if ($ProductPerm.Count -le 0) { continue }
        $EXORelated = (($Productkey -eq "exo") -or ($Productkey -eq "defender"))

        # skip if the permissions were already added in a different product
        if (($EXORelated) -and (-not $EXOPermissionsRequired)) { continue }


        $ResourceAppId = $ProductPerm['ResourceAppId']
        $ResourceAccessArr = $ProductPerm['ResourceAccess']

        # Get the SP ID of the Resource Application i.e MS Graph PowerShell
        $ResourcePrincipal = Get-MgBetaServicePrincipal -Filter "appId eq '$($ResourceAppId)'"

        foreach ($ResourceAccessDict in $ResourceAccessArr) {
            $BodySPParams = @{
                PrincipalId = $AppServicePrincipalId
                ResourceId  = $ResourcePrincipal.Id
                AppRoleId   = $ResourceAccessDict.Id
            }
            $SPParams = @{
                ServicePrincipalId = $AppServicePrincipalId
                BodyParameter      = $BodySPParams
            }
            $SPAssignmentParams += @{
                'Cmdlet' = 'New-MgBetaServicePrincipalAppRoleAssignment'
                'Params' = $SPParams
            }
        }
        switch ($Productkey) {
            "aad" {
                $AADPermissionsRequired = $false
            }
            { ($_ -eq "exo") -or ($_ -eq "defender") } {
                if ($EXOPermissionsRequired) {
                    $EXOPermissionsRequired = $false
                }
            }
            "sharepoint" {
                if ($AADPermissionsRequired) {
                    # $ResourceAppAccessIds += @{
                    #     # MS Graph
                    #     ResourceAppId  = "00000003-0000-0000-c000-000000000000"
                    #     ResourceAccess = @(
                    #         {
                    #             # Directory.Read.All
                    #             Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
                    #             Type = "Role"
                    #         }
                    #     )
                    # }
                    $AADPermissionsRequired = $false
                }
            }
            default {
                # Teams and PowerPlatform do not need any app permissions for ScubaGear
                continue
            }
        }
    }

    # Run New-MgBetaServicePrincipalAppRoleAssignment to
    # consent to each ResourceAccessID
    foreach ($SPAssignParam in $SPAssignmentParams) {
        $count +=1
        $Cmdlet = $SPAssignParam['Cmdlet']
        $CmdletParams = $SPAssignParam['Params']
        try {
            & $Cmdlet @CmdletParams | Out-Null
        }
        catch {
            Write-Warning $_
        }
    }
}

# function Get-SharePointAADPermissions {
#     param {

#     }
# }

$CommercialAppPermissions = @{
    aad = @{
        # Microsoft Graph
        ResourceAppId = "00000003-0000-0000-c000-000000000000"
        ResourceAccess = @(
            @{
                # Directory.Read.All
                Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
                Type = "Role"
            },
            @{
                # GroupMember.Read.All
                Id = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                Type = "Role"
            },
            @{
                # Organization.Read.All
                Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"
                Type = "Role"
            },
            @{
                # Policy.Read.All
                Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"
                Type = "Role"
            },
            @{
                # RoleManagement.Read.Directory
                Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
                Type = "Role"
            },
            @{
                # User.Read.All
                Id = "df021288-bdef-4463-88db-98f22de89214"
                Type = "Role"
            },
            @{
                # UserAuthenticationMethod.Read.All
                Id = "38d9df27-64da-44fd-b7c5-a6fbac20248f"
                Type = "Role"
            },
            @{
                # PrivilegedEligibilitySchedule.Read.AzureADGroup
                Id = "edb419d6-7edc-42a3-9345-509bfdf5d87c"
                Type = "Role"
            }
        )
    };
    exo = @{
        # Office 365 Exchange Online
        ResourceAppId = "00000002-0000-0ff1-ce00-000000000000"
        ResourceAccess = @(
            @{
                # Exchange.ManageAsApp
                Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"
                Type = "Role"
            }
        )
    };
    defender = @{
        # Office 365 Exchange Online
        ResourceAppId = "00000002-0000-0ff1-ce00-000000000000"
        ResourceAccess = @(
            @{
                # Exchange.ManageAsApp
                Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"
                Type = "Role"
            }
        )
    };
    powerplatform = @{};
    sharepoint = @{
        # Office 365 SharePoint Online
        ResourceAppId = "00000003-0000-0ff1-ce00-000000000000"
        ResourceAccess = @(
            @{
                # Sites.FullControl.All
                Id = "678536fe-1083-478a-9c59-b99265e6b0d3"
                Type = "Role"
            }
        )
    };
    teams = @{};
}

$USGovAppPermissions = @{
    aad = "AAD";
    exo = "EXO";
    defender = "Defender";
    powerplatform = "PowerPlatform";
    sharepoint = "SharePoint";
    teams = "Teams";
}

$RolePermissions = @{
    aad = "none";
    exo = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"; # Global Reader
    defender = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
    powerplatform = "none";
    sharepoint = "none";
    teams = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
}

Export-ModuleMember -Function @(
    'New-SCuBAApplication',
    'Update-SCuBAApplication'
)
