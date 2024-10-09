package aad
import future.keywords

################
# The report formatting functions below are generic and used throughout the policies #
################
Format(Array) = format_int(count(Array), 10)

Description(String1, String2, String3) =  trim(concat(" ", [String1, String2, String3]), " ")

ReportDetailsBoolean(Status) = "Requirement met" if {Status == true}

ReportDetailsBoolean(Status) = "Requirement not met" if {Status == false}

ReportDetailsArray(Array, String) = Description(Format(Array), String, "")

# Set to the maximum number of array items to be
# printed in the report details section
ReportArrayMaxCount := 20

ReportFullDetailsArray(Array, String) = Details {
    count(Array) == 0
    Details := ReportDetailsArray(Array, String)
}

ReportFullDetailsArray(Array, String) = Details {
    count(Array) > 0
    count(Array) <= ReportArrayMaxCount
    Details := Description(Format(Array), concat(":<br/>", [String, concat(", ", Array)]), "")
}

ReportFullDetailsArray(Array, String) = Details {
    count(Array) > ReportArrayMaxCount
    List := [ x | x := Array[_] ]

    TruncationWarning := "...<br/>Note: The list of matching items has been truncated.  Full details are available in the JSON results."
    TruncatedList := concat(", ", array.slice(List, 0, ReportArrayMaxCount))
    Details := Description(Format(Array), concat(":<br/>", [String, TruncatedList]), TruncationWarning)
}

CapLink := "<a href='#caps'>View all CA policies</a>."

################
# The report formatting functions below are for policies that check the required Azure AD Premium P2 license #
################
Aad2P2Licenses[ServicePlan.ServicePlanId] {
    ServicePlan = input.service_plans[_]
    ServicePlan.ServicePlanName == "AAD_PREMIUM_P2"
}

P2WarningString := "**NOTE: Your tenant does not have an Azure AD Premium P2 license, which is required for this feature**"

ReportDetailsArrayLicenseWarningCap(Array, String) = Description if {
  count(Aad2P2Licenses) > 0
  Description :=  concat(". ", [ReportFullDetailsArray(Array, String), CapLink])
}

ReportDetailsArrayLicenseWarningCap(Array, String) = Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsArrayLicenseWarning(Array, String) = Description if {
  count(Aad2P2Licenses) > 0
  Description :=  ReportFullDetailsArray(Array, String)
}

ReportDetailsArrayLicenseWarning(Array, String) = Description if {
  count(Aad2P2Licenses) == 0
  Description := P2WarningString
}

ReportDetailsBooleanLicenseWarning(Status) = Description if {
    count(Aad2P2Licenses) > 0
    Status == true
    Description := "Requirement met"
}

ReportDetailsBooleanLicenseWarning(Status) = Description if {
    count(Aad2P2Licenses) > 0
    Status == false
    Description := "Requirement not met"
}

ReportDetailsBooleanLicenseWarning(Status) = Description if {
    count(Aad2P2Licenses) == 0
    Description := P2WarningString
}


################# Bridewell Azure CSPA Rules #################

# Return all (top-level) keys in object o
keys(o) = [k | o[k]]

# Return all (top-level) values in object o
values(o) = [v | v := o[_]]

#
# B-MCSP-007   Privacy Profile
#--
tests[{
    "Requirement" : "Privacy Profile",
    "Control" : "B-MCSP-007",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.tenant_details.AADAdditionalData.PrivacyProfile["ContactEmail"] != null
}
#--


#
# B-MCSP-002   Password Protection
#--
B_MCSP_002 := true if {
    some i 
    input.directory_settings[0].Values[i].Name == "EnableBannedPasswordCheck"
    Value := input.directory_settings[0].Values[i].Value
    Value == "True"
} else := false

tests[{
    "Requirement" : "Password Protection",
    "Control" : "B-MCSP-002",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : B_MCSP_002,
    "ReportDetails" : ReportDetailsBoolean(B_MCSP_002),
    "RequirementMet" : B_MCSP_002
}] {
    Status := B_MCSP_002
}
#--


#
# B-MCSP-001   Password hash sync
#--
tests[{
    "Requirement" : "Password hash sync",
    "Control" : "B-MCSP-001",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.tenant_details.AADAdditionalData.OnPremisesSyncEnabled != null
}
#--


#
# B-MCSP-004   Notifications when admins change their password
#--
tests[{
    "Requirement" : "Notifications when admins change their password",
    "Control" : "B-MCSP-004",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.SSPR_policy[0].notifyOnAdminPasswordReset == true
}
#--


#
# B-MCSP-008   Company Branding
#--
tests[{
    "Requirement" : "Company Branding",
    "Control" : "B-MCSP-008",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.tenant_details.AADAdditionalData.Branding.BackgroundImage != null
}
#--


#
# B-MCSP-009   Guest User and External Collaboration Settings
#--
tests[{
    "Requirement" : "Guest User and External Collaboration Settings",
    "Control" : "B-MCSP-009",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.authorization_policies[0].AllowInvitesFrom == "adminsAndGuestInviters"
}
#--


#
# B-MCSP-010   User Application Registration
#--
tests[{
    "Requirement" : "User Application Registration",
    "Control" : "B-MCSP-010",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgPolicyAuthorizationPolicy",
    "ActualValue" : AllowedCreate,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    AllowedCreate := input.authorization_policies[0].DefaultUserRolePermissions.AllowedToCreateApps
    Status := AllowedCreate == false
}
#--


#
# B-MCSP-011   Disable Legacy Authentication
#--
B_MCSP_011[Cap.DisplayName] {
    Cap := input.conditional_access_policies[_]
    # Filter: only include policies that meet all the requirements
    "All" in Cap.Conditions.Users.IncludeUsers
    "All" in Cap.Conditions.Applications.IncludeApplications
    "other" in Cap.Conditions.ClientAppTypes
    # "exchangeActiveSync" in Cap.Conditions.ClientAppTypes
    "block" in Cap.GrantControls.BuiltInControls
    Cap.State == "enabled"
}

tests[{
    "Requirement" : "Disable Legacy Authentication",
    "Control" : "B-MCSP-011",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : B_MCSP_011,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_011, DescriptionString),
    "RequirementMet" : count(B_MCSP_011) > 0
}] {
    DescriptionString := "conditional access policy(s) found that meet(s) all requirements"
    true
}
#--


#
# B-MCSP-012   Conditional Access Policies
#--
B_MCSP_012[Cap.DisplayName] {
    Cap := input.conditional_access_policies[_]
    Cap.State == "enabled"
}

tests[{
    "Requirement" : "Conditional Access Policies",
    "Control" : "B-MCSP-012",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : B_MCSP_012,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_012, DescriptionString),
    "RequirementMet" : count(B_MCSP_012) > 0
}] {
    DescriptionString := "conditional access policy(s) found that meet(s) all requirements"
    true
}
#--


#
# B-MCSP-013   Security Defaults
#--
B_MCSP_013 := true if {
    count(input.security_default_settings) >= 1
    input.security_default_settings[0].IsEnabled == true
    
} else := false

tests[{
    "Requirement" : "Security Defaults",
    "Control" : "B-MCSP-013",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgPolicyAuthorizationPolicy",
    "ActualValue" : B_MCSP_013,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_013
}
#--


#
# B-MCSP-014   Self-Service Password Reset
#--
tests[{
    "Requirement" : "Self-Service Password Reset",
    "Control" : "B-MCSP-014",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.authorization_policies[0].AllowedToUseSspr == true
}
#--


#
# B-MCSP-015   Global Administrator Accounts
#--
B_MCSP_015[User.DisplayName] {
    User := input.privileged_users[_]
    "Global Administrator" in User.roles
}

tests[{
    "Requirement" : "Global Administrator Accounts",
    "Control" : "B-MCSP-015",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : B_MCSP_015,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_015, DescriptionString),
    "RequirementMet" : count(B_MCSP_015) > 3
}] {
    DescriptionString := "privileged users found"
    true
}
#--


#
# B-MCSP-016   Disable LinkedIn Contact Sync
#--
tests[{
    "Requirement" : "Disable LinkedIn Contact Sync",
    "Control" : "B-MCSP-016",
    "Criticality" : "Shall",
    "Commandlet" : "Directories/Properties",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.directory_properties[0].enableLinkedInAppFamily != 1
}
#--


#
# B-MCSP-017   Third party Enterprise Applications
#--
tests[{
    "Requirement" : "Third party Enterprise Applications",
    "Control" : "B-MCSP-017",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : AllowedCreate,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    AllowedCreate := input.authorization_policies[0].DefaultUserRolePermissions.AllowedToCreateApps
    Status := AllowedCreate == false
}
#--


#
# B-MCSP-019   Enabling MFA for admins and users
#--
# Needs to exclude breaking glass accounts
B_MCSP_019[Cap.DisplayName] {
    Cap := input.conditional_access_policies[_]
    "All" in Cap.Conditions.Users.IncludeUsers
    "All" in Cap.Conditions.Applications.IncludeApplications
    "high" in Cap.Conditions.UserRiskLevels
    "passwordChange" in Cap.GrantControls.BuiltInControls
    Cap.State == "enabled"
}

tests[{
    "Requirement" : "Enabling MFA for admins and users",
    "Control" : "B-MCSP-019",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : B_MCSP_019,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_019, DescriptionString),
    "RequirementMet" : count(B_MCSP_019) > 0
}] {
    DescriptionString := "conditional access policy(s) found that meet(s) all requirements"
}
#--


#
# B-MCSP-022   Restrict access to Azure Active Directory portal
#--
tests[{
    "Requirement" : "Restrict access to Azure Active Directory portal",
    "Control" : "B-MCSP-022",
    "Criticality" : "Shall",
    "Commandlet" : "Directories/SsgmProperties",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.directory_properties[0].restrictNonAdminUsers == true
}
#--


#
# B-MCSP-025   Force devices to use MFA when joining Azure Active Directory
#--
tests[{
    "Requirement" : "Force devices to use MFA when joining Azure Active Directory",
    "Control" : "B-MCSP-025",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgPolicyDeviceRegistrationPolicy",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.MgPolicyDeviceRegistrationPolicy[0].MultiFactorAuthConfiguration == "1"
}
#--


#
# B-MCSP-024   Admin consent requests
#--
EnableAdminConsentRequests := a.Values if {
	some a in input.directory_settings
	a.DisplayName == "Consent Policy Settings"
}

B_MCSP_024 := true if {
    some b in EnableAdminConsentRequests
    b.Name == "EnableAdminConsentRequests"
    b.Value== "true"
} else := false

tests[{
    "Requirement" : "Admin consent requests",
    "Control" : "B-MCSP-024",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : B_MCSP_024,
    "ReportDetails" : ReportDetailsBoolean(B_MCSP_024),
    "RequirementMet" : B_MCSP_024
}] {
    Status := B_MCSP_024 == true
}
#--


#
# B-MCSP-018   Temporary Groups Expiration Settings
#--
B_MCSP_018_has[i] {
	some i, val in input.group_lifecycle_settings
	i == "AlternateNotificationEmails"
}

B_MCSP_018_has[i] {
	some i, val in input.group_lifecycle_settings
	i == "ManagedGroupTypes"
	val == "Selected"
}

B_MCSP_018 := true if {
	count(B_MCSP_018_has) == 2
}
else := false

tests[{
    "Requirement" : "Temporary Groups Expiration Settings",
    "Control" : "B-MCSP-018",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : B_MCSP_018,
    "ReportDetails" : ReportDetailsBoolean(B_MCSP_018),
    "RequirementMet" : B_MCSP_018
}] {
    Status := B_MCSP_018
}
#--


#
# B-MCSP-020   Self-service password reset methods
#--
B_MCSP_020[config.Id] {
	some config in input.authentication_policies.AuthenticationMethodConfigurations
    config.State = "enabled"
}

tests[{
    "Requirement" : "Self-service password reset methods",
    "Control" : "B-MCSP-020",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.SSPR_policy[0].numberOfAuthenticationMethodsRequired >= 2
}
#--


#
# B-MCSP-021   Privileged Identity Management
#--
DoPIMRoleRulesExist {
    _ = input.privileged_roles[_]["Rules"]
}

default check_if_role_rules_exist := false
check_if_role_rules_exist := DoPIMRoleRulesExist

RolesWithoutLimitedExpirationPeriod[Role.DisplayName] {
    Role := input.privileged_roles[_]
    Rule := Role.Rules[_]
    RuleMatch := Rule.Id == "Expiration_Admin_Assignment"
    ExpirationNotRequired := Rule.AdditionalProperties.isExpirationRequired == false
    MaximumDurationCorrect := Rule.AdditionalProperties.maximumDuration == "P15D"

    # Role policy does not require assignment expiration
    Conditions1 := [RuleMatch == true, ExpirationNotRequired == true]
    Case1 := count([Condition | Condition = Conditions1[_]; Condition == false]) == 0

    # Role policy requires assignment expiration, but maximum duration is not 15 days
    Conditions2 := [RuleMatch == true, ExpirationNotRequired == false, MaximumDurationCorrect == false]
    Case2 := count([Condition | Condition = Conditions2[_]; Condition == false]) == 0

    # Filter: only include rules that meet one of the two cases
    Conditions := [Case1, Case2]
    count([Condition | Condition = Conditions[_]; Condition == true]) > 0
}

tests[{
    "Requirement" : "Privileged Identity Management",
    "Control" : "B-MCSP-021",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance",
    "ActualValue" : RolesWithoutLimitedExpirationPeriod,
    "ReportDetails" : ReportDetailsArrayLicenseWarning(RolesWithoutLimitedExpirationPeriod, DescriptionString),
    "RequirementMet" : Status
}] {
    DescriptionString := "role(s) configured to allow permanent active assignment or expiration period too long"
    Conditions := [count(RolesWithoutLimitedExpirationPeriod) == 0, check_if_role_rules_exist]
    Status := count([Condition | Condition = Conditions[_]; Condition == false]) == 0
}
#--


# #
# # B-MCSP-023   Utilise Azure active directory identity protection
# #--
# B_MCSP_023 := true if {
# 	Service := input.tenant_details.AADAdditionalData.AssignedPlans[_]
#     Service.ServicePlanId == "eec0eb4f-6444-4f95-aba0-50c24d67f998"
#     Service.CapabilityStatus == true

# } else := "partial" if {
# 	Service := input.tenant_details.AADAdditionalData.AssignedPlans[_]
#     Service.ServicePlanId == "eec0eb4f-6444-4f95-aba0-50c24d67f998"
#     Service.CapabilityStatus == true
    

# } else := false

# tests[{
#     "Requirement" : "Utilise Azure active directory identity protection",
#     "Control" : "B-MCSP-023",
#     "Commandlet" : ["Get-MgSubscribedSku"],
#     "ActualValue" : Status,
#     "ReportDetails" : ReportDetailsBoolean(Status),
#     "RequirementMet" : Status
# }] {
#     Status := B_MCSP_023
# }
# #--


#
# B-MCSP-030   Report Fraud option should be enabled when using multi-factor authentication
#--
tests[{
    "Requirement" : "Report Fraud option should be enabled when using multi-factor authentication",
    "Control" : "B-MCSP-030",
    "Criticality" : "Shall",
    "Commandlet" : "MultiFactorAuthentication/GetOrCreateExpandedTenantModel",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.multi_factor_authentication[0].enableFraudAlert == true
}
#--


#
# B-MCSP-036   User Risk Policies
#--
# Needs to exclude breaking glass accounts
B_MCSP_036[Cap.DisplayName] {
    Cap := input.conditional_access_policies[_]
    "All" in Cap.Conditions.Users.IncludeUsers
    "All" in Cap.Conditions.Applications.IncludeApplications
    "high" in Cap.Conditions.UserRiskLevels
    "passwordChange" in Cap.GrantControls.BuiltInControls
    Cap.State == "enabled"
}

tests[{
    "Requirement" : "User Risk Policies",
    "Control" : "B-MCSP-036",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgIdentityConditionalAccessPolicy",
    "ActualValue" : B_MCSP_036,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_036, DescriptionString),
    "RequirementMet" : count(B_MCSP_036) > 0
}] {
    DescriptionString := "conditional access policy(s) found that meet(s) all requirements"
}
#--


#
# B-MCSP-037   Allow specific group owners to consent for apps
#--
EnableAdminConsentRequests := a.Values if {
	some a in input.directory_settings
	a.DisplayName == "Consent Policy Settings"
}

B_MCSP_037 := true if {
    some b in EnableAdminConsentRequests
    b.Name == "EnableGroupSpecificConsent"
    b.Value== "true"
} else := false

tests[{
    "Requirement" : "Allow specific group owners to consent for apps",
    "Control" : "B-MCSP-037",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgDirectorySetting",
    "ActualValue" : B_MCSP_037,
    "ReportDetails" : ReportDetailsBoolean(B_MCSP_037),
    "RequirementMet" : B_MCSP_037
}] {
    Status := B_MCSP_037 == true
}
#--


#
# B-MCSP-038   Self Service Group Management Configuration
#--
B_MCSP_038 := true if {
    ssgm_Properties := input.ssgm_Properties[0]
    ssgm_Properties.selfServiceGroupManagementEnabled == true
    ssgm_Properties.groupsInAccessPanelEnabled == false

    directory_properties := input.directory_properties[0]
    directory_properties.securityGroupsEnabled == false
    directory_properties.office365GroupsEnabled == false
} else := false

tests[{
    "Requirement" : "Self Service Group Management Configuration",
    "Control" : "B-MCSP-038",
    "Criticality" : "Shall",
    "Commandlet" : "MultiFactorAuthentication/GetOrCreateExpandedTenantModel",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_038 == true
}
#--


#
# B-MCSP-039   Group naming policy
#--
B_MCSP_039[value.Name] {
    setting := input.directory_settings[_]
    setting.DisplayName == "Group.Unified"
    value := setting.Values[_]
    value.Name = "PrefixSuffixNamingRequirement"
    value.Value != ""
}

tests[{
    "Requirement" : "Group naming policy",
    "Control" : "B-MCSP-039",
    "Criticality" : "Shall",
    "Commandlet" : "MultiFactorAuthentication/GetOrCreateExpandedTenantModel",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_039) == 1
}
#--


#
# B-MCSP-040   Consider managing the lifecycle of external users
#--
B_MCSP_040 := true if {
    input.privileged_role_setting[0].ExternalUserLifecycleAction == "BlockSignInAndDelete"
} else := false

tests[{
    "Requirement" : "Consider managing the lifecycle of external users",
    "Control" : "B-MCSP-040",
    "Criticality" : "Shall",
    "Commandlet" : "Get-MgEntitlementManagementSetting",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_040 == true
}
#--


#
# B-MCSP-042   Ensure security team has visibility into risks for assets
#--
B_MCSP_042[User.DisplayName] {
    User := input.privileged_users[_]
    "Security Reader" in User.roles
}

tests[{
    "Requirement" : "Ensure security team has visibility into risks for assets",
    "Control" : "B-MCSP-042",
    "Criticality" : "Shall",
    "Commandlet" : "Get-PrivilegedUser",
    "ActualValue" : B_MCSP_042,
    "ReportDetails" : ReportFullDetailsArray(B_MCSP_042, DescriptionString),
    "RequirementMet" : count(B_MCSP_042) > 0
}] {
    DescriptionString := "privileged users found"
    true
}
#--


#
# B-MCSP-053   Sender Policy Framework should be configured to hard fail
#--
B_MCSP_053[spf_record.domain] {
	spf_record := input.spf_records[_]
    count([txt | txt = spf_record.rdata[_]; contains(txt,"~all")]) != 0
}

tests[{
    "Requirement" : "Sender Policy Framework should be configured to hard fail",
    "Control" : "B-MCSP-053",
    "Criticality" : "Shall",
    "Commandlet" : "Get-ScubaSpfRecords",
    "ActualValue" : B_MCSP_053,
    "ReportDetails" : B_MCSP_053,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_053) == 0
}
#--


###### Checks that will always be not implemented ######

#
# B-MCSP-006   Privileged Access Reviews Protection
#--
tests[{
    "Requirement" : "Privileged Access Reviews Protection",
    "Control" : "B-MCSP-006",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-026   Periodically review all administrative accounts
#--
tests[{
    "Requirement" : "Periodically review all administrative accounts",
    "Control" : "B-MCSP-026",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-032   Do not use shared accounts among administrators
#--
tests[{
    "Requirement" : "Do not use shared accounts among administrators",
    "Control" : "B-MCSP-032",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-033   Emergency access accounts should be controlled and monitored
#--
tests[{
    "Requirement" : "Emergency access accounts should be controlled and monitored",
    "Control" : "B-MCSP-033",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-034   Principle of least privilege should be used
#--
tests[{
    "Requirement" : "Principle of least privilege should be used",
    "Control" : "B-MCSP-034",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-035   Service account access should be limited
#--
tests[{
    "Requirement" : "Service account access should be limited",
    "Control" : "B-MCSP-035",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-041   Encrypt sensitive information in transit
#--
tests[{
    "Requirement" : "Encrypt sensitive information in transit",
    "Control" : "B-MCSP-041",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--


###### Checks that will always be not implemented ######

#
# B-MCSP-028   AAD Connect should be kept up to date for security updates
#--
tests[{
    "Requirement" : "AAD Connect should be kept up to date for security updates",
    "Control" : "B-MCSP-028",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--