package sharepoint
import future.keywords

ReportDetailsBoolean(Status) = "Requirement met" if {Status == true}

ReportDetailsBoolean(Status) = "Requirement not met" if {Status == false}


################# Bridewell Azure CSPA Rules #################

#
# B-MCSP-138   Modern Authentication and SharePoint Applications
#--
tests[{
    "Requirement" : "Modern Authentication and SharePoint Applications",
    "Control" : "B-MCSP-138",
    "Criticality" : "Shall",
    "Commandlet" : "Get-SPOTenant",
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.SPO_tenant[0].LegacyAuthProtocolsEnabled == false
}
#--


#
# B-MCSP-139   Data Loss Prevention
#--
B_MCSP_139[label.DisplayName] {
	label := input.data_classification_label[_]
    label.Disabled == false
}

tests[{
	"Requirement" : "Data Loss Prevention",
	"Control" : "B-MCSP-139",
	"Criticality" : "Should",
	"Commandlet" : "Get-Label",
	"ActualValue" : Status,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_139) > 0
}
#--


#
# B-MCSP-140   Unmanaged Device Access in Office 365/SharePoint
#--
B_MCSP_140[concat(": ", ["CA policy", Policy.DisplayName])] {
    Policy := input.conditional_access_policies[_]
    "00000003-0000-0ff1-ce00-000000000000" in Policy.Conditions.Applications.IncludeApplications
    "compliantDevice" in Policy.GrantControls.BuiltInControls
    Policy.State == "enabled"
}
B_MCSP_140[concat(": ", ["CA policy", Policy.DisplayName])] {
    Policy := input.conditional_access_policies[_]
    "All" in Policy.Conditions.Applications.IncludeApplications
    "compliantDevice" in Policy.GrantControls.BuiltInControls
    Policy.State == "enabled"
}
B_MCSP_140[index] {
    some index, tenant in input.SPO_tenant
    tenant.ConditionalAccessPolicy in [1,2]
}

tests[{
    "Requirement" : "Unmanaged Device Access in Office 365/SharePoint",
    "Control" : "B-MCSP-140",
    "Criticality" : "Shall",
    "Commandlet" : "Get-SPOTenant",
    "ActualValue" : B_MCSP_140,
    "ReportDetails" : count(B_MCSP_140),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_140) >= 1
}
#--


#
# B-MCSP-141   Limit External Sharing in SharePoint Online
#--
B_MCSP_141[index] {
	some index, tenant in input.SPO_tenant
    tenant.SharingDomainRestrictionMode in [1,2]
}
B_MCSP_141[index] {
	some index, site in input.SPO_site
    count(site.WhoCanShareAllowListInTenantByPrincipalIdentity) > 0
}
B_MCSP_141[index] {
	some index, site in input.SPO_site
    count(site.GuestSharingGroupAllowListInTenantByPrincipalIdentity) > 0
}

tests[{
	"Requirement" : "Limit External Sharing in SharePoint Online",
	"Control" : "B-MCSP-141",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_141,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_141) > 0
}
#--


#
# B-MCSP-142   External Links Expiration Settings
#--
B_MCSP_142[index] {
	some index, tenant in input.SPO_tenant
    tenant.ExternalUserExpirationRequired == false
}

tests[{
	"Requirement" : "External Links Expiration Settings",
	"Control" : "B-MCSP-142",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_142,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_142) == 0
}
#--


#
# B-MCSP-143   Access Control Policy
#--
B_MCSP_143[index] {
	some index, tenant in input.SPO_tenant
    tenant.ExternalUserExpirationRequired == false
}

tests[{
	"Requirement" : "Access Control Policy",
	"Control" : "B-MCSP-143",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_143,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status := input.SPO_tenant[0].LegacyAuthProtocolsEnabled == false
}
#--


#
# B-MCSP-144   Monitor SharePoint Online and OneDrive external sharing invitations
#--
B_MCSP_144[tenant.BccExternalSharingInvitationsList] {
	some index, tenant in input.SPO_tenant
    tenant.BccExternalSharingInvitations == true
}

tests[{
	"Requirement" : "Monitor SharePoint Online and OneDrive external sharing invitations",
	"Control" : "B-MCSP-144",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_144,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_144) == count(input.SPO_tenant)
}
#--


#
# B-MCSP-152   Limit OneDrive access
#--
B_MCSP_152 := true if {
	tenant := input.SPO_tenant[_]
  tenant.EnableRestrictedAccessControl != false
} else := false

tests[{
	"Requirement" : "Limit OneDrive access",
	"Control" : "B-MCSP-152",
	"Commandlet" : ["Get-SPOTenant"],
	"ActualValue" : B_MCSP_152,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status := B_MCSP_152
}
#--


#
# B-MCSP-148   Consider setting the default sharing link type to a value other than Anonymous
#--
SPO_share_with_anyone_sites := [Site.Title | Site = input.SPO_site[_]; Site.DefaultSharingLinkType == 3 ]

B_MCSP_148 := true {
	# Check if default sharing type is NOT anyone
	input.SPO_tenant[0].DefaultSharingLinkType > 0
	input.SPO_tenant[0].DefaultSharingLinkType < 3
	# Check all sites if sharing type is NOT anyone
	site := input.SPO_site[_]
	count(SPO_share_with_anyone_sites) == 0
} else := false

tests[{
	"Requirement" : "Consider setting the default sharing link type to a value other than Anonymous",
	"Control" : "B-MCSP-148",
	"Commandlet" : ["Get-SPOSite"],
	"ActualValue" : SPO_share_with_anyone_sites,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  B_MCSP_148
}
#--


# B-MCSP-145   Consider configuring conditional access in SharePoint Online
#--
# B_MCSP_145[concat(": ", ["CA policy", Policy.DisplayName])] {
#     # Get CA policy for sharepoint
#     Policy := input.conditional_access_policies[_]
#     "00000003-0000-0ff1-ce00-000000000000" in Policy.Conditions.Applications.IncludeApplications
#     "compliantDevice" in Policy.GrantControls.BuiltInControls
#     Policy.State == "enabled"
# }

B_MCSP_145[index] {
	some index, tenant in input.SPO_tenant
    tenant.IPAddressEnforcement == true
}

tests[{
    "Requirement" : "Consider configuring conditional access in SharePoint Online",
    "Control" : "B-MCSP-145",
    "Criticality" : "Shall",
    "Commandlet" : "Get-SPOTenant",
    "ActualValue" : B_MCSP_145,
    "ReportDetails" : count(B_MCSP_145),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_145) >= 1
}
#--
#


#
# B-MCSP-147   Link expiration should be configured when using anonymous access sharing links
#--
B_MCSP_147[site.Title] {
	site := input.SPO_site[_]
  site.AnonymousLinkExpirationInDays > 0
}

tests[{
	"Requirement" : "Link expiration should be configured when using anonymous access sharing links",
	"Control" : "B-MCSP-147",
	"Commandlet" : ["Get-SPOSite"],
	"ActualValue" : B_MCSP_147,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_147) == 0
}
#--


#
# B-MCSP-149   Ensure that external users cannot share files, folders, and sites they do not own
#--
B_MCSP_149[index] {
	some index, tenant in input.SPO_tenant
    not tenant.PreventExternalUsersFromResharing == true
}

tests[{
	"Requirement" : "Ensure that external users cannot share files, folders, and sites they do not own",
	"Control" : "B-MCSP-149",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_149,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_149) == 0
}
#--


#
# B-MCSP-150   Default permission type on shared links
#--
B_MCSP_150[index] {
	some index, tenant in input.SPO_tenant
    not tenant.DefaultLinkPermission == 1
}

tests[{
	"Requirement" : "Default permission type on shared links",
	"Control" : "B-MCSP-150",
	"Criticality" : "Should",
	"Commandlet" : "Get-SPOTenant",
	"ActualValue" : B_MCSP_150,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_150) == 0
}
#--


###### Checks that will always be not implemented ######

#
# B-MCSP-146   Consider disallowing Anyone sharing links at the tenant level in SharePoint Online
#--
tests[{
    "Requirement" : "Consider disallowing Anyone sharing links at the tenant level in SharePoint Online",
    "Control" : "B-MCSP-146",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--