package defender
import future.keywords

## Report details menu
#
# If you simply want a boolean "Requirement met" / "Requirement not met"
# just call ReportDetails(Status) and leave it at that.
#
# If you want to customize the error message, wrap the ReportDetails call
# inside CustomizeError, like so:
# CustomizeError(ReportDetails(Status), "Custom error message")
#
# If you want to customize the error message with details about an array,
# generate the custom error message using GenerateArrayString, for example:
# CustomizeError(ReportDetails(Status), GenerateArrayString(BadPolicies, "bad policies found:"))
#
# If the setting in question requires a defender license,
# wrap the details string inside ApplyLicenseWarning, like so:
# ApplyLicenseWarning(ReportDetails(Status))
#
# These functions can be nested. For example:
# ApplyLicenseWarning(CustomizeError(ReportDetails(Status), "Custom error message"))
#
##
ReportDetails(Status) := "Requirement met" if {
    Status == true
}

ReportDetails(Status) := "Requirement not met" if {
    Status == false
}

GenerateArrayString(Array, CustomString) := Output if {
    # Example usage and output:
    # GenerateArrayString([1,2], "numbers found:") ->
    # 2 numbers found: 1, 2
    Length := format_int(count(Array), 10)
    ArrayString := concat(", ", Array)
    Output := trim(concat(" ", [Length, concat(" ", [CustomString, ArrayString])]), " ")
}

CustomizeError(Message, CustomString) := Message if {
    # If the message reports success, don't apply the custom
    # error message
    Message == ReportDetails(true)
}

CustomizeError(Message, CustomString) := CustomString if {
    # If the message does not report success, apply the custom
    # error message
    Message != ReportDetails(true)
}

CustomizeDetail(Message, CustomString) := Message if {
    # If the message reports success, don't apply the custom
    # Detail message
    Message == ReportDetails(false)
}

CustomizeDetail(Message, CustomString) := CustomString if {
    # If the message does not report success, apply the custom
    # Detail message
    Message != ReportDetails(false)
}

ApplyLicenseWarning(Message) := Message if {
    # If a defender license is present, don't apply the warning
    # and leave the message unchanged
    input.defender_license == true
}

ApplyLicenseWarning(Message) := concat("", [ReportDetails(false), LicenseWarning]) if {
    # If a defender license is not present, assume failure and
    # replace the message with the warning
    input.defender_license == false
    LicenseWarning := " **NOTE: Either you do not have sufficient permissions or your tenant does not have a license for Microsoft Defender for Office 365 Plan 1, which is required for this feature.**"
}


################# Bridewell Azure CSPA Rules #################

#
# B-MCSP-052   Safe attachments and safe links 
#--
B_MCSP_052 := true if {
    # Check for safe attachments
    Policy := input.atp_policy_for_o365[_]
    Policy.EnableSafeDocs == true

    # Check for safe link
    safelink_policy := input.safe_links_policies[_]
    safelink_policy.Id == "Built-In Protection Policy"
    safelink_policy.EnableSafeLinksForOffice == true
} else := false

tests[{
    "Requirement" : "Safe attachments and safe links ",
    "Control" : "B-MCSP-052",
    "Commandlet" : ["Get-AdminAuditLogConfig"],
	"ActualValue" : B_MCSP_052,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_052 == true
}
#--


#
# B-MCSP-104   Enable unified audit logging
#--
B_MCSP_104[{
    "Identity": AuditLog.Identity,
    "UnifiedAuditLogIngestionEnabled": AuditLog.UnifiedAuditLogIngestionEnabled
}] {
    AuditLog := input.admin_audit_log_config[_]
    AuditLog.UnifiedAuditLogIngestionEnabled == true
}

tests[{
    "Requirement" : "Enable unified audit logging",
    "Control" : "B-MCSP-104",
    "Commandlet" : ["Get-AdminAuditLogConfig"],
	"ActualValue" : B_MCSP_104,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_104) >= 1
}
#--

#
# B-MCSP-055   High confidence spam detection action should be set to Quarantine
#--
B_MCSP_055 [concat(": ", [Policy.Id,Policy.Name])] {
    Policy := input.hosted_content_filter_policies[_]
    Policy.HighConfidenceSpamAction in ["Quarantine"]
}

tests[{
    "Requirement" : "High confidence spam detection action should be set to Quarantine",
    "Control" : "B-MCSP-055",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_055,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_055) > 0
}


#
# B-MCSP-056   Phishing detection action should be set to Quarantine
#--
B_MCSP_056 [concat(": ", [Policy.Id,Policy.Name])] {
    Policy := input.hosted_content_filter_policies[_]
    # Policy.Identity == "Default"
    Policy.PhishSpamAction == "Quarantine"
}

tests[{
    "Requirement" : "Phishing detection action should be set to Quarantine",
    "Control" : "B-MCSP-056",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_056,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_056) > 0
}


#
# B-MCSP-058   Auditing of the owner login event should be enabled for all mailboxes
#--
B_MCSP_058 [Setting.UserPrincipalName] {
    Setting := input.mail_settings[_]
    # Policy.Identity == "Default"
    "MailboxLogin" in Setting.AuditOwner
}

tests[{
    "Requirement" : "Auditing of the owner login event should be enabled for all mailboxes",
    "Control" : "B-MCSP-058",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_058,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_058) > 0
}


#
# B-MCSP-060   IMAP should be disabled where not required
#--
B_MCSP_060_1 [CAS.PrimarySmtpAddress] {
    CAS := input.mail_cas_settings[_]
    not CAS.ImapEnabled == false
}

B_MCSP_060_2 [Plan.DisplayName] {
    Plan := input.cas_mailbox_plan[_]
    not Plan.ImapEnabled == false
}

tests[{
    "Requirement" : "IMAP should be disabled where not required",
    "Control" : "B-MCSP-060_1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_060_1,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_060_1) == 0
}

tests[{
    "Requirement" : "IMAP should be disabled for future mailboxes",
    "Control" : "B-MCSP-060_2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_060_2,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_060_2) == 0
}


#
# B-MCSP-061   POP should be disabled where not required
#--
B_MCSP_061_1 [CAS.PrimarySmtpAddress] {
    CAS := input.mail_cas_settings[_]
    not CAS.POPEnabled == false
}

B_MCSP_061_2 [Plan.DisplayName] {
    Plan := input.cas_mailbox_plan[_]
    not Plan.POPEnabled == false
}

tests[{
    "Requirement" : "POP should be disabled where not required",
    "Control" : "B-MCSP-061_1",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_061_1,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_061_1) == 0
}

tests[{
    "Requirement" : "POP should be disabled for future mailboxes",
    "Control" : "B-MCSP-061_2",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_061_2,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_061_2) == 0
}


#
# B-MCSP-062   Consider disabling additional cloud storage providers in Outlook on the web
#--
tests[{
    "Requirement" : "Consider disabling additional cloud storage providers in Outlook on the web",
    "Control" : "B-MCSP-062",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := input.owa_mailbox_policy[0].AdditionalStorageProvidersAvailable == false
}


#
# B-MCSP-063   Configure alerts for restricted users
#--
B_MCSP_063 := true if {
    Alert := input.protection_alerts[_]
    Alert.ImmutableId == "be215649-fba8-4339-9ddd-05991a43b948"
    Alert.Disabled == false

    Alert1 := input.protection_alerts[_]
    Alert1.ImmutableId == "7a4e7306-bbcb-401f-b112-8ca5f798a230"
    Alert1.Disabled == false
} else := false

tests[{
    "Requirement" : "Configure alerts for restricted users",
    "Control" : "B-MCSP-063",
    "Commandlet" : ["Get-ProtectionAlert"],
	"ActualValue" : B_MCSP_063,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_063 == true
}
#--


#
# B-MCSP-064   Safety Tips are enabled
#--
tests[{
    "Requirement" : "Safety Tips are enabled",
    "Control" : "B-MCSP-064",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := input.anti_phish_policies[0].EnableFirstContactSafetyTips == true
}


#
# B-MCSP-065   Whitelisting sender IP addresses should be avoided
#--
B_MCSP_065 [whitelistedIPs] {
    Setting := input.conn_filter[0]
    whitelistedIPs = Setting.IPAllowList[_]
}

tests[{
    "Requirement" : "Whitelisting sender IP addresses should be avoided",
    "Control" : "B-MCSP-065",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_065,
    "ReportDetails" : CustomizeDetail(ReportDetails(Status),GenerateArrayString(B_MCSP_065, "IP allow list found:")),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_065) > 0
}


#
# B-MCSP-067   Zero-hour Auto Purge should be enabled
#--
tests[{
    "Requirement" : "Zero-hour Auto Purge should be enabled",
    "Control" : "B-MCSP-067",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := input.malware_filter_policies[0].ZapEnabled == true
}


#
# B-MCSP-068   Spam detection action should be set to JMF or Quarantine
#--
B_MCSP_068 [concat(": ", [Policy.Id,Policy.Name])] {
    Policy := input.hosted_content_filter_policies[_]
    Policy.Identity == "Default"
    Policy.SpamAction in ["Quarantine", "MoveToJmf"]
}

tests[{
    "Requirement" : "Spam detection action should be set to JMF or Quarantine",
    "Control" : "B-MCSP-068",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_068) == 1
}


#
# B-MCSP-069   Bulk detection action should be set to JMF or Quarantine
#--
B_MCSP_069 [concat(": ", [Policy.Id,Policy.Name])] {
    Policy := input.hosted_content_filter_policies[_]
    Policy.Identity == "Default"
    Policy.BulkSpamAction in ["Quarantine", "MoveToJmf"]
}

tests[{
    "Requirement" : "Bulk detection action should be set to JMF or Quarantine",
    "Control" : "B-MCSP-069",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_069) == 1
}


#
# B-MCSP-072   Use common attachment type filter for blocking suspicious file types
#--
tests[{
    "Requirement" : "Use common attachment type filter for blocking suspicious file types",
    "Control" : "B-MCSP-072",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := input.malware_filter_policies[0].EnableFileFilter == true
}


#
# B-MCSP-074   Turn on Safe Documents for Office Clients
#--
B_MCSP_074 [Policy.Guid] {
    Policy := input.atp_policy_for_o365[_]
    Policy.EnableSafeDocs == true 
    Policy.AllowSafeDocsOpen == false 
}

tests[{
    "Requirement" : "Turn on Safe Documents for Office Clients",
    "Control" : "B-MCSP-074",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_074) > 0
}


#
# B-MCSP-076   Enable notifications for internal users sending malware
#--
B_MCSP_076 [Policy.Guid] {
    Policy := input.malware_filter_policies[_]
    Policy.Identity = "Default"
    Policy.EnableInternalSenderAdminNotifications == true 
}

tests[{
    "Requirement" : "Enable notifications for internal users sending malware",
    "Control" : "B-MCSP-076",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_076) > 0
}


#
# B-MCSP-027   Monitor the addition and removal of users from sensitive roles
#--
B_MCSP_027 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    raw_consoleFilters = replace(Policy.consoleFilters,"'","\"")
    parsed_consoleFilters = json.unmarshal(raw_consoleFilters)
    parsed_consoleFilters["activity.eventActionType"].eq == ["assignPrivilege"]
    parsed_consoleFilters["activity.type"].eq == true
}

tests[{
    "Requirement" : "Monitor the addition and removal of users from sensitive roles",
    "Control" : "B-MCSP-027",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_027,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_027) > 0
}


#
# B-MCSP-110   App Discovery policy
#--
B_MCSP_110 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "NEW_SERVICE"
}

tests[{
    "Requirement" : "App Discovery policy",
    "Control" : "B-MCSP-110",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_110,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_110) > 0
}


#
# B-MCSP-112   Create a custom activity policy to get alerts about suspicious usage patterns
#--
B_MCSP_112 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    Policy.templateId == "5df5c2810de47a83d01a0e56"
}

tests[{
    "Requirement" : "Create a custom activity policy to get alerts about suspicious usage patterns",
    "Control" : "B-MCSP-112",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_112,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_112) > 0
}


#
# B-MCSP-113   Detect administrative actions from a non-corporate IP Address
#--
B_MCSP_113 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    Policy.templateId == "5b3116e1996fe317b4a1b26e"
}

tests[{
    "Requirement" : "Detect administrative actions from a non-corporate IP Address",
    "Control" : "B-MCSP-113",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_113,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_113) > 0
}


#
# B-MCSP-114   Detect Potential ransomware activity
#--
B_MCSP_114 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    Policy.templateId == "5b3116e1996fe317b4a1b275"
}

tests[{
    "Requirement" : "Detect Potential ransomware activity",
    "Control" : "B-MCSP-114",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_114,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_114) > 0
}


#
# B-MCSP-115   Detect a Log on from outdated browser
#--
B_MCSP_115 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    Policy.templateId == "61b5e94e90c2dcaac9cb6a24"
}

tests[{
    "Requirement" : "Detect a Log on from outdated browser",
    "Control" : "B-MCSP-115",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_115,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_115) > 0
}


#
# B-MCSP-116   Multiple failed user log on attempts to an app
#--
B_MCSP_116 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.policyType == "AUDIT"
    Policy.templateId == "61b5e94e90c2dcaac9cb6a1c"
}

tests[{
    "Requirement" : "Multiple failed user log on attempts to an app",
    "Control" : "B-MCSP-116",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_116,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_116) > 0
}


#
# B-MCSP-117   Detect Suspicious inbox manipulation rules
#--
B_MCSP_117 [Policy.name] {
    Policy := input.mcas_policy[_]
    Policy.enabled == true
    Policy.createdBy == "Builtin Policy"
    Policy.policyType == "ANOMALY_DETECTION"
    Policy.name == "Suspicious inbox manipulation rule"
}

tests[{
    "Requirement" : "Detect Suspicious inbox manipulation rules",
    "Control" : "B-MCSP-117",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-McasApi"],
    "ActualValue" : B_MCSP_117,
    "ReportDetails" : ReportDetails(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_117) > 0
}


#
# B-MCSP-043   Email notifications - additional email addresses with a security email contact
#--
B_MCSP_043 [Contact.Email] {
    Contact := input.security_contact[_]
    Contact.Email != ""
}

tests[{
    "Requirement" : "Email notifications - additional email addresses with a security email contact",
    "Control" : "B-MCSP-043",
    "Commandlet" : ["Get-AzSecurityContact"],
    "ActualValue" : B_MCSP_043,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_043) > 0
}


#
# B-MCSP-044   Email notifications - Alert severity
#--
B_MCSP_044 [Contact.Email] {
    Contact := input.security_contact[_]
    Contact.AlertNotifications == "On"
}

tests[{
    "Requirement" : "Email notifications - Alert severity",
    "Control" : "B-MCSP-044",
    "Commandlet" : ["Get-AzSecurityContact"],
    "ActualValue" : B_MCSP_044,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_044) > 0
}


#
# B-MCSP-045   Email notifications - All users set to owner
#--
B_MCSP_045 [Contact.Email] {
    Contact := input.security_contact[_]
    Contact.AlertsToAdmins == "On"
}

tests[{
    "Requirement" : "Email notifications - All users set to owner",
    "Control" : "B-MCSP-045",
    "Commandlet" : ["Get-AzSecurityContact"],
    "ActualValue" : B_MCSP_045,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_045) > 0
}


#
# B-MCSP-119   Compliance policies and configuration profiles
#--
B_MCSP_119 [Configuration_Profile.DisplayName] {
    Configuration_Profile := input.device_management_device_configuration[_]
}

tests[{
    "Requirement" : "Compliance policies and configuration profiles",
    "Control" : "B-MCSP-119",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_119,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_119) > 0
}


#
# B-MCSP-120   Mobile device password/passcode reuse
#--
B_MCSP_120 [Configuration_Profile.DisplayName] {
    # Android Enterprise
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] == "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration"
    "passwordPreviousPasswordCountToBlock" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordPreviousPasswordCountToBlock"] >= 5
}

B_MCSP_120 [Configuration_Profile.DisplayName] {
    # IOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] == "#microsoft.graph.iosGeneralDeviceConfiguration"
    "passcodePreviousPasscodeBlockCount" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passcodePreviousPasscodeBlockCount"] >= 5
}

B_MCSP_120 [Configuration_Profile.DisplayName] {
    # MacOS and Android device administrator
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.macOSGeneralDeviceConfiguration", "#microsoft.graph.androidGeneralDeviceConfiguration"]
    "passwordPreviousPasswordBlockCount" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordPreviousPasswordBlockCount"] >= 5
}

tests[{
    "Requirement" : "Mobile device password/passcode reuse",
    "Control" : "B-MCSP-120",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_120,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_120) > 0
}


#
# B-MCSP-121   Mobile device password expiration
#--
B_MCSP_121 [Configuration_Profile.DisplayName] {
    # Android Enterprise, Android device administrator and MacOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration", "#microsoft.graph.androidGeneralDeviceConfiguration", "#microsoft.graph.macOSGeneralDeviceConfiguration"]
    "passwordExpirationDays" in object.keys(Configuration_Profile.AdditionalProperties)
}

B_MCSP_121 [Configuration_Profile.DisplayName] {
    # IOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] == "#microsoft.graph.iosGeneralDeviceConfiguration"
    "passcodeExpirationDays" in object.keys(Configuration_Profile.AdditionalProperties)
}

tests[{
    "Requirement" : "Mobile device password expiration",
    "Control" : "B-MCSP-121",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_121,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_121) == 0
}


#
# B-MCSP-098   Require devices to be patched, have anti-virus, and firewalls enabled
#--
B_MCSP_098 [Configuration_Policy.DisplayName] {
    Configuration_Policy := input.device_management_device_compliance_policy[_]
    Configuration_Policy.AdditionalProperties["@odata.type"] == "#microsoft.graph.windows10CompliancePolicy"
    Configuration_Policy.AdditionalProperties.antivirusRequired == true
    Configuration_Policy.AdditionalProperties.activeFirewallRequired == true
    "osMinimumVersion" in object.keys(Configuration_Policy.AdditionalProperties)
}

tests[{
    "Requirement" : "Require devices to be patched, have anti-virus, and firewalls enabled",
    "Control" : "B-MCSP-098",
    "Commandlet" : ["Get-MgDeviceManagementDeviceCompliancePolicy"],
    "ActualValue" : B_MCSP_098,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_098) > 0
}


#
# B-MCSP-122   Jailbroken or rooted devices
#--
B_MCSP_122 [Configuration_Policy.DisplayName] {
    Configuration_Policy := input.device_management_device_compliance_policy[_]
    Configuration_Policy.AdditionalProperties["@odata.type"] == "#microsoft.graph.iosCompliancePolicy"
    Configuration_Policy.AdditionalProperties.securityBlockJailbrokenDevices == true
}

tests[{
    "Requirement" : "Jailbroken or rooted devices",
    "Control" : "B-MCSP-122",
    "Commandlet" : ["Get-MgDeviceManagementDeviceCompliancePolicy"],
    "ActualValue" : B_MCSP_122,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_122) > 0
}


#
# B-MCSP-123   Brute force attack
#--
B_MCSP_123 [Configuration_Profile.DisplayName] {
    # Android Enterprise and Android device administrator
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration", "#microsoft.graph.androidGeneralDeviceConfiguration"]
    "passwordSignInFailureCountBeforeFactoryReset" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordSignInFailureCountBeforeFactoryReset"] >= 10
}

B_MCSP_123 [Configuration_Profile.DisplayName] {
    # Android Enterprise, Android device administrator and MacOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration", "#microsoft.graph.androidGeneralDeviceConfiguration", "#microsoft.graph.macOSGeneralDeviceConfiguration"]
    "passwordMinimumLength" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordMinimumLength"] >= 12
}

B_MCSP_123 [Configuration_Profile.DisplayName] {
    # IOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] == "#microsoft.graph.iosGeneralDeviceConfiguration"
    "passcodeSignInFailureCountBeforeWipe" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passcodeSignInFailureCountBeforeWipe"] >= 10
}

B_MCSP_123 [Configuration_Profile.DisplayName] {
    # IOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] == "#microsoft.graph.iosGeneralDeviceConfiguration"
    "passcodeMinimumLength" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passcodeMinimumLength"] >= 12
}

tests[{
    "Requirement" : "Brute force attack",
    "Control" : "B-MCSP-123",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_123,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_123) > 0
}


#
# B-MCSP-124   Screen Lock
#--
B_MCSP_124 [Configuration_Profile.DisplayName] {
    # Android Enterprise and Android device administrator
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration", "#microsoft.graph.androidGeneralDeviceConfiguration"]
    "passwordMinutesOfInactivityBeforeScreenTimeout " in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordMinutesOfInactivityBeforeScreenTimeout "] == 1
}

B_MCSP_124 [Configuration_Profile.DisplayName] {
    # IOS and MacOS
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.iosGeneralDeviceConfiguration","#microsoft.graph.macOSGeneralDeviceConfiguration"]
    "passwordMinutesOfInactivityBeforeLock" in object.keys(Configuration_Profile.AdditionalProperties)
    "passwordMinutesOfInactivityBeforeScreenTimeout" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["passwordMinutesOfInactivityBeforeLock"] == 0
    Configuration_Profile.AdditionalProperties["passwordMinutesOfInactivityBeforeScreenTimeout"] == 1
}

tests[{
    "Requirement" : "Screen Lock",
    "Control" : "B-MCSP-124",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_124,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_124) > 0
}


#
# B-MCSP-125   Enable mobile device encryption
#--
B_MCSP_125 [Configuration_Profile.DisplayName] {
    # Android device administrator
    Configuration_Profile := input.device_management_device_configuration[_]
    Configuration_Profile.AdditionalProperties["@odata.type"] in ["#microsoft.graph.androidGeneralDeviceConfiguration"]
    "storageRequireDeviceEncryption" in object.keys(Configuration_Profile.AdditionalProperties)
    Configuration_Profile.AdditionalProperties["storageRequireDeviceEncryption"] == true
}

tests[{
    "Requirement" : "Enable mobile device encryption",
    "Control" : "B-MCSP-125",
    "Commandlet" : ["Get-MgDeviceManagementDeviceConfiguration"],
    "ActualValue" : B_MCSP_125,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_125) > 0
}


#
# B-MCSP-126   Data Retention
#--
B_MCSP_126 [Policy.Name] {
    Policy := input.retention_compliance_policies[_]
    Policy.Enabled == true
}

tests[{
    "Requirement" : "Data Retention",
    "Control" : "B-MCSP-126",
    "Commandlet" : ["Get-RetentionCompliancePolicy"],
    "ActualValue" : B_MCSP_126,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_126) > 0
}


#
# B-MCSP-127   Data Loss Prevention policy
#--
B_MCSP_127 [Policy.Name] {
    Policy := input.dlp_compliance_policies[_]
    Policy.Enabled == true
    Policy.Workload == "Exchange, SharePoint, OneDriveForBusiness, Teams"
}

tests[{
    "Requirement" : "Data Loss Prevention policy",
    "Control" : "B-MCSP-127",
    "Commandlet" : ["Get-DlpCompliancePolicy"],
    "ActualValue" : B_MCSP_127,
    "ReportDetails" : Status,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_127) > 0
}


###### Checks that will always be not implemented ######

#
# B-MCSP-054   Perform simulated phishing campaigns
#--
tests[{
    "Requirement" : "Perform simulated phishing campaigns",
    "Control" : "B-MCSP-054",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-057   Documented phishing/suspicious email action plan should be developed or improved
#--
tests[{
    "Requirement" : "Documented phishing/suspicious email action plan should be developed or improved",
    "Control" : "B-MCSP-057",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-089   Develop or improve end-user security training program
#--
tests[{
    "Requirement" : "Develop or improve end-user security training program",
    "Control" : "B-MCSP-089",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-090   Develop or improve documented account compromise remediation plan
#--
tests[{
    "Requirement" : "Develop or improve documented account compromise remediation plan",
    "Control" : "B-MCSP-090",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--

#
# B-MCSP-091   Documented process for search & destroy should be developed or improved
#--
tests[{
    "Requirement" : "Documented process for search & destroy should be developed or improved",
    "Control" : "B-MCSP-091",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--