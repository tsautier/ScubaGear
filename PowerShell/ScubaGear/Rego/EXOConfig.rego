package exo
import future.keywords

Format(Array) = format_int(count(Array), 10)

Description(String1, String2, String3) = trim(concat(" ", [String1, concat(" ", [String2, String3])]), " ")

ReportDetailsBoolean(Status) = "Requirement met" if {Status == true}

ReportDetailsBoolean(Status) = "Requirement not met" if {Status == false}

ReportDetailsArray(Status, Array1, Array2) =  Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsArray(Status, Array1, Array2) = Detail if {
	Status == false
    Fraction := concat(" of ", [Format(Array1), Format(Array2)])
	String := concat(", ", Array1)
    Detail := Description(Fraction, "agency domain(s) found in violation:", String)
}

ReportDetailsString(Status, String) =  Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsString(Status, String) =  Detail if {
    Status == false
    Detail := String
}

AllDomains := {Domain.domain | Domain = input.spf_records[_]}

CustomDomains[Domain.domain] {
    Domain = input.spf_records[_]
    not endswith( Domain.domain, "onmicrosoft.com")
}


################# Bridewell Azure CSPA Rules #################

#
# B-MCSP-046   Ensure DKIM is enabled for all domains
#--
B_MCSP_046 := true if {
    # Check if return is empty
    input.dkim_config != [null]
    count(input.dkim_config) > 0
    # Get domains that have dkim enabled
    res := [dkim_config.Domain|dkim_config := input.dkim_config[_];dkim_config.Enabled == true]
    # Check if ALL domains are enabled
    count(input.dkim_config) == count(res)
} else := false

tests[{
    "Requirement" : "Ensure DKIM is enabled for all domains",
    "Control" : "B-MCSP-046",
    "Commandlet" : ["Get-DkimSigningConfig"],
    "ActualValue" : B_MCSP_046,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_046
}


#
# B-MCSP-047   SPF Records
#--
B_MCSP_047[spf_record.domain] {
    # Soft fail
    spf_record := input.spf_records[_]
    number_of_soft_fail := [rdata | rdata := spf_record.rdata[_]; contains(rdata,"~all")]
    count(number_of_soft_fail) > 0
}
B_MCSP_047[spf_record.domain] {
    # Too many lookups
    spf_record := input.spf_records[_]
    number_of_included_domains := [domain | rdata := spf_record.rdata[_]; contains(rdata,"v=spf1"); domains := split(rdata," "); domain := domains[_]; startswith(domain, "include:")]
    count(number_of_included_domains) > 5
}
B_MCSP_047[spf_record.domain] {
    # Missing spf records
    spf_record := input.spf_records[_]
    count(spf_record.rdata) == 0
}

tests[{
    "Requirement" : "SPF Records",
    "Control" : "B-MCSP-047",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-ScubaSpfRecords"],
    "ActualValue" : B_MCSP_047,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_047) == 0
}


#
# B-MCSP-048   DMARC Entries
#--
B_MCSP_048[dmarc_record.domain] {
    # No DMARC record
    dmarc_record = input.dmarc_records[_]
    count(dmarc_record.rdata) == 0
}
B_MCSP_048[dmarc_record.domain] {
    # Policy action of 'none'
    dmarc_record = input.dmarc_records[_]
    rdata := dmarc_record.rdata
    invalid_policy := [rdata | rdata := dmarc_record.rdata; contains(rdata,"p=none")]
    count(invalid_policy) != 0
}
# B_MCSP_048[dmarc_record.domain] {
#     # Issues with DNS records
#     dmarc_record = input.dmarc_records[_]
# }

tests[{
    "Requirement" : "DMARC Entries",
    "Control" : "B-MCSP-048",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-ScubaDmarcRecords"],
    "ActualValue" : B_MCSP_048,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_048) == 0
}


#
# B-MCSP-059   SMTP authenticated submission should be turned off when not required by applications
#--
tests[{
    "Requirement" : "SMTP authenticated submission should be turned off when not required by applications",
    "Control" : "B-MCSP-059",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.transport_config[0].SmtpClientAuthenticationDisabled == true
}


#
# B-MCSP-071   SMTP authenticated submission should be disabled if not required by apps
#--
B_MCSP_071 [CAS.PrimarySmtpAddress] {
    CAS := input.mail_cas_settings[_]
    CAS.SmtpClientAuthenticationDisabled == false 
}

tests[{
    "Requirement" : "SMTP authenticated submission should be disabled if not required by apps",
    "Control" : "B-MCSP-071",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.transport_config[0].SmtpClientAuthenticationDisabled == true
}


#
# B-MCSP-073   Zero-hour Auto Purge requires supported action in spam policy
#--
B_MCSP_073 := true if  {
    Policy := input.hosted_content_filter_policies[0]
    # Policy.HighConfidenceSpamAction in ["AddXHeader", "MoveToJmf", "Quarantine"]
    Policy.SpamAction in ["AddXHeader", "MoveToJmf", "Quarantine"]
} else := false

tests[{
    "Requirement" : "Zero-hour Auto Purge requires supported action in spam policy",
    "Control" : "B-MCSP-073",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_073,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_073 == true
}


#
# B-MCSP-077   Installing Outlook add-ins is not allowed
#--
B_MCSP_077 [Policy.Name] {
    Policy := input.role_assignment_policy[_]
    Policy.IsDefault == true
    "My Custom Apps" in Policy.AssignedRoles
}

tests[{
    "Requirement" : "Installing Outlook add-ins is not allowed",
    "Control" : "B-MCSP-077",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_077,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_077) == 0
}


#
# B-MCSP-078   Ensure mail transport rules do not forward to external domains
#--
B_MCSP_078 [Rule.Name] {
    Rule := input.transport_rule[_]
    "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.RedirectMessageAction" in Rule.Actions
    Rule.RedirectMessageTo != null
    AllDomainsUpper = {Domain | Domain = upper(input.spf_records[_].domain)}
    RedirectDest := {res | Domain = Rule.RedirectMessageTo[_]; l := split(Domain, "@") ; res := upper(l[count(l)-1])}
    ExternalDest := intersection({RedirectDest, AllDomainsUpper})
    count(ExternalDest) != 0
}

tests[{
    "Requirement" : "Ensure mail transport rules do not forward to external domains",
    "Control" : "B-MCSP-078",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_078,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_078) == 0
}


#
# B-MCSP-081   Enable mailbox auditing for all mailboxes
#--
B_MCSP_081_pass [Setting.UserPrincipalName] {
    Setting := input.mail_settings[_]
    Setting.AuditEnabled == true
    "BPOS_S_EquivioAnalytics" in Setting.PersistedCapabilities
    "M365Auditing" in Setting.PersistedCapabilities
}

B_MCSP_081 [Setting.UserPrincipalName] {
    Setting := input.mail_settings[_]
    not Setting.UserPrincipalName in B_MCSP_081_pass
}

tests[{
    "Requirement" : "Enable mailbox auditing for all mailboxes",
    "Control" : "B-MCSP-081",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_081,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_081) == count(input.mail_settings)
}


#
# B-MCSP-082   Disable remote PowerShell on standard user accounts
#--
B_MCSP_082 [User.DisplayName] {
    User := input.exo_users[0][_]
    User.RemotePowerShellEnabled == true
}

tests[{
    "Requirement" : "Disable remote PowerShell on standard user accounts",
    "Control" : "B-MCSP-082",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_082,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_082) == 0
}


#
# B-MCSP-083   Ensure Calendar details sharing with external users is disabled
#--
B_MCSP_083_Wanted_Domains := ["*", "Anonymous"]

B_MCSP_083 [{"Name": Policy.Id, "Policy": Domains}]{
	Policy := input.sharing_policy[_]
	Domains := [{"Domain": domain, "Rule": rule} | domain := split(Policy.Domains[i], ":")[0]; rule := split(Policy.Domains[i], ":")[1]]
	count(Domains) > 0
    ValidDomains := [domain | domain := Domains[i].Domain ; domain in B_MCSP_083_Wanted_Domains ]
    count(ValidDomains) > 0
}

B_MCSP_083_fail [Policy.Name] {
    Policy := B_MCSP_083[_]
    InvalidDomains := [domain | domain := Policy.Policy[i].Domain ; domain in B_MCSP_083_Wanted_Domains; Policy.Policy[i].Rule != "CalendarSharingFreeBusySimple" ]
    count(InvalidDomains) > 0
}

tests[{
    "Requirement" : "Ensure Calendar details sharing with external users is disabled",
    "Control" : "B-MCSP-083",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_083_fail,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_083_fail) == 0
}


#
# B-MCSP-084   Disable notifying external senders of malware detection
#--
B_MCSP_084_not_exist := true if {
	Policy := input.malware_filter_policies[0]
	not "EnableExternalSenderNotifications" in object.keys(Policy)
} else := false

B_MCSP_084_value := true if {
	Policy := input.malware_filter_policies[0]
	Policy.EnableExternalSenderNotifications == false
} else := false

B_MCSP_084 := true if {
	true in [B_MCSP_084_not_exist, B_MCSP_084_value]
} else := false

tests[{
    "Requirement" : "Disable notifying external senders of malware detection",
    "Control" : "B-MCSP-084",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_084
}


#
# B-MCSP-086   Disable remote PowerShell on standard user accounts
#--
B_MCSP_086 [User] {
    User := input.exo_accepted_domain[_]["DomainName"]
}

tests[{
    "Requirement" : "Disable remote PowerShell on standard user accounts",
    "Control" : "B-MCSP-086",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_086,
    "ReportDetails" : B_MCSP_086,
    "RequirementMet" : Status
}] {
    Status := false
}


#
# B-MCSP-087   External Email Recipient MailTip
#--
tests[{
    "Requirement" : "External Email Recipient MailTip",
    "Control" : "B-MCSP-087",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := input.org_config[0].MailTipsExternalRecipientsTipsEnabled == true
}


#
# B-MCSP-088   External sender identification
#--
B_MCSP_088 := true if {
	Policy := input.external_in_outlook[0]
    "Enabled" in object.keys(Policy)
	Policy.Enabled == true
} else := false

tests[{
    "Requirement" : "External sender identification",
    "Control" : "B-MCSP-088",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : Status,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := B_MCSP_088 == true
}


#
# B-MCSP-079   Client rules forwarding block
#--
B_MCSP_079 [Rule.Name] {
    Rule := input.transport_rule[_]
    Rule.FromScope == "InOrganization"
    Rule.SentToScope == "NotInOrganization"
}

tests[{
    "Requirement" : "Client rules forwarding block",
    "Control" : "B-MCSP-079",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_079,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_079) == 0
}


#
# B-MCSP-080   External Email Warning Message
#--
B_MCSP_080 [{
    "Name": Rule.Name, 
    "SubjectOrBodyMatchesPatterns": Rule.SubjectOrBodyMatchesPatterns, 
    "PrependSubject": Rule.PrependSubject
}] {
    Rule := input.transport_rule[_]
    Rule.FromScope == "NotInOrganization"
    Rule.SentToScope == "InOrganization"
}

tests[{
    "Requirement" : "External Email Warning Message",
    "Control" : "B-MCSP-080",
    "Criticality" : "Shall",
    "Commandlet" : ["Get-HostedContentFilterPolicy"],
    "ActualValue" : B_MCSP_080,
    "ReportDetails" : ReportDetailsBoolean(Status),
    "RequirementMet" : false
}] {
    Status := false
}


#
# B-MCSP-051   Ensure anti-phishing policy is created
#--
B_MCSP_051[policy.Identity] {
	policy := input.anti_phish_policies[_]
    policy.EnableMailboxIntelligence == true
    policy.EnableSpoofIntelligence == true
}

tests[{
    "Requirement" : "Ensure anti-phishing policy is created",
    "Control" : "B-MCSP-051",
    "Criticality" : "Shall",
    "Commandlet" : "Get-ScubaSpfRecords",
    "ActualValue" : B_MCSP_051,
    "ReportDetails" : B_MCSP_051,
    "RequirementMet" : Status
}] {
    Status := count(B_MCSP_051) != 0
}
#--


###### Checks that will always be not implemented ######

#
# B-MCSP-085   Periodically review mail forwarding
#--
tests[{
    "Requirement" : "Periodically review mail forwarding",
    "Control" : "B-MCSP-085",
    "Commandlet" : ["None"],
    "ActualValue" : Status,
    "ReportDetails" : "Client should review this check internally",
    "RequirementMet" : Status
}] {
    Status := false
}
#--