package teams
import future.keywords

Format(Array) = format_int(count(Array), 10)

Description(String1, String2, String3) = trim(concat(" ", [String1, concat(" ", [String2, String3])]), " ")

ReportDetailsBoolean(Status) = "Requirement met" if {Status == true}

ReportDetailsBoolean(Status) = "Requirement not met" if {Status == false}

ReportDetailsArray(Status, Array, String1) =  Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsArray(Status, Array, String1) = Detail if {
	Status == false
	String2 := concat(", ", Array)
    Detail := Description(Format(Array), String1, String2)
}

ReportDetailsString(Status, String) =  Detail if {
    Status == true
    Detail := "Requirement met"
}

ReportDetailsString(Status, String) =  Detail if {
    Status == false
    Detail := String
}


################# Bridewell Azure CSPA Rules #################



#
# B-MCSP-094   Ensure there are no public groups
#--
B_MCSP_094[Team.DisplayName] {
	Team := input.Team_Config[_]
	Team.Visibility == "Public"
}

B_MCSP_094_result := true if {
	count(B_MCSP_094) == 0
} else := "partial" if {
	Total_Team_Count := count(input.Team_Config)
	count(B_MCSP_094) < Total_Team_Count
} else := false

tests[{
	"Requirement" : "Ensure there are no public groups",
	"Control" : "B-MCSP-094",
	"Commandlet" : ["Get-Team"],
	"ActualValue" : B_MCSP_094,
	"ReportDetails" : B_MCSP_094,
	"RequirementMet" : Status
}] {
	# If all groups are public then not implemented 
	# If some are public then partially implemented
	Status := B_MCSP_094_result
}
#--


#
# B-MCSP-128   File Sharing and Cloud Storage for Teams
#--
B_MCSP_128[client.Identity] {
	client := input.client_configuration[_]
	client.AllowShareFile == true
}

B_MCSP_128[client.Identity] {
	client := input.client_configuration[_]
	client.AllowDropBox == true
}

B_MCSP_128[client.Identity] {
	client := input.client_configuration[_]
	client.AllowBox == true
}

B_MCSP_128[client.Identity] {
	client := input.client_configuration[_]
	client.AllowGoogleDrive == true
}

B_MCSP_128[client.Identity] {
	client := input.client_configuration[_]
	client.AllowEgnyte == true
}

tests[{
	"Requirement" : "File Sharing and Cloud Storage for Teams",
	"Control" : "B-MCSP-128",
	"Criticality" : "Shall",
	"Commandlet" : "Get-CsTenantFederationConfiguration",
	"ActualValue" : Policies,
	"ReportDetails" : ReportDetailsArray(Status, Policies, String),
	"RequirementMet" : Status
}] {
	Policies := B_MCSP_128
	String := "Team policy(ies) that allow file sharing:"
	Status := count(Policies) == 0
}
#--


#
# B-MCSP-129   External Organisations
#--
B_MCSP_129_allow_all[Policy.Identity] {
	Policy := input.federation_configuration[_]
	Policy.AllowFederatedUsers == true
	count(Policy.AllowedDomains) == 0
	count(Policy.BlockedDomains) == 0
}

tests[{
	"Requirement" : "External Organisations",
	"Control" : "B-MCSP-129",
	"Criticality" : "Shall",
	"Commandlet" : "Get-CsTenantFederationConfiguration",
	"ActualValue" : Policies,
	"ReportDetails" : ReportDetailsArray(Status, Policies, String),
	"RequirementMet" : Status
}] {
	Policies := B_MCSP_129_allow_all
	String := "meeting policy(ies) that allow external access across all domains:"
	Status := count(Policies) == 0
}
#--


#
# B-MCSP-130   Consider not automatically admitting anonymous users into Teams meetings
#--
B_MCSP_130[Policy.Identity] {
	Policy := input.meeting_policies[_]
	# Policy.AutoAdmittedUsers in ["EveryoneInCompany", "EveryoneInSameAndFederatedCompany", "EveryoneInCompanyExcludingGuests"]
	Policy.AutoAdmittedUsers ==  "EveryoneInCompanyExcludingGuests"
}

tests[{
	"Requirement" : "Consider not automatically admitting anonymous users into Teams meetings",
	"Control" : "B-MCSP-130",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsMeetingPolicy",
	"ActualValue" : B_MCSP_130,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_130) > 0
}
#--


#
# B-MCSP-131   Consider requiring lobby admittance for anonymous dial-in meeting attendees
#--
B_MCSP_131[Policy.Identity] {
	Policy := input.meeting_policies[_]
	Policy.AllowPSTNUsersToBypassLobby ==  false
}

tests[{
	"Requirement" : "Consider requiring lobby admittance for anonymous dial-in meeting attendees",
	"Control" : "B-MCSP-131",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsMeetingPolicy",
	"ActualValue" : B_MCSP_131,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_131) > 0
}
#--


#
# B-MCSP-132   Consider identifying dial-in meeting attendees
#--
B_MCSP_132[Policy.Identity] {
	Policy := input.teams_meeting_configuration[_]
	Policy.DisableAnonymousJoin ==  true
}

tests[{
	"Requirement" : "Consider identifying dial-in meeting attendees",
	"Control" : "B-MCSP-132",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsMeetingConfiguration",
	"ActualValue" : B_MCSP_132,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_132) == 0
}
#--


#
# B-MCSP-134   Consider disabling open federation in Microsoft Teams
#--
B_MCSP_134[Policy.Identity] {
	# Get allow specific
	Policy := input.federation_configuration[_]
	Policy.AllowFederatedUsers == true
	count(Policy.AllowedDomains) != 0
}

B_MCSP_134[Policy.Identity] {
	# Get block all
	Policy := input.federation_configuration[_]
	Policy.AllowFederatedUsers == false
	count(Policy.AllowedDomains) == 0
	count(Policy.BlockedDomains) == 0
}

tests[{
	"Requirement" : "Consider disabling open federation in Microsoft Teams",
	"Control" : "B-MCSP-134",
	"Criticality" : "Shall",
	"Commandlet" : "Get-CsTenantFederationConfiguration",
	"ActualValue" : Policies,
	"ReportDetails" : ReportDetailsArray(Status, Policies, String),
	"RequirementMet" : Status
}] {
	Policies := B_MCSP_134
	String := "meeting policy(ies) that allow external access across all domains:"
	Status := count(Policies) == 1
}
#--


#
# B-MCSP-135   Manage Guests private calls
#--
B_MCSP_135[Configuration.Identity] {
	Configuration := input.teams_guest_calling_configuration[_]
	Configuration.AllowPrivateCalling ==  true
}

tests[{
	"Requirement" : "Manage Guests private calls",
	"Control" : "B-MCSP-135",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsGuestCallingConfiguration",
	"ActualValue" : B_MCSP_135,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_135) == 0
}
#--


#
# B-MCSP-136   Manage Guests meeting permissions
#--
B_MCSP_136[Configuration.Identity] {
	Configuration := input.teams_guest_meeting_configuration[_]
	Configuration.AllowIPVideo ==  false
	Configuration.AllowMeetNow ==  false
}

tests[{
	"Requirement" : "Manage Guests meeting permissions",
	"Control" : "B-MCSP-136",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsGuestMeetingConfiguration",
	"ActualValue" : B_MCSP_136,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_136) == count(input.teams_guest_meeting_configuration)
}
#--


#
# B-MCSP-137   Configure Guest permissions
#--
B_MCSP_137[Configuration.Identity] {
	Configuration := input.teams_guest_messaging_configuration[_]
	Configuration.AllowUserEditMessage ==  false
	Configuration.AllowUserDeleteMessage ==  false
	Configuration.AllowUserDeleteChat ==  false
	Configuration.AllowUserChat ==  true
	Configuration.AllowGiphy ==  true
	Configuration.GiphyRatingType ==  "Moderate"
	Configuration.AllowMemes ==  true
	Configuration.AllowImmersiveReader ==  true
	Configuration.AllowStickers ==  true
}

tests[{
	"Requirement" : "Configure Guest permissions",
	"Control" : "B-MCSP-137",
	"Criticality" : "Should",
	"Commandlet" : "Get-CsTeamsGuestMessagingConfiguration",
	"ActualValue" : B_MCSP_137,
	"ReportDetails" : ReportDetailsBoolean(Status),
	"RequirementMet" : Status
}] {
	Status :=  count(B_MCSP_137) == count(input.teams_guest_messaging_configuration)
}
#--