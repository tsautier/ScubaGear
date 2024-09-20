### Mitchel - Overall Scenario 1 - Test Results - AAD group is assigned to a PIM group causes the tool to crash (nested groups)

- Repeat the tests below in each tenant. You are responsible for setting up your own test users and groups with unique names that are specific to your testing.
- Run the ScubaGear main branch code against the tenant for a specific scenario and verify that it crashes under the conditions described. Then run the fix branch associated with this PR. We are running the main branch and observing the crash to ensure that   the fix was successful.

| Branch | Tenant | Scenario | Expected Results | Actual Results |
|----------|----------|----------|----------|----------|
| main    | G5 | Scenario 1 - Nested group assignment in PIM for Groups (Active assigned to role) | crash 404 error | [ENTER INFO HERE] |
| main    | G5 | Scenario 2 - Nested group assignment in PIM for Groups (Eligible assigned to role) | crash 404 error | [ENTER INFO HERE] |
| main    | G5 | Scenario 3 - Nested group assignment in PIM for Groups (PIM group circular reference) | crash 404 error | [ENTER INFO HERE] |
| fix    | G5 | Scenario 1 - Nested group assignment in PIM for Groups (Active assigned to role) | no crash | [ENTER INFO HERE] |
| fix    | G5 | Scenario 2 - Nested group assignment in PIM for Groups (Eligible assigned to role) | no crash | [ENTER INFO HERE] |
| fix    | G5 | Scenario 3 - Nested group assignment in PIM for Groups (PIM group circular reference) | no crash | [ENTER INFO HERE] |


Test users/groups created: 
- Mitchel's PIM Group 1 (active assigned to Sharepoint Admin)
- Mitchel's PIM Group 2 (eligible assignment to Mitchel's PIM Group 1)
