control "V-63705" do
  title "InPrivate browsing in Microsoft Edge must be disabled."
  desc  "The InPrivate browsing feature in Microsoft Edge prevents the storing
of history, cookies, temporary Internet files, or other data.  Disabling this
feature maintains this data for review as necessary."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-CC-000240"
  tag gid: "V-63705"
  tag rid: "SV-78195r4_rule"
  tag stig_id: "WN10-CC-000240"
  tag fix_id: "F-83243r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: false
  tag mitigations: nil
  tag severity_override_guidance: false
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  tag check: "Windows 10 LTSC\\B versions do not include Microsoft Edge, this
is NA for those systems.

If the following registry value does not exist or is not configured as
specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\\

Value Name: AllowInPrivate

Type: REG_DWORD
Value: 0x00000000 (0)"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Microsoft Edge >> \"Allow
InPrivate browsing\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main') do
    it { should have_property 'AllowInPrivate' }
    its('AllowInPrivate') { should cmp 0 }
  end
end

