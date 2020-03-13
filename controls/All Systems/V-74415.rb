control "V-74415" do
  title "Windows 10 must be configured to prevent Microsoft Edge browser data
from being cleared on exit."
  desc  "Clearing browser data on exit automatically deletes specified items
when the last browser window closes.  This data could be used to identify
malicious websites and files that could later be used for anti-virus and
Intrusion Detection System (IDS) signatures.  Disabling this function will
prevent the data from automatically being deleted when the browser closes."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-CC-000228"
  tag gid: "V-74415"
  tag rid: "SV-89089r4_rule"
  tag stig_id: "WN10-CC-000228"
  tag fix_id: "F-80957r1_fix"
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
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Privacy\\

Value Name: ClearBrowsingHistoryOnExit

Type: REG_DWORD
Value: 0x00000000 (0)"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Microsoft Edge >> \"Allow
clearing browsing data on exit\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Privacy') do
    it { should have_property 'ClearBrowsingHistoryOnExit' }
    its('ClearBrowsingHistoryOnExit') { should cmp 0 }
  end
end

