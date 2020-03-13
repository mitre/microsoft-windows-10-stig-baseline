control "V-63707" do
  title "The Windows SMB client must be enabled to perform SMB packet signing
when possible."
  desc  "The server message block (SMB) protocol provides the basis for many
network operations.   If this policy is enabled, the SMB client will request
packet signing when communicating with an SMB server that is enabled or
required to perform SMB packet signing."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-SO-000105"
  tag gid: "V-63707"
  tag rid: "SV-78197r1_rule"
  tag stig_id: "WN10-SO-000105"
  tag fix_id: "F-69635r1_fix"
  tag cci: ["CCI-002418", "CCI-002421"]
  tag nist: ["SC-8", "SC-8 (1)", "Rev_4"]
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
  tag check: "If the following registry value does not exist or is not
configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:
\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Microsoft network client: Digitally sign communications (if server agrees)\"
to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

