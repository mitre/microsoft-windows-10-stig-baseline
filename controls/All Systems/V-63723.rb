control "V-63723" do
  title "The Windows SMB server must perform SMB packet signing when possible."
  desc  "The server message block (SMB) protocol provides the basis for many
network operations.   Digitally signed SMB packets aid in preventing
man-in-the-middle attacks.  If this policy is enabled, the SMB server will
negotiate SMB packet signing as requested by the client."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-SO-000125"
  tag gid: "V-63723"
  tag rid: "SV-78213r1_rule"
  tag stig_id: "WN10-SO-000125"
  tag fix_id: "F-69651r1_fix"
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
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: EnableSecuritySignature

Value Type: REG_DWORD
Value: 1"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Microsoft network server: Digitally sign communications (if Client agrees)\"
to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should cmp 1 }
  end
end

