control "V-63745" do
  title "Anonymous enumeration of SAM accounts must not be allowed."
  desc  "Anonymous enumeration of SAM accounts allows anonymous log on users
(null session connections) to list all accounts names, thus providing a list of
potential points to attack the system."
  impact 0.7
  tag severity: nil
  tag gtitle: "WN10-SO-000145"
  tag gid: "V-63745"
  tag rid: "SV-78235r1_rule"
  tag stig_id: "WN10-SO-000145"
  tag fix_id: "F-69673r1_fix"
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
  tag check: "If the following registry value does not exist or is not
configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Network access: Do not allow anonymous enumeration of SAM accounts\" to
\"Enabled\"."
end

