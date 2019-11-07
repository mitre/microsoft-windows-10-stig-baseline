control "V-63763" do
  title "Services using Local System that use Negotiate when reverting to NTLM
authentication must use the computer identity vs. authenticating anonymously."
  desc  "Services using Local System that use Negotiate when reverting to NTLM
authentication may gain unauthorized access if allowed to authenticate
anonymously vs. using the computer identity."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-SO-000175"
  tag gid: "V-63763"
  tag rid: "SV-78253r1_rule"
  tag stig_id: "WN10-SO-000175"
  tag fix_id: "F-69691r1_fix"
  tag cci: ["CCI-000778"]
  tag nist: ["IA-3", "Rev_4"]
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
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\

Value Name: UseMachineId

Value Type: REG_DWORD
Value: 1"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Network security: Allow Local System to use computer identity for NTLM\" to
\"Enabled\"."
end

