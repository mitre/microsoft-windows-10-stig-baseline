control "V-63639" do
  title "Outgoing secure channel traffic must be encrypted or signed."
  desc  "Requests sent on the secure channel are authenticated, and sensitive
information (such as passwords) is encrypted, but not all information is
encrypted.  If this policy is enabled, outgoing secure channel traffic will be
encrypted and signed."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-SO-000035"
  tag gid: "V-63639"
  tag rid: "SV-78129r1_rule"
  tag stig_id: "WN10-SO-000035"
  tag fix_id: "F-69567r1_fix"
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
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireSignOrSeal

Value Type: REG_DWORD
Value: 1"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain
member: Digitally encrypt or sign secure channel data (always)\" to
\"Enabled\"."
end

