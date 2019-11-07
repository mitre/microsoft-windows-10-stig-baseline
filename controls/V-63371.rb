control "V-63371" do
  title "Accounts must be configured to require password expiration."
  desc  "Passwords that do not expire increase exposure with a greater
probability of being discovered or cracked."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-00-000090"
  tag gid: "V-63371"
  tag rid: "SV-77861r1_rule"
  tag stig_id: "WN10-00-000090"
  tag fix_id: "F-69291r1_fix"
  tag cci: ["CCI-000199"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]
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
  tag check: "Run \"Computer Management\".
Navigate to System Tools >> Local Users and Groups >> Users.
Double click each active account.

If \"Password never expires\" is selected for any account, this is a finding."
  tag fix: "Configure all passwords to expire.
Run \"Computer Management\".
Navigate to System Tools >> Local Users and Groups >> Users.
Double click each active account.
Ensure \"Password never expires\" is not checked on all active accounts."
end

