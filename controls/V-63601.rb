# -*- encoding : utf-8 -*-

control 'V-63601' do
  title 'The built-in administrator account must be disabled.'
  desc  "The built-in administrator account is a well-known account subject to
        attack.  It also provides no accountability to individual administrators on a
        system.  It must be disabled to prevent its use."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000005'
  tag gid: 'V-63601'
  tag rid: 'SV-78091r1_rule'
  tag stig_id: 'WN10-SO-000005'
  tag fix_id: 'F-69531r1_fix'
  tag cci: ['CCI-000764']
  tag nist: %w[IA-2 Rev_4]
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
  desc "check", "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".

      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
      >> Security Settings >> Local Policies >> Security Options.

      If the value for \"Accounts: Administrator account status\" is not set to
      \"Disabled\", this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Accounts: Administrator account status\" to \"Disabled\"."

  describe security_policy do
    its('EnableAdminAccount') { should cmp 0 }
  end
end

