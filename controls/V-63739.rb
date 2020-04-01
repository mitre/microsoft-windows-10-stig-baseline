# -*- encoding : utf-8 -*-

control 'V-63739' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc  "Allowing anonymous SID/Name translation can provide sensitive
        information for accessing a system.  Only authorized users must be able to
        perform such translations."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-SO-000140'
  tag gid: 'V-63739'
  tag rid: 'SV-78229r1_rule'
  tag stig_id: 'WN10-SO-000140'
  tag fix_id: 'F-69667r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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

      If the value for \"Network access: Allow anonymous SID/Name translation\" is
      not set to \"Disabled\", this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network access: Allow anonymous SID/Name translation\" to \"Disabled\"."

  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

