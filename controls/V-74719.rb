# -*- encoding : utf-8 -*-

control 'V-74719' do
  title 'The Secondary Logon service must be disabled on Windows 10.'
  desc  "The Secondary Logon service provides a means for entering alternate
        credentials, typically used to run commands with elevated privileges.  Using
        privileged credentials in a standard user session can expose those credentials
        to theft."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000175'
  tag gid: 'V-74719'
  tag rid: 'SV-89393r2_rule'
  tag stig_id: 'WN10-00-000175'
  tag fix_id: 'F-81333r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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
  desc "check", "Run \"Services.msc\".

      Locate the \"Secondary Logon\" service.

      If the \"Startup Type\" is not \"Disabled\" or the \"Status\" is \"Running\",
      this is a finding."
  desc "fix", 'Configure the "Secondary Logon" service "Startup Type" to "Disabled".'

  describe.one do
    describe service('Secondary Logon') do
      it { should_not be_enabled }
    end
    describe service('Secondary Logon') do
      it { should_not be_running }
    end
  end
end

