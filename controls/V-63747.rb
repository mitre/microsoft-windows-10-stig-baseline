# -*- encoding : utf-8 -*-

control 'V-63747' do
  title 'Basic authentication for RSS feeds over HTTP must not be used.'
  desc  "Basic authentication uses plain text passwords that could be used to
        compromise a system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000300'
  tag gid: 'V-63747'
  tag rid: 'SV-78237r1_rule'
  tag stig_id: 'WN10-CC-000300'
  tag fix_id: 'F-69675r1_fix'
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

  desc "check", "The default behavior is for the Windows RSS platform to not use
        Basic authentication over HTTP connections.

        If the registry value name below does not exist, this is not a finding.

        If it exists and is configured with a value of \"0\", this is not a finding.

        If it exists and is configured with a value of \"1\", this is a finding.

        Registry Hive: HKEY_LOCAL_MACHINE
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

        Value Name: AllowBasicAuthInClear

        Value Type: REG_DWORD
        Value: 0 (or if the Value Name does not exist)"
      
  desc "fix", "The default behavior is for the Windows RSS platform to not use
        Basic authentication over HTTP connections.

        If this needs to be corrected, configure the policy value for Computer
        Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >>
        \"Turn on Basic feed authentication over HTTP\" to \"Not Configured\" or
        \"Disabled\"."

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
      it { should have_property 'AllowBasicAuthInClear' }
      its('AllowBasicAuthInClear') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
      it { should_not have_property 'AllowBasicAuthInClear' }
    end
  end
end

