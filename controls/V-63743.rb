# -*- encoding : utf-8 -*-

control 'V-63743' do
  title 'Attachments must be prevented from being downloaded from RSS feeds.'
  desc  "Attachments from RSS feeds may not be secure.  This setting will
        prevent attachments from being downloaded from RSS feeds."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000295'
  tag gid: 'V-63743'
  tag rid: 'SV-78233r1_rule'
  tag stig_id: 'WN10-CC-000295'
  tag fix_id: 'F-69671r1_fix'
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

      Value Name: DisableEnclosureDownload

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> RSS Feeds >> \"Prevent
      downloading of enclosures\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp 1 }
  end
end

