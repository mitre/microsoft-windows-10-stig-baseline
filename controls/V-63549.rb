# -*- encoding : utf-8 -*-

control 'V-63549' do
  title 'The display of slide shows on the lock screen must be disabled.'
  desc  "Slide shows that are displayed on the lock screen could display
        sensitive information to unauthorized personnel.  Turning off this feature will
        limit access to the information to a logged on user."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000010'
  tag gid: 'V-63549'
  tag rid: 'SV-78039r1_rule'
  tag stig_id: 'WN10-CC-000010'
  tag fix_id: 'F-69479r1_fix'
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

  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

      Value Name: NoLockScreenSlideshow

      Value Type: REG_DWORD
      Value: 1"
      
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Control Panel >> Personalization >> \"Prevent
      enabling lock screen slide show\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should cmp 1 }
  end
end

