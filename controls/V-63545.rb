# -*- encoding : utf-8 -*-

control 'V-63545' do
  title 'Camera access from the lock screen must be disabled.'
  desc  "Enabling camera access from the lock screen could allow for
        unauthorized use.  Requiring logon will ensure the device is only used by
        authorized personnel."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000005'
  tag gid: 'V-63545'
  tag rid: 'SV-78035r1_rule'
  tag stig_id: 'WN10-CC-000005'
  tag fix_id: 'F-69475r1_fix'
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
  desc 'check', "If the device does not have a camera, this is NA.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

      Value Name: NoLockScreenCamera

      Value Type: REG_DWORD
      Value: 1"

  desc 'fix', "If the device does not have a camera, this is NA.

      Configure the policy value for Computer Configuration >> Administrative
      Templates >> Control Panel >> Personalization >> \"Prevent enabling lock screen
      camera\" to \"Enabled\"."

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63545.' do
      skip 'This is a VDI System; This System is NA for Control V-63545.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
      it { should have_property 'NoLockScreenCamera' }
      its('NoLockScreenCamera') { should cmp 1 }
    end
  end
end

