# -*- encoding : utf-8 -*-

control 'V-63839' do
  title 'Toast notifications to the lock screen must be turned off.'
  desc  "Toast notifications that are displayed on the lock screen could
        display sensitive information to unauthorized personnel.  Turning off this
        feature will limit access to the information to a logged on user."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-UC-000015'
  tag gid: 'V-63839'
  tag rid: 'SV-78329r1_rule'
  tag stig_id: 'WN10-UC-000015'
  tag fix_id: 'F-69767r1_fix'
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
      configured as specified, this is a finding:

      Registry Hive: HKEY_CURRENT_USER
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

      Value Name: NoToastApplicationNotificationOnLockScreen

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for User Configuration >> Administrative
      Templates >> Start Menu and Taskbar >> Notifications >> \"Turn off toast
      notifications on the lock screen\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    it { should have_property 'NoToastApplicationNotificationOnLockScreen' }
    its('NoToastApplicationNotificationOnLockScreen') { should cmp 1 }
  end
end

