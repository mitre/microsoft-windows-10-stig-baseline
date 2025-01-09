control 'SV-220954' do
  title 'Toast notifications to the lock screen must be turned off.'
  desc 'Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\

Value Name: NoToastApplicationNotificationOnLockScreen

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration >> Administrative Templates >> Start Menu and Taskbar >> Notifications >> "Turn off toast notifications on the lock screen" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22669r555347_chk'
  tag severity: 'low'
  tag gid: 'V-220954'
  tag rid: 'SV-220954r958478_rule'
  tag stig_id: 'WN10-UC-000015'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22658r555348_fix'
  tag 'documentable'
  tag legacy: ['V-63839', 'SV-78329']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    it { should have_property 'NoToastApplicationNotificationOnLockScreen' }
    its('NoToastApplicationNotificationOnLockScreen') { should cmp 1 }
  end
end
