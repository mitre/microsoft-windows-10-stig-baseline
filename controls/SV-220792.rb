control 'SV-220792' do
  title 'Camera access from the lock screen must be disabled.'
  desc 'Enabling camera access from the lock screen could allow for unauthorized use.  Requiring logon will ensure the device is only used by authorized personnel.'
  desc 'check', 'If the device does not have a camera, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenCamera

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'If the device does not have a camera, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen camera" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22507r554861_chk'
  tag severity: 'medium'
  tag gid: 'V-220792'
  tag rid: 'SV-220792r958478_rule'
  tag stig_id: 'WN10-CC-000005'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22496r554862_fix'
  tag 'documentable'
  tag legacy: ['SV-78035', 'V-63545']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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
