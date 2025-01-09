control 'SV-220822' do
  title 'The user must be prompted for a password on resume from sleep (plugged in).'
  desc 'Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (plugged in).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: ACSettingIndex

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> "Require a password when a computer wakes (plugged in)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22537r554951_chk'
  tag severity: 'medium'
  tag gid: 'V-220822'
  tag rid: 'SV-220822r1016413_rule'
  tag stig_id: 'WN10-CC-000150'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-22526r554952_fix'
  tag 'documentable'
  tag legacy: ['SV-78139', 'V-63649']
  tag cci: ['CCI-004895', 'CCI-002038', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11', 'IA-11']

   if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63649.' do
      skip 'This is a VDI System; This System is NA for Control V-63649.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
     it { should have_property 'ACSettingIndex' }
     its('ACSettingIndex') { should cmp 1 }
    end
  end
end
