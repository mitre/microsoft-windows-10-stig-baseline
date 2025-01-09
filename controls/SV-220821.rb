control 'SV-220821' do
  title 'Users must be prompted for a password on resume from sleep (on battery).'
  desc 'Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: DCSettingIndex

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> "Require a password when a computer wakes (on battery)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22536r554948_chk'
  tag severity: 'medium'
  tag gid: 'V-220821'
  tag rid: 'SV-220821r1016412_rule'
  tag stig_id: 'WN10-CC-000145'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-22525r554949_fix'
  tag 'documentable'
  tag legacy: ['SV-78135', 'V-63645']
  tag cci: ['CCI-004895', 'CCI-002038', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11', 'IA-11']

    if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63645.' do
      skip 'This is a VDI System; This System is NA for Control V-63645.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
     it { should have_property 'DCSettingIndex' }
     its('DCSettingIndex') { should cmp 1 }
   end
 end
end
