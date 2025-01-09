control 'SV-220803' do
  title 'Internet connection sharing must be disabled.'
  desc 'Internet connection sharing makes it possible for an existing internet connection, such as through wireless, to be shared and used by other systems essentially creating a mobile hotspot.  This exposes the system sharing the connection to others with potentially malicious purpose.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_ShowSharedAccessUI

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network Connections >> "Prohibit use of Internet Connection Sharing on your DNS domain network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22518r554894_chk'
  tag severity: 'medium'
  tag gid: 'V-220803'
  tag rid: 'SV-220803r958478_rule'
  tag stig_id: 'WN10-CC-000044'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22507r554895_fix'
  tag 'documentable'
  tag legacy: ['SV-86389', 'V-71765']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should cmp 0 }
  end
end
