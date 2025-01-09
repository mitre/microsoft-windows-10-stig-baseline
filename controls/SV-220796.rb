control 'SV-220796' do
  title 'The system must be configured to prevent IP source routing.'
  desc 'Configuring the system to disable IP source routing protects against spoofing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22511r554873_chk'
  tag severity: 'medium'
  tag gid: 'V-220796'
  tag rid: 'SV-220796r991589_rule'
  tag stig_id: 'WN10-CC-000025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22500r554874_fix'
  tag 'documentable'
  tag legacy: ['SV-78049', 'V-63559']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end
