control 'SV-220798' do
  title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
  desc "Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the servers WINS resolution capability."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22513r554879_chk'
  tag severity: 'low'
  tag gid: 'V-220798'
  tag rid: 'SV-220798r958902_rule'
  tag stig_id: 'WN10-CC-000035'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-22502r554880_fix'
  tag 'documentable'
  tag legacy: ['V-63567', 'SV-78057']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters') do
    it { should have_property 'NoNameReleaseOnDemand' }
    its('NoNameReleaseOnDemand') { should cmp 1 }
  end
end
