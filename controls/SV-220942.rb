control 'SV-220942' do
  title 'The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
  desc 'This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

Value Name: Enabled

Value Type: REG_DWORD
Value: 1
 
Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms.  Both the browser and web server must be configured to use TLS otherwise the browser will not be able to connect to a secure site.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22657r555311_chk'
  tag severity: 'medium'
  tag gid: 'V-220942'
  tag rid: 'SV-220942r959006_rule'
  tag stig_id: 'WN10-SO-000230'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-22646r555312_fix'
  tag 'documentable'
  tag legacy: ['V-63811', 'SV-78301']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp 1 }
  end
end
