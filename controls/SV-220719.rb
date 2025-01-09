control 'SV-220719' do
  title 'Simple Network Management Protocol (SNMP) must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', '"SNMP" is not installed by default.  Verify it has not been installed.

Navigate to the Windows\\System32 directory.

If the "SNMP" application exists, this is a finding.'
  desc 'fix', 'Uninstall "Simple Network Management Protocol (SNMP)" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".
De-select "Simple Network Management Protocol (SNMP)".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22434r554642_chk'
  tag severity: 'medium'
  tag gid: 'V-220719'
  tag rid: 'SV-220719r958480_rule'
  tag stig_id: 'WN10-00-000105'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-22423r554643_fix'
  tag 'documentable'
  tag legacy: ['V-63381', 'SV-77871']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe windows_feature('SNMP') do
    it { should_not be_installed }
  end
end
