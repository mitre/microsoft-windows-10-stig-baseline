control 'SV-220720' do
  title 'Simple TCP/IP Services must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', '"Simple TCP/IP Services" is not installed by default.  Verify it has not been installed.

Run "Services.msc".

If "Simple TCP/IP Services" is listed, this is a finding.'
  desc 'fix', 'Uninstall "Simple TCPIP Services (i.e. echo, daytime etc)" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".
De-select "Simple TCPIP Services (i.e. echo, daytime etc)".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22435r554645_chk'
  tag severity: 'medium'
  tag gid: 'V-220720'
  tag rid: 'SV-220720r958478_rule'
  tag stig_id: 'WN10-00-000110'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22424r554646_fix'
  tag 'documentable'
  tag legacy: ['V-63383', 'SV-77873']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe windows_feature('Simple TCP/IP Services') do
    it { should_not be_installed }
  end
end
