control 'SV-220721' do
  title 'The Telnet Client must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'The "Telnet Client" is not installed by default.  Verify it has not been installed.

Navigate to the Windows\\System32 directory.

If the "telnet" application exists, this is a finding.'
  desc 'fix', 'Uninstall "Telnet Client" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".

De-select "Telnet Client".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22436r554648_chk'
  tag severity: 'medium'
  tag gid: 'V-220721'
  tag rid: 'SV-220721r958480_rule'
  tag stig_id: 'WN10-00-000115'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-22425r554649_fix'
  tag 'documentable'
  tag legacy: ['SV-77875', 'V-63385']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe windows_feature('Telnet Client') do
    it { should_not be_installed }
  end
end
