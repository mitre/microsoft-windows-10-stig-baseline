control 'SV-220722' do
  title 'The TFTP Client must not be installed on the system.'
  desc 'Some protocols and services do not support required security features, such as encrypting passwords or traffic.'
  desc 'check', 'The "TFTP Client" is not installed by default.  Verify it has not been installed.

Navigate to the Windows\\System32 directory.

If the "TFTP" application exists, this is a finding.'
  desc 'fix', 'Uninstall "TFTP Client" from the system.

Run "Programs and Features".
Select "Turn Windows Features on or off".

De-select "TFTP Client".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22437r554651_chk'
  tag severity: 'medium'
  tag gid: 'V-220722'
  tag rid: 'SV-220722r958480_rule'
  tag stig_id: 'WN10-00-000120'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-22426r554652_fix'
  tag 'documentable'
  tag legacy: ['V-63389', 'SV-77879']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe windows_feature('TFTP Client') do
    it { should_not be_installed }
  end
end
