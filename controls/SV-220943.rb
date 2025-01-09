control 'SV-220943' do
  title 'The default permissions of global system objects must be increased.'
  desc 'Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default DACL that specifies who can access the objects with what permissions. If this policy is enabled, the default DACL is stronger, allowing non-admin users to read shared objects, but not modify shared objects that they did not create.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\

Value Name: ProtectionMode

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic links)" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22658r555314_chk'
  tag severity: 'low'
  tag gid: 'V-220943'
  tag rid: 'SV-220943r991589_rule'
  tag stig_id: 'WN10-SO-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22647r555315_fix'
  tag 'documentable'
  tag legacy: ['SV-78305', 'V-63815']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager') do
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should cmp 1 }
  end
end
