control 'SV-220871' do
  title 'Windows Ink Workspace must be configured to disallow access above the lock.'
  desc 'This action secures Windows Ink, which contains applications and features oriented toward pen computing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\WindowsInkWorkspace

Value Name: AllowWindowsInkWorkspace
Value Type: REG_DWORD
Value data: 1'
  desc 'fix', 'Disable the convenience PIN sign-in. 

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Ink Workspace >> Set "Allow Windows Ink Workspace" to "Enabled” and set Options "On, but disallow access above lock".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22586r642139_chk'
  tag severity: 'medium'
  tag gid: 'V-220871'
  tag rid: 'SV-220871r958478_rule'
  tag stig_id: 'WN10-CC-000385'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22575r642140_fix'
  tag 'documentable'
  tag legacy: ['SV-108665', 'V-99561']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

   describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp 1 }
   end
end
