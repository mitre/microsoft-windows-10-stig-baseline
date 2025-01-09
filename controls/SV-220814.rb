control 'SV-220814' do
  title 'Group Policy objects must be reprocessed even if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

Value Name: NoGPOListChanges

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >> "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22529r554927_chk'
  tag severity: 'medium'
  tag gid: 'V-220814'
  tag rid: 'SV-220814r991589_rule'
  tag stig_id: 'WN10-CC-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22518r554928_fix'
  tag 'documentable'
  tag legacy: ['SV-78099', 'V-63609']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp 0 }
  end
end
