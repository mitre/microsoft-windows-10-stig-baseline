control 'SV-220865' do
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled".

Severity Override Guidance: The AO can allow the severity override if they have reviewed the overall protection. This would only be allowed temporarily for implementation as documented and approved. 
….
Allowing Basic authentication to be used for the sole creation of Office 365 DoD tenants.
….
A documented mechanism and or script that can disable Basic authentication once administration completes. 
….
Use of a Privileged Access Workstation (PAW) and adherence to the Clean Source principle for administration.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22580r555080_chk'
  tag severity: 'high'
  tag gid: 'V-220865'
  tag rid: 'SV-220865r958510_rule'
  tag stig_id: 'WN10-CC-000345'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-22569r654973_fix'
  tag 'documentable'
  tag legacy: ['SV-77837', 'V-63347']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp 0 }
  end
end
