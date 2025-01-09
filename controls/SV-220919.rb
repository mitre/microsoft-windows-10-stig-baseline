control 'SV-220919' do
  title 'The system must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
Warning: This setting may prevent a system from being joined to a domain if not configured consistently between systems.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22634r555242_chk'
  tag severity: 'medium'
  tag gid: 'V-220919'
  tag rid: 'SV-220919r958908_rule'
  tag stig_id: 'WN10-SO-000060'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-22623r555243_fix'
  tag 'documentable'
  tag legacy: ['V-63665', 'SV-78155']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should have_property 'RequireStrongKey' }
    its('RequireStrongKey') { should cmp 1 }
  end
end
