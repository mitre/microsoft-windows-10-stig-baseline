control 'SV-220932' do
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc 'Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access.  This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously",  both of which must be blank under other requirements.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22647r555281_chk'
  tag severity: 'high'
  tag gid: 'V-220932'
  tag rid: 'SV-220932r958524_rule'
  tag stig_id: 'WN10-SO-000165'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-22636r555282_fix'
  tag 'documentable'
  tag legacy: ['SV-78249', 'V-63759']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should have_property 'RestrictNullSessAccess' }
    its('RestrictNullSessAccess') { should cmp 1 }
  end
end
