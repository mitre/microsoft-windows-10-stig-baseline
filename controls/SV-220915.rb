control 'SV-220915' do
  title 'Outgoing secure channel traffic must be encrypted when possible.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: SealSecureChannel

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain member: Digitally encrypt secure channel data (when possible)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22630r555230_chk'
  tag severity: 'medium'
  tag gid: 'V-220915'
  tag rid: 'SV-220915r958908_rule'
  tag stig_id: 'WN10-SO-000040'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-22619r555231_fix'
  tag 'documentable'
  tag legacy: ['SV-78133', 'V-63643']
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should have_property 'SealSecureChannel' }
    its('SealSecureChannel') { should cmp 1 }
  end
end
