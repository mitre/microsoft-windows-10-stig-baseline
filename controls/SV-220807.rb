control 'SV-220807' do
  title 'Connections to non-domain networks when connected to a domain authenticated network must be blocked.'
  desc 'Multiple network connections can provide additional attack vectors to a system and should be limited.  When connected to a domain, communication must go through the domain connection.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fBlockNonDomain

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Prohibit connection to non-domain networks when connected to domain authenticated network" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22522r554906_chk'
  tag severity: 'medium'
  tag gid: 'V-220807'
  tag rid: 'SV-220807r991589_rule'
  tag stig_id: 'WN10-CC-000060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22511r554907_fix'
  tag 'documentable'
  tag legacy: ['V-63585', 'SV-78075']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should cmp 1 }
  end
end
