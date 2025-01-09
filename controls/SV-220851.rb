control 'SV-220851' do
  title 'The Remote Desktop Session Host must require secure RPC communications.'
  desc 'Allowing unsecure RPC communication exposes the system to man in the middle attacks and data disclosure attacks. A man in the middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fEncryptRPCTraffic

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security "Require secure RPC communication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22566r555038_chk'
  tag severity: 'medium'
  tag gid: 'V-220851'
  tag rid: 'SV-220851r991554_rule'
  tag stig_id: 'WN10-CC-000285'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-22555r555039_fix'
  tag 'documentable'
  tag legacy: ['V-63737', 'SV-78227']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should cmp 1 }
  end
end
