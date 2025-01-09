control 'SV-220852' do
  title 'Remote Desktop Services must be configured with the client connection encryption set to the required level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Value Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Set client connection encryption level" to "Enabled" and "High Level".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22567r555041_chk'
  tag severity: 'medium'
  tag gid: 'V-220852'
  tag rid: 'SV-220852r958408_rule'
  tag stig_id: 'WN10-CC-000290'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-22556r555042_fix'
  tag 'documentable'
  tag legacy: ['V-63741', 'SV-78231']
  tag cci: ['CCI-000068', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'MA-4 (6)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should cmp 3 }
  end
end
