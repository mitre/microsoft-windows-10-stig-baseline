control 'SV-220847' do
  title 'Windows 10 must be configured to require a minimum pin length of six characters or greater.'
  desc 'Windows allows the use of PINs as well as biometrics for authentication without sending a password to a network or website where it could be compromised.  Longer minimum PIN lengths increase the available combinations an attacker would have to attempt.  Shorter minimum length significantly reduces the strength.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity\\

Value Name:  MinimumPINLength

Type:  REG_DWORD
Value:  6 (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> PIN Complexity >> "Minimum PIN length" to "6" or greater. 

v1607 LTSB:
The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Windows Hello for Business >> Pin Complexity.

v1507 LTSB:
The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Passport for Work >> Pin Complexity.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22562r555026_chk'
  tag severity: 'medium'
  tag gid: 'V-220847'
  tag rid: 'SV-220847r991589_rule'
  tag stig_id: 'WN10-CC-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22551r555027_fix'
  tag 'documentable'
  tag legacy: ['SV-78211', 'V-63721']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity') do
    it { should have_property 'MinimumPINLength' }
    its('MinimumPINLength') { should be >= 6 }
  end
end
