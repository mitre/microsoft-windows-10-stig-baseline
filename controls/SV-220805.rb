control 'SV-220805' do
  title 'Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. By default Windows uses ECC curves with shorter key lengths first.  Requiring ECC curves with longer key lengths to be prioritized first helps ensure more secure algorithms are used.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\\

Value Name: EccCurves

Value Type: REG_MULTI_SZ
Value: NistP384 NistP256'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> SSL Configuration Settings >> "ECC Curve Order" to "Enabled" with "ECC Curve Order:" including the following in the order listed:

NistP384
NistP256'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22520r554900_chk'
  tag severity: 'medium'
  tag gid: 'V-220805'
  tag rid: 'SV-220805r971535_rule'
  tag stig_id: 'WN10-CC-000052'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-22509r554901_fix'
  tag 'documentable'
  tag legacy: ['V-74413', 'SV-89087']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') do
    it { should have_property 'EccCurves' }
   end
  
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') do
      its('EccCurves') { should include 'NistP384' }
      its('EccCurves') { should include 'NistP256' }
    end
end
