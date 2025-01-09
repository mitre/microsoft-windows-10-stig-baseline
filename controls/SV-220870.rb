control 'SV-220870' do
  title 'The convenience PIN for Windows 10 must be disabled.'
  desc 'This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password Stuffer).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System

Value Name: AllowDomainPINLogon
Value Type: REG_DWORD
Value data: 0'
  desc 'fix', 'Disable the convenience PIN sign-in. 

If this needs to be corrected configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> Set "Turn on convenience PIN sign-in" to "Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22585r555095_chk'
  tag severity: 'medium'
  tag gid: 'V-220870'
  tag rid: 'SV-220870r958478_rule'
  tag stig_id: 'WN10-CC-000370'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22574r555096_fix'
  tag 'documentable'
  tag legacy: ['V-99559', 'SV-108663']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

   describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
      it { should have_property 'AllowDomainPINLogon' }
      its('AllowDomainPINLogon') { should cmp 0 }
   end
end
