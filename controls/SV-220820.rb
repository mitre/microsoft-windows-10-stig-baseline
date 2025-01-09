control 'SV-220820' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
  desc 'check', 'This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

Value Name: EnumerateLocalUsers

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Enumerate local users on domain-joined computers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22535r857192_chk'
  tag severity: 'medium'
  tag gid: 'V-220820'
  tag rid: 'SV-220820r958478_rule'
  tag stig_id: 'WN10-CC-000130'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22524r857193_fix'
  tag 'documentable'
  tag legacy: ['SV-78123', 'V-63633']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain != 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should have_property 'EnumerateLocalUsers' }
      its('EnumerateLocalUsers') { should cmp 0 }
    end
  end
end
