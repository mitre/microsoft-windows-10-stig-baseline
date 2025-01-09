control 'SV-220800' do
  title 'WDigest Authentication must be disabled.'
  desc 'When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft.  WDigest is disabled by default in Windows 10.  This setting ensures this is enforced.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

Value Name: UseLogonCredential

Type: REG_DWORD
Value:  0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "WDigest Authentication (disabling may require KB2871997)" to "Disabled".

The patch referenced in the policy title is not required for Windows 10.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package.  "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22515r554885_chk'
  tag severity: 'medium'
  tag gid: 'V-220800'
  tag rid: 'SV-220800r958478_rule'
  tag stig_id: 'WN10-CC-000038'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22504r554886_fix'
  tag 'documentable'
  tag legacy: ['V-71763', 'SV-86387']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest') do
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should cmp 0 }
  end
end
