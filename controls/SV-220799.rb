control 'SV-220799' do
  title 'Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.'
  desc 'A compromised local administrator account can provide means for an attacker to move laterally between domain systems.

With User Account Control enabled, filtering the privileged token for built-in administrator accounts will prevent the elevated privileges of these accounts from being used over the network.'
  desc 'check', 'If the system is not a member of a domain, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: LocalAccountTokenFilterPolicy

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Apply UAC restrictions to local accounts on network logons" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package.  "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22514r554882_chk'
  tag severity: 'medium'
  tag gid: 'V-220799'
  tag rid: 'SV-220799r958518_rule'
  tag stig_id: 'WN10-CC-000037'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22503r554883_fix'
  tag 'documentable'
  tag legacy: ['V-63597', 'SV-78087']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      it { should have_property 'LocalAccountTokenFilterPolicy' }
      its('LocalAccountTokenFilterPolicy') { should cmp 0 }
    end
  end
end
