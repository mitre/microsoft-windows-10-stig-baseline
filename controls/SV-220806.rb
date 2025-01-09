control 'SV-220806' do
  title 'Simultaneous connections to the internet or a Windows domain must be limited.'
  desc 'Multiple network connections can provide additional attack vectors to a system and must be limited. The "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems from automatically establishing multiple connections. When both wired and wireless connections are available, for example, the less-preferred connection (typically wireless) will be disconnected.'
  desc 'check', 'The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "3", this is not a finding.

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

Value Name: fMinimizeConnections

Value Type: REG_DWORD
Value: 3 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain" is "Enabled".

If this must be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows Connection Manager >> "Minimize the number of simultaneous connections to the Internet or a Windows Domain" to "Enabled". 

Under "Options", set "Minimize Policy Options" to "3 = Prevent Wi-Fi When on Ethernet".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22521r857186_chk'
  tag severity: 'medium'
  tag gid: 'V-220806'
  tag rid: 'SV-220806r991589_rule'
  tag stig_id: 'WN10-CC-000055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22510r857187_fix'
  tag 'documentable'
  tag legacy: ['SV-78071', 'V-63581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
        it { should_not have_property 'fMinimizeConnections' }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
        its('fMinimizeConnections') { should cmp 1 }
      end
    end
  end
end
