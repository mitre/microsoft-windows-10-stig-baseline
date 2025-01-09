control 'SV-220858' do
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Web-based programs may attempt to install malicious software on a system.  Ensuring users are notified if a web-based program attempts to install software allows them to refuse the installation.'
  desc 'check', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22573r555059_chk'
  tag severity: 'medium'
  tag gid: 'V-220858'
  tag rid: 'SV-220858r991589_rule'
  tag stig_id: 'WN10-CC-000320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22562r555060_fix'
  tag 'documentable'
  tag legacy: ['V-63329', 'SV-77819']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
        it { should_not have_property 'SafeForScripting' }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
        its('SafeForScripting') { should_not cmp 1 }
      end
    end
end
