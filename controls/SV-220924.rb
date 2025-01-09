control 'SV-220924' do
  title 'The Smart Card removal option must be configured to Force Logoff or Lock Workstation.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  SCRemoveOption

Value Type:  REG_SZ
Value:  1 (Lock Workstation) or 2 (Force Logoff)

This can be left not configured or set to "No action" on workstations with the following conditions.  This must be documented with the ISSO.
-The setting cannot be configured due to mission needs, or because it interferes with applications.
-Policy must be in place that users manually lock workstations when leaving them unattended.
-The screen saver is properly configured to lock as required.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or "Force Logoff".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22639r555257_chk'
  tag severity: 'medium'
  tag gid: 'V-220924'
  tag rid: 'SV-220924r991589_rule'
  tag stig_id: 'WN10-SO-000095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22628r555258_fix'
  tag 'documentable'
  tag legacy: ['V-63697', 'SV-78187']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
      it { should have_property 'SCRemoveOption' }
      its('SCRemoveOption') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
      it { should have_property 'SCRemoveOption' }
      its('SCRemoveOption') { should cmp 2 }
    end
  end
end
