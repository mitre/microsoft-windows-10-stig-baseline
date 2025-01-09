control 'SV-220823' do
  title 'Solicited Remote Assistance must not be allowed.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Solicited assistance is help that is specifically requested by the local user.  This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fAllowToGetHelp
 
Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Assistance >> "Configure Solicited Remote Assistance" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22538r554954_chk'
  tag severity: 'high'
  tag gid: 'V-220823'
  tag rid: 'SV-220823r958524_rule'
  tag stig_id: 'WN10-CC-000155'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-22527r554955_fix'
  tag 'documentable'
  tag legacy: ['SV-78141', 'V-63651']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should cmp 0 }
  end
end
