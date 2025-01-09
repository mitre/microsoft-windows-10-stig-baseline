control 'SV-220816' do
  title 'Web publishing and online ordering wizards must be prevented from downloading a list of providers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting prevents Windows from downloading a list of providers for the Web publishing and online ordering wizards.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoWebServices

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off Internet download for Web publishing and online ordering wizards" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22531r554933_chk'
  tag severity: 'medium'
  tag gid: 'V-220816'
  tag rid: 'SV-220816r958478_rule'
  tag stig_id: 'WN10-CC-000105'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22520r554934_fix'
  tag 'documentable'
  tag legacy: ['V-63621', 'SV-78111']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should cmp 1 }
  end
end
