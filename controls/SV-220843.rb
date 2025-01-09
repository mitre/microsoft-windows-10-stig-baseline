control 'SV-220843' do
  title 'The password manager function in the Edge browser must be disabled.'
  desc 'Passwords save locally for re-use when browsing may be subject to compromise.  Disabling the Edge password manager will prevent this for the browser.'
  desc 'check', 'Windows 10 LTSC\\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\\

Value Name: FormSuggest Passwords

Type: REG_SZ
Value: no'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Edge >> "Configure Password Manager" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22558r555014_chk'
  tag severity: 'medium'
  tag gid: 'V-220843'
  tag rid: 'SV-220843r991589_rule'
  tag stig_id: 'WN10-CC-000245'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22547r555015_fix'
  tag 'documentable'
  tag legacy: ['V-63709', 'SV-78199']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main') do
    it { should have_property 'FormSuggest Passwords' }
    its('FormSuggest Passwords') { should cmp 'no' }
  end
end
