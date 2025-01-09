control 'SV-220854' do
  title 'Basic authentication for RSS feeds over HTTP must not be used.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: AllowBasicAuthInClear

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Turn on Basic feed authentication over HTTP" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22569r555047_chk'
  tag severity: 'medium'
  tag gid: 'V-220854'
  tag rid: 'SV-220854r958478_rule'
  tag stig_id: 'WN10-CC-000300'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22558r555048_fix'
  tag 'documentable'
  tag legacy: ['SV-78237', 'V-63747']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
      it { should have_property 'AllowBasicAuthInClear' }
      its('AllowBasicAuthInClear') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
      it { should_not have_property 'AllowBasicAuthInClear' }
    end
  end
end
