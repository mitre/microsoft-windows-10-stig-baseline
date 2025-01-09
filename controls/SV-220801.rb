control 'SV-220801' do
  title 'Run as different user must be removed from context menus.'
  desc 'The "Run as different user" selection from context menus allows the use of credentials other than the currently logged on user.  Using privileged credentials in a standard user session can expose those credentials to theft.  Removing this option from context menus helps prevent this from occurring.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding.
The policy configures the same Value Name, Type and Value under four different registry paths.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Paths:  
\\SOFTWARE\\Classes\\batfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\exefile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser\\

Value Name:  SuppressionPolicy

Type:  REG_DWORD
Value:  0x00001000 (4096)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Remove "Run as Different User" from context menus" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package.  "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22516r554888_chk'
  tag severity: 'medium'
  tag gid: 'V-220801'
  tag rid: 'SV-220801r958478_rule'
  tag stig_id: 'WN10-CC-000039'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22505r554889_fix'
  tag 'documentable'
  tag legacy: ['SV-86953', 'V-72329']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser') do
      it { should have_property 'SuppressionPolicy' }
      its('SuppressionPolicy') { should cmp 4096 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser') do
      it { should have_property 'SuppressionPolicy' }
      its('SuppressionPolicy') { should cmp 4096 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser') do
      it { should have_property 'SuppressionPolicy' }
      its('SuppressionPolicy') { should cmp 4096 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser') do
      it { should have_property 'SuppressionPolicy' }
      its('SuppressionPolicy') { should cmp 4096 }
    end
  end
end
