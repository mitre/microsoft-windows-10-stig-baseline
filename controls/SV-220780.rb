control 'SV-220780' do
  title 'The Security event log size must be configured to 1024000 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

Value Name: MaxSize

Value Type: REG_DWORD
Value: 0x000fa000 (1024000) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "1024000" or greater.

If the system is configured to send audit records directly to an audit server, documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22495r554825_chk'
  tag severity: 'medium'
  tag gid: 'V-220780'
  tag rid: 'SV-220780r958752_rule'
  tag stig_id: 'WN10-AU-000505'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-22484r554826_fix'
  tag 'documentable'
  tag legacy: ['V-63523', 'SV-78013']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 1_024_000 }
  end
end
