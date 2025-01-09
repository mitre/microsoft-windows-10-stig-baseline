control 'SV-220781' do
  title 'The System event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System\\

Value Name:  MaxSize

Value Type:  REG_DWORD
Value:  0x00008000 (32768) (or greater)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22496r554828_chk'
  tag severity: 'medium'
  tag gid: 'V-220781'
  tag rid: 'SV-220781r958752_rule'
  tag stig_id: 'WN10-AU-000510'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-22485r554829_fix'
  tag 'documentable'
  tag legacy: ['SV-78017', 'V-63527']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32_768 }
  end
end
