# -*- encoding : utf-8 -*-

control 'V-63527' do
  title 'The System event log size must be configured to 32768 KB or greater.'
  desc  "Inadequate log size will cause the log to fill up quickly.  This may
        prevent audit events from being recorded properly and require frequent
        attention by administrative personnel."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AU-000510'
  tag gid: 'V-63527'
  tag rid: 'SV-78017r1_rule'
  tag stig_id: 'WN10-AU-000510'
  tag fix_id: 'F-69457r1_fix'
  tag cci: ['CCI-001849']
  tag nist: %w[AU-4 Rev_4]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: false
  tag mitigations: nil
  tag severity_override_guidance: false
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil

  desc "check", "If the system is configured to send audit records directly to an
      audit server, this is NA.  This must be documented with the ISSO.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System\\

      Value Name:  MaxSize

      Value Type:  REG_DWORD
      Value:  0x00008000 (32768) (or greater)"

  desc "fix", "If the system is configured to send audit records directly to an
      audit server, this is NA.  This must be documented with the ISSO.

      Configure the policy value for Computer Configuration >> Administrative
      Templates >> Windows Components >> Event Log Service >> System >> \"Specify the
      maximum log file size (KB)\" to \"Enabled\" with a \"Maximum Log Size (KB)\" of
      \"32768\" or greater."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 32_768 }
  end
end

