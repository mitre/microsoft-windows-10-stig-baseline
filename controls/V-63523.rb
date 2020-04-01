# -*- encoding : utf-8 -*-

control 'V-63523' do
  title "The Security event log size must be configured to 1024000 KB or
        greater."
  desc  "Inadequate log size will cause the log to fill up quickly.  This may
        prevent audit events from being recorded properly and require frequent
        attention by administrative personnel."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AU-000505'
  tag gid: 'V-63523'
  tag rid: 'SV-78013r2_rule'
  tag stig_id: 'WN10-AU-000505'
  tag fix_id: 'F-86735r1_fix'
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

  desc 'check', "If the system is configured to send audit records directly to an
      audit server, this is NA. This must be documented with the ISSO.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

      Value Name: MaxSize

      Value Type: REG_DWORD
      Value: 0x000fa000 (1024000) (or greater)"

  desc 'fix', "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Event Log Service >> Security
      >> \"Specify the maximum log file size (KB)\" to \"Enabled\" with a \"Maximum
      Log Size (KB)\" of \"1024000\" or greater.

      If the system is configured to send audit records directly to an audit server,
      documented with the ISSO."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should be >= 1_024_000 }
  end
end

