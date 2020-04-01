# -*- encoding : utf-8 -*-

control 'V-68819' do
  title 'PowerShell script block logging must be enabled on Windows 10.'
  desc  "Maintaining an audit trail of system activity logs can help identify
        configuration errors, troubleshoot service disruptions, and analyze compromises
        that have occurred, as well as detect attacks. Audit logs are necessary to
        provide a trail of evidence in case the system or network is compromised.
        Collecting this data is essential for analyzing the security of information
        assets and detecting signs of suspicious and unexpected behavior.

        Enabling PowerShell script block logging will record detailed information
        from the processing of PowerShell commands and scripts.  This can provide
        additional detail when malware has run on a system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000326'
  tag gid: 'V-68819'
  tag rid: 'SV-83411r2_rule'
  tag stig_id: 'WN10-CC-000326'
  tag fix_id: 'F-74989r1_fix'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)', 'Rev_4']
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

      Value Name: EnableScriptBlockLogging

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Windows PowerShell >> \"Turn
      on PowerShell Script Block Logging\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should cmp 1 }
  end
end

