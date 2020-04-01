# -*- encoding : utf-8 -*-

control 'V-72329' do
  title 'Run as different user must be removed from context menus.'
  desc  "The \"Run as different user\" selection from context menus allows the
        use of credentials other than the currently logged on user.  Using privileged
        credentials in a standard user session can expose those credentials to theft.
        Removing this option from context menus helps prevent this from occurring."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000039'
  tag gid: 'V-72329'
  tag rid: 'SV-86953r1_rule'
  tag stig_id: 'WN10-CC-000039'
  tag fix_id: 'F-78683r2_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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
  desc "check", "If the following registry values do not exist or are not
      configured as specified, this is a finding.
      The policy configures the same Value Name, Type and Value under four different
      registry paths.

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Paths:
      \\SOFTWARE\\Classes\\batfile\\shell\
      unasuser\\
      \\SOFTWARE\\Classes\\cmdfile\\shell\
      unasuser\\
      \\SOFTWARE\\Classes\\exefile\\shell\
      unasuser\\
      \\SOFTWARE\\Classes\\mscfile\\shell\
      unasuser\\

      Value Name:  SuppressionPolicy

      Type:  REG_DWORD
      Value:  0x00001000 (4096)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MS Security Guide >> \"Remove \"Run as Different
      User\" from context menus\" to \"Enabled\".

      This policy setting requires the installation of the SecGuide custom templates
      included with the STIG package.  \"SecGuide.admx\" and \"SecGuide.adml\" must
      be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

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

