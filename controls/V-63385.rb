# -*- encoding : utf-8 -*-

control 'V-63385' do
  title 'The Telnet Client must not be installed on the system.'
  desc  "Some protocols and services do not support required security features,
        such as encrypting passwords or traffic."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000115'
  tag gid: 'V-63385'
  tag rid: 'SV-77875r1_rule'
  tag stig_id: 'WN10-00-000115'
  tag fix_id: 'F-69307r1_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b', 'Rev_4']
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

  desc "check", "The \"Telnet Client\" is not installed by default.  Verify it has
        not been installed.

        Navigate to the Windows\\System32 directory.

        If the \"telnet\" application exists, this is a finding."

  desc "fix", "Uninstall \"Telnet Client\" from the system.

        Run \"Programs and Features\".
        Select \"Turn Windows Features on or off\".

        De-select \"Telnet Client\"."

  describe windows_feature('Telnet Client') do
    it { should_not be_installed }
  end
end

