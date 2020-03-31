# -*- encoding : utf-8 -*-

control 'V-63389' do
  title 'The TFTP Client must not be installed on the system.'
  desc  "Some protocols and services do not support required security features,
        such as encrypting passwords or traffic."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000120'
  tag gid: 'V-63389'
  tag rid: 'SV-77879r1_rule'
  tag stig_id: 'WN10-00-000120'
  tag fix_id: 'F-69313r1_fix'
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

  desc "check", "The \"TFTP Client\" is not installed by default.  Verify it has
        not been installed.

        Navigate to the Windows\\System32 directory.

        If the \"TFTP\" application exists, this is a finding."

  desc "fix", "Uninstall \"TFTP Client\" from the system.

        Run \"Programs and Features\".
        Select \"Turn Windows Features on or off\".

        De-select \"TFTP Client\"."

  describe windows_feature('TFTP Client') do
    it { should_not be_installed }
  end
end

