# -*- encoding : utf-8 -*-

control 'V-63383' do
  title 'Simple TCP/IP Services must not be installed on the system.'
  desc  "Some protocols and services do not support required security features,
        such as encrypting passwords or traffic."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000110'
  tag gid: 'V-63383'
  tag rid: 'SV-77873r1_rule'
  tag stig_id: 'WN10-00-000110'
  tag fix_id: 'F-69305r1_fix'
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

  desc "check", "\"Simple TCP/IP Services\" is not installed by default.  Verify
        it has not been installed.

        Run \"Services.msc\".

        If \"Simple TCP/IP Services\" is listed, this is a finding."

  desc "fix", "Uninstall \"Simple TCPIP Services (i.e. echo, daytime etc)\" from
        the system.

        Run \"Programs and Features\".
        Select \"Turn Windows Features on or off\".
        De-select \"Simple TCPIP Services (i.e. echo, daytime etc)\"."

  describe windows_feature('Simple TCP/IP Services') do
    it { should_not be_installed }
  end
end

