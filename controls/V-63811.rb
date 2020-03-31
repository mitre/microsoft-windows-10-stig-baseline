# -*- encoding : utf-8 -*-

control 'V-63811' do
  title "The system must be configured to use FIPS-compliant algorithms for
        encryption, hashing, and signing."
  desc  "This setting ensures that the system uses algorithms that are
        FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms
        meet specific standards established by the U.S. Government and must be the
        algorithms used for all OS encryption functions."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000230'
  tag gid: 'V-63811'
  tag rid: 'SV-78301r1_rule'
  tag stig_id: 'WN10-SO-000230'
  tag fix_id: 'F-69739r1_fix'
  tag cci: ['CCI-002450']
  tag nist: %w[SC-13 Rev_4]
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
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

      Value Name: Enabled

      Value Type: REG_DWORD
      Value: 1

      Warning: Clients with this setting enabled will not be able to communicate via
      digitally encrypted or signed protocols with servers that do not support these
      algorithms.  Both the browser and web server must be configured to use TLS
      otherwise the browser will not be able to connect to a secure site."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"System
      cryptography: Use FIPS compliant algorithms for encryption, hashing, and
      signing\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp 1 }
  end
end

