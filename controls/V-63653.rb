# -*- encoding : utf-8 -*-

control 'V-63653' do
  title 'The computer account password must not be prevented from being reset.'
  desc  "Computer account passwords are changed automatically on a regular
        basis.  Disabling automatic password changes can make the system more
        vulnerable to malicious access.  Frequent password changes can be a significant
        safeguard for your system.  A new password for the computer account will be
        generated every 30 days."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-SO-000050'
  tag gid: 'V-63653'
  tag rid: 'SV-78143r1_rule'
  tag stig_id: 'WN10-SO-000050'
  tag fix_id: 'F-69885r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

      Value Name: DisablePasswordChange

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain
      member: Disable machine account password changes\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should have_property 'DisablePasswordChange' }
    its('DisablePasswordChange') { should cmp 0 }
  end
end

