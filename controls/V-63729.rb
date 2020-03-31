# -*- encoding : utf-8 -*-

control 'V-63729' do
  title 'Passwords must not be saved in the Remote Desktop Client.'
  desc  "Saving passwords in the Remote Desktop Client could allow an
        unauthorized user to establish a remote desktop session to another system.  The
        system must be configured to prevent users from saving passwords in the Remote
        Desktop Client."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000270'
  tag gid: 'V-63729'
  tag rid: 'SV-78219r1_rule'
  tag stig_id: 'WN10-CC-000270'
  tag fix_id: 'F-69657r1_fix'
  tag cci: ['CCI-002038']
  tag nist: %w[IA-11 Rev_4]
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

      Value Name: DisablePasswordSaving

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Remote Desktop Services >>
      Remote Desktop Connection Client >> \"Do not allow passwords to be saved\" to
      \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should cmp 1 }
  end
end

