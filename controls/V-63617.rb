# -*- encoding : utf-8 -*-

control 'V-63617' do
  title "Local accounts with blank passwords must be restricted to prevent
        access from the network."
  desc  "An account without a password can allow unauthorized access to a
        system as only the username would be required.  Password policies should
        prevent accounts with blank passwords from existing on a system.  However, if a
        local account with a blank password did exist, enabling this setting will
        prevent network access, limiting the account to local console logon only."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000015'
  tag gid: 'V-63617'
  tag rid: 'SV-78107r1_rule'
  tag stig_id: 'WN10-SO-000015'
  tag fix_id: 'F-69547r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

      Value Name: LimitBlankPasswordUse

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Accounts: Limit local account use of blank passwords to console logon only\"
      to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'LimitBlankPasswordUse' }
    its('LimitBlankPasswordUse') { should cmp 1 }
  end
end

