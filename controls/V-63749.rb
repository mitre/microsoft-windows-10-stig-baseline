# -*- encoding : utf-8 -*-

control 'V-63749' do
  title 'Anonymous enumeration of shares must be restricted.'
  desc  "Allowing anonymous logon users (null session connections) to list all
        account names and enumerate all shared resources can provide a map of potential
        points to attack the system."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-SO-000150'
  tag gid: 'V-63749'
  tag rid: 'SV-78239r1_rule'
  tag stig_id: 'WN10-SO-000150'
  tag fix_id: 'F-69677r1_fix'
  tag cci: ['CCI-001090']
  tag nist: %w[SC-4 Rev_4]
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

      Value Name: RestrictAnonymous

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network access: Do not allow anonymous enumeration of SAM accounts and
      shares\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should cmp 1 }
  end
end

