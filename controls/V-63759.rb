# -*- encoding : utf-8 -*-

control 'V-63759' do
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc  "Allowing anonymous access to named pipes or shares provides the
        potential for unauthorized system access.  This setting restricts access to
        those defined in \"Network access: Named Pipes that can be accessed
        anonymously\" and \"Network access: Shares that can be accessed anonymously\",
        both of which must be blank under other requirements."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-SO-000165'
  tag gid: 'V-63759'
  tag rid: 'SV-78249r1_rule'
  tag stig_id: 'WN10-SO-000165'
  tag fix_id: 'F-69687r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

      Value Name: RestrictNullSessAccess

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network access: Restrict anonymous access to Named Pipes and Shares\" to
      \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should have_property 'RestrictNullSessAccess' }
    its('RestrictNullSessAccess') { should cmp 1 }
  end
end

