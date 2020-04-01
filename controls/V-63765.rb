# -*- encoding : utf-8 -*-

control 'V-63765' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc  "NTLM sessions that are allowed to fall back to Null (unauthenticated)
        sessions may gain unauthorized access."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000180'
  tag gid: 'V-63765'
  tag rid: 'SV-78255r1_rule'
  tag stig_id: 'WN10-SO-000180'
  tag fix_id: 'F-69693r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

      Value Name: allownullsessionfallback

      Value Type: REG_DWORD
      Value: 0"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: Allow LocalSystem NULL session fallback\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0') do
    it { should have_property 'allownullsessionfallback' }
    its('allownullsessionfallback') { should cmp 0 }
  end
end

