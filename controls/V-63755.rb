# -*- encoding : utf-8 -*-

control 'V-63755' do
  title "The system must be configured to prevent anonymous users from having
        the same rights as the Everyone group."
  desc  "Access by anonymous users must be restricted.  If this setting is
        enabled, then anonymous users have the same rights and permissions as the
        built-in Everyone group.  Anonymous users must not have these permissions or
        rights."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000160'
  tag gid: 'V-63755'
  tag rid: 'SV-78245r1_rule'
  tag stig_id: 'WN10-SO-000160'
  tag fix_id: 'F-69683r1_fix'
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

      Value Name: EveryoneIncludesAnonymous

      Value Type: REG_DWORD
      Value: 0"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network access: Let Everyone permissions apply to anonymous users\" to
      \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'EveryoneIncludesAnonymous' }
    its('EveryoneIncludesAnonymous') { should cmp 0 }
  end
end

