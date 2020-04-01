# -*- encoding : utf-8 -*-

control 'V-63635' do
  title 'Audit policy using subcategories must be enabled.'
  desc  "Maintaining an audit trail of system activity logs can help identify
        configuration errors, troubleshoot service disruptions, and analyze compromises
        that have occurred, as well as detect attacks.  Audit logs are necessary to
        provide a trail of evidence in case the system or network is compromised.
        Collecting this data is essential for analyzing the security of information
        assets and detecting signs of suspicious and unexpected behavior.  This setting
        allows administrators to enable more precise auditing capabilities."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000030'
  tag gid: 'V-63635'
  tag rid: 'SV-78125r1_rule'
  tag stig_id: 'WN10-SO-000030'
  tag fix_id: 'F-69563r1_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a', 'Rev_4']
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

      Value Name: SCENoApplyLegacyAuditPolicy

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"Audit:
      Force audit policy subcategory settings (Windows Vista or later) to override
      audit policy category settings\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'SCENoApplyLegacyAuditPolicy' }
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end

