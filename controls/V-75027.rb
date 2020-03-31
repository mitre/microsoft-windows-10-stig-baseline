# -*- encoding : utf-8 -*-

control 'V-75027' do
  title 'Windows 10 must be configured to audit Object Access - File Share failures.'
  desc  "Maintaining an audit trail of system activity logs can help identify
        configuration errors, troubleshoot service disruptions, and analyze compromises
        that have occurred, as well as detect attacks. Audit logs are necessary to
        provide a trail of evidence in case the system or network is compromised.
        Collecting this data is essential for analyzing the security of information
        assets and detecting signs of suspicious and unexpected behavior.

        Auditing file shares records events related to connection to shares on a
        system including system shares such as C$."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AU-000081'
  tag gid: 'V-75027'
  tag rid: 'SV-89701r1_rule'
  tag stig_id: 'WN10-AU-000081'
  tag fix_id: 'F-81643r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c', 'Rev_4']
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
  desc "check", "Security Option \"Audit: Force audit policy subcategory settings
      (Windows Vista or later) to override audit policy category settings\" must be
      set to \"Enabled\" (WN10-SO-000030) for the detailed auditing subcategories to
      be effective.

      Use the AuditPol tool to review the current Audit Policy configuration:

      Open PowerShell or a Command Prompt with elevated privileges (\"Run as
      Administrator\").

      Enter \"AuditPol /get /category:*\"

      Compare the AuditPol settings with the following:

      Object Access >> File Share - Failure

      If the system does not audit the above, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
      Audit Policies >> Object Access >> \"Audit File Share\" with \"Failure\"
      selected."

  describe.one do
    describe audit_policy do
      its('File Share') { should eq 'Failure' }
    end
    describe audit_policy do
      its('File Share') { should eq 'Success and Failure' }
    end
  end
end

