# -*- encoding : utf-8 -*-

control 'V-63471' do
  title "The system must be configured to audit Object Access - Removable
        Storage failures."
  desc  "Maintaining an audit trail of system activity logs can help identify
        configuration errors, troubleshoot service disruptions, and analyze compromises
        that have occurred, as well as detect attacks.  Audit logs are necessary to
        provide a trail of evidence in case the system or network is compromised.
        Collecting this data is essential for analyzing the security of information
        assets and detecting signs of suspicious and unexpected behavior.

        Auditing object access for removable media records events related to access
        attempts on file system objects on removable storage devices."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AU-000085'
  tag gid: 'V-63471'
  tag rid: 'SV-77961r2_rule'
  tag stig_id: 'WN10-AU-000085'
  tag fix_id: 'F-69401r1_fix'
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
      Open a Command Prompt with elevated privileges (\"Run as Administrator\").
      Enter \"AuditPol /get /category:*\"

      Compare the AuditPol settings with the following. If the system does not audit
      the following, this is a finding:

      Object Access >> Removable Storage - Failure

      Some virtual machines may generate excessive audit events for access to the
      virtual hard disk itself when this setting is enabled. This may be set to Not
      Configured in such cases and would not be a finding.  This must be documented
      with the ISSO to include mitigations such as monitoring or restricting any
      actual removable storage connected to the VM."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
      Audit Policies >> Object Access >> \"Audit Removable Storage\" with \"Failure\"
      selected."

  describe.one do
    describe audit_policy do
      its('Removable Storage') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Removable Storage') { should eq 'Success and Failure' }
    end
  end
end

