control 'SV-220766' do
  title 'The system must be configured to audit Object Access - Removable Storage successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing object access for removable media records events related to access attempts on file system objects on removable storage devices.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Object Access >> Removable Storage - Success

Some virtual machines may generate excessive audit events for access to the virtual hard disk itself when this setting is enabled. This may be set to Not Configured in such cases and would not be a finding.  This must be documented with the ISSO to include mitigations such as monitoring or restricting any actual removable storage connected to the VM.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Removable Storage" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22481r554783_chk'
  tag severity: 'medium'
  tag gid: 'V-220766'
  tag rid: 'SV-220766r991583_rule'
  tag stig_id: 'WN10-AU-000090'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-22470r554784_fix'
  tag 'documentable'
  tag legacy: ['V-63473', 'SV-77963']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Removable Storage') { should eq 'Success' }
    end
    describe audit_policy do
      its('Removable Storage') { should eq 'Success and Failure' }
    end
  end
end
