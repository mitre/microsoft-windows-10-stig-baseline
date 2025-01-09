control 'SV-220754' do
  title 'The system must be configured to audit Detailed Tracking - Process Creation successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Process creation records events related to the creation of a process and the source.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Detailed Tracking >> Process Creation - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking >> "Audit Process Creation" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22469r997910_chk'
  tag severity: 'medium'
  tag gid: 'V-220754'
  tag rid: 'SV-220754r1016411_rule'
  tag stig_id: 'WN10-AU-000050'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-22458r554748_fix'
  tag 'documentable'
  tag legacy: ['V-63453', 'SV-77943']
  tag cci: ['CCI-000172', 'CCI-003938', 'CCI-001814', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1) (b)', 'CM-5 (1)', 'CM-5 (1)']

  describe.one do
    describe audit_policy do
      its('Process Creation') { should eq 'Success' }
    end
    describe audit_policy do
      its('Process Creation') { should eq 'Success and Failure' }
    end
  end
end
