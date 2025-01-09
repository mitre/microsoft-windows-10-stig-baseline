control 'SV-220762' do
  title 'Windows 10 must be configured to audit Object Access - File Share successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Auditing file shares records events related to connection to shares on a system including system shares such as C$.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following:

Object Access >> File Share - Success

If the system does not audit the above, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit File Share" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22477r554771_chk'
  tag severity: 'medium'
  tag gid: 'V-220762'
  tag rid: 'SV-220762r991583_rule'
  tag stig_id: 'WN10-AU-000082'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-22466r554772_fix'
  tag 'documentable'
  tag legacy: ['V-74721', 'SV-89395']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('File Share') { should eq 'Success' }
    end
    describe audit_policy do
      its('File Share') { should eq 'Success and Failure' }
    end
  end
end
