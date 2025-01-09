control 'SV-220769' do
  title 'The system must be configured to audit Policy Change - Authorization Policy Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Authorization Policy Change records events related to changes in user rights, such as Create a token object.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.

Policy Change >> Authorization Policy Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Authorization Policy Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22484r554792_chk'
  tag severity: 'medium'
  tag gid: 'V-220769'
  tag rid: 'SV-220769r991579_rule'
  tag stig_id: 'WN10-AU-000107'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-22473r554793_fix'
  tag 'documentable'
  tag legacy: ['SV-86385', 'V-71761']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Authorization Policy Change') { should eq 'Success' }
    end
    describe audit_policy do
      its('Authorization Policy Change') { should eq 'Success and Failure' }
    end
  end
end