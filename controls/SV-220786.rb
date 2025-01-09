control 'SV-220786' do
  title 'Windows 10 must be configured to audit Other Policy Change Events Failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in Windows Filtering Platform filter, status on Security policy settings updates for local Group Policy settings, Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG) operations.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Policy Change  >> Other Policy Change Events - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Policy Change>> "Audit Other Policy Change Events" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22501r554843_chk'
  tag severity: 'medium'
  tag gid: 'V-220786'
  tag rid: 'SV-220786r958412_rule'
  tag stig_id: 'WN10-AU-000555'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-22490r554844_fix'
  tag 'documentable'
  tag legacy: ['V-99553', 'SV-108657']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  describe.one do
    describe audit_policy do
      its('Other Policy Change Events') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Other Policy Change Events') { should eq 'Success and Failure' }
    end
  end
end
