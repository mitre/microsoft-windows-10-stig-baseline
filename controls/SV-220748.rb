control 'SV-220748' do
  title 'The system must be configured to audit Account Logon - Credential Validation failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Credential validation records events related to validation tests on credentials for a user account logon.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Account Logon >> Credential Validation - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Logon >> "Audit Credential Validation" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22463r554729_chk'
  tag severity: 'medium'
  tag gid: 'V-220748'
  tag rid: 'SV-220748r991578_rule'
  tag stig_id: 'WN10-AU-000005'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-22452r554730_fix'
  tag 'documentable'
  tag legacy: ['SV-77921', 'V-63431']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Credential Validation') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Credential Validation') { should eq 'Success and Failure' }
    end
  end
end
