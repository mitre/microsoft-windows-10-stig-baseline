control 'SV-220787' do
  title 'Windows 10 must be configured to audit other Logon/Logoff Events Successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other Logon/Logoff Events determines whether Windows generates audit events for other logon or logoff events. Logon events are essential to understanding user activity and detecting potential attacks.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Logon/Logoff  >> Other Logon/Logoff Events - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Other Logon/Logoff Events" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22502r554846_chk'
  tag severity: 'medium'
  tag gid: 'V-220787'
  tag rid: 'SV-220787r958412_rule'
  tag stig_id: 'WN10-AU-000560'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-22491r554847_fix'
  tag 'documentable'
  tag legacy: ['V-99543', 'SV-108647']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  describe.one do
    describe audit_policy do
      its('Other Logon/Logoff Events') { should eq 'Success' }
    end
    describe audit_policy do
      its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
    end
  end
end
