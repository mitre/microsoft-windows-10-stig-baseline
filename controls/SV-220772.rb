control 'SV-220772' do
  title 'The system must be configured to audit System - IPSec Driver failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

IPSec Driver records events related to the IPSec Driver such as dropped packets.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding:

System >> IPSec Driver - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit IPSec Driver" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22487r554801_chk'
  tag severity: 'medium'
  tag gid: 'V-220772'
  tag rid: 'SV-220772r991586_rule'
  tag stig_id: 'WN10-AU-000120'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-22476r554802_fix'
  tag 'documentable'
  tag legacy: ['V-63491', 'SV-77981']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('IPsec Driver') { should eq 'Failure' }
    end
    describe audit_policy do
      its('IPsec Driver') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'IPsec Driver'") do
      its('stdout') { should match /IPsec Driver                    Failure/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'IPsec Driver'") do
      its('stdout') { should match /IPsec Driver                    Success and Failure/ }
    end
  end
end
