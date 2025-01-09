control 'SV-220775' do
  title 'The system must be configured to audit System - Security State Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security State Change records events related to changes in the security state, such as startup and shutdown of the system.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding:

System >> Security State Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit Security State Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22490r554810_chk'
  tag severity: 'medium'
  tag gid: 'V-220775'
  tag rid: 'SV-220775r958732_rule'
  tag stig_id: 'WN10-AU-000140'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-22479r554811_fix'
  tag 'documentable'
  tag legacy: ['V-63507', 'SV-77997']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']

   describe.one do
    describe audit_policy do
      its('Security State Change') { should eq 'Success' }
    end
    describe audit_policy do
      its('Security State Change') { should eq 'Success and Failure' }
    end
  end  
end
