control 'SV-220756' do
  title 'The system must be configured to audit Logon/Logoff - Group Membership successes.'
  desc "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Group Membership records information related to the group membership of a user's logon token."
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding:

Logon/Logoff >> Group Membership - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Group Membership" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22471r554753_chk'
  tag severity: 'medium'
  tag gid: 'V-220756'
  tag rid: 'SV-220756r991578_rule'
  tag stig_id: 'WN10-AU-000060'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-22460r554754_fix'
  tag 'documentable'
  tag legacy: ['SV-77947', 'V-63457']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe.one do
    describe audit_policy do
      its('Group Membership') { should eq 'Success' }
    end
    describe audit_policy do
      its('Group Membership') { should eq 'Success and Failure' }
    end
  end
end
