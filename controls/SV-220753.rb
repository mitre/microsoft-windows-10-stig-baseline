control 'SV-220753' do
  title 'The system must be configured to audit Detailed Tracking - PNP Activity successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Plug and Play activity records events related to the successful connection of external devices.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges ("Run as Administrator").
Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding:

Detailed Tracking >> Plug and Play Events - Success'
  desc 'fix', 'Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking >> "Audit PNP Activity" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22468r997908_chk'
  tag severity: 'medium'
  tag gid: 'V-220753'
  tag rid: 'SV-220753r1016410_rule'
  tag stig_id: 'WN10-AU-000045'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-22457r554745_fix'
  tag 'documentable'
  tag legacy: ['SV-77941', 'V-63451']
  tag cci: ['CCI-000172', 'CCI-003938', 'CCI-001814', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1) (b)', 'CM-5 (1)', 'CM-5 (1)']

  describe.one do
    describe audit_policy do
      its('Plug and Play Events') { should eq 'Success' }
    end
    describe audit_policy do
      its('Plug and Play Events') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Plug and Play Events'") do
      its('stdout') { should match /Plug and Play Events                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Plug and Play Events'") do
      its('stdout') { should match /Plug and Play Events                    Success and Failure/ }
    end
  end
end
