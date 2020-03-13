control "V-63495" do
  title "The system must be configured to audit System - IPSec Driver
successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks.  Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    IPSec Driver records events related to the IPSec Driver such as dropped
packets.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AU-000125"
  tag gid: "V-63495"
  tag rid: "SV-77985r1_rule"
  tag stig_id: "WN10-AU-000125"
  tag fix_id: "F-69425r1_fix"
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: false
  tag mitigations: nil
  tag severity_override_guidance: false
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  tag check: "Security Option \"Audit: Force audit policy subcategory settings
(Windows Vista or later) to override audit policy category settings\" must be
set to \"Enabled\" (WN10-SO-000030) for the detailed auditing subcategories to
be effective.

Use the AuditPol tool to review the current Audit Policy configuration:
Open a Command Prompt with elevated privileges (\"Run as Administrator\").
Enter \"AuditPol /get /category:*\".

Compare the AuditPol settings with the following.  If the system does not audit
the following, this is a finding:\"

System >> IPSec Driver - Success"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
Audit Policies >> System >> \"Audit IPSec Driver\" with \"Success\" selected."

   describe.one do
    describe audit_policy do
      its('IPsec Driver') { should eq 'Success' }
    end
    describe audit_policy do
      its('IPsec Driver') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'IPsec Driver'") do
      its('stdout') { should match /IPsec Driver                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'IPsec Driver'") do
      its('stdout') { should match /IPsec Driver                    Success and Failure/ }
    end
  end  
end

