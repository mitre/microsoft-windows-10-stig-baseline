control "V-63451" do
  title "The system must be configured to audit Detailed Tracking - PNP
Activity successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Plug and Play activity records events related to the successful connection
of external devices.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AU-000045"
  tag gid: "V-63451"
  tag rid: "SV-77941r1_rule"
  tag stig_id: "WN10-AU-000045"
  tag fix_id: "F-69379r1_fix"
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
Enter \"AuditPol /get /category:*\"

Compare the AuditPol settings with the following.  If the system does not audit
the following, this is a finding:

Detailed Tracking >> Plug and Play Events - Success"
  tag fix: "Computer Configuration >> Windows Settings >> Advanced Audit Policy
Configuration >> System Audit Policies >> Detailed Tracking >> \"Audit PNP
Activity\" with \"Success\" selected."
end

