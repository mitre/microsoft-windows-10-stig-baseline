# encoding: UTF-8

control "V-99551" do
  title "Windows 10 must be configured to audit Other Policy Change Events
Successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Audit Other Policy Change Events contains events about EFS Data Recovery
Agent policy changes, changes in Windows Filtering Platform filter, status on
Security policy settings updates for local Group Policy settings, Central
Access Policy changes, and detailed troubleshooting events for Cryptographic
Next Generation (CNG) operations."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AU-000550"
  tag gid: "V-99551"
  tag rid: "SV-108655r1_rule"
  tag stig_id: "WN10-AU-000550"
  tag fix_id: "F-105235r1_fix"
  tag cci: ["CCI-000130"]
  tag nist: ["AU-3", "Rev_4"]
  desc  "rationale", ""
  desc  "check", "Security Option \"Audit: Force audit policy subcategory settings (Windows
Vista or later) to override audit policy category settings\" must be set to
\"Enabled\" (WN10-SO-000030) for the detailed auditing subcategories to be
effective.

    Use the AuditPol tool to review the current Audit Policy configuration:
    Open a Command Prompt with elevated privileges (\"Run as Administrator\").
    Enter \"AuditPol /get /category:*\".

    Compare the AuditPol settings with the following. If the system does not
audit the following, this is a finding:

    Policy Change  >> Other Policy Change Events - Success"
  desc  "fix", "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Policy Change>> \"Audit Other Policy Change Events\"
with \"Success\" selected."
 
  describe.one do
    describe audit_policy do
      its('Other Policy Change Events') { should eq 'Success' }
    end
    describe audit_policy do
      its('Other Policy Change Events') { should eq 'Success and Failure' }
    end
  end
end

