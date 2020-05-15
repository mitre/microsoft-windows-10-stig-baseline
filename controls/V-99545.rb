# encoding: UTF-8

control "V-99545" do
  title "Windows 10 must be configured to audit Detailed File Share Failures."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Audit Detailed File Share allows you to audit attempts to access files and
folders on a shared folder.
    The Detailed File Share setting logs an event every time a file or folder
is accessed, whereas the File Share setting only records one event for any
connection established between a client and file share. Detailed File Share
audit events include detailed information about the permissions or other
criteria used to grant or deny access."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AU-000570"
  tag gid: "V-99545"
  tag rid: "SV-108649r1_rule"
  tag stig_id: "WN10-AU-000570"
  tag fix_id: "F-105229r1_fix"
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

    Object Access  >> Detailed File Share - Failure"
  desc  "fix", "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Object Access >> “Detailed File Share\" with
\"Failure\" selected."
 
  describe.one do
    describe audit_policy do
      its('Detailed File Share') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Detailed File Share') { should eq 'Success and Failure' }
    end
  end
end