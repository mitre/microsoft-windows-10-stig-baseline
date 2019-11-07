control "V-63541" do
  title "Windows 10 permissions for the System event log must prevent access by
non-privileged accounts."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks.  Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.  The
System event log may be  susceptible to tampering if proper permissions are not
applied."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AU-000525"
  tag gid: "V-63541"
  tag rid: "SV-78031r2_rule"
  tag stig_id: "WN10-AU-000525"
  tag fix_id: "F-69471r1_fix"
  tag cci: ["CCI-000162", "CCI-000163", "CCI-000164"]
  tag nist: ["AU-9", "AU-9", "AU-9", "Rev_4"]
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
  tag check: "Verify the permissions on the System event log (System.evtx).
Standard user accounts or groups must not have access. The default permissions
listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.
They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed,
this is a finding.

NOTE: If \"APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES\" has
Special Permissions, this would not be a finding."
  tag fix: "Ensure the permissions on the System event log (System.evtx) are
configured to prevent standard user accounts or groups from having access. The
default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the \"%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS\" directory.

If the location of the logs has been changed, when adding Eventlog to the
permissions, it must be entered as \"NT Service\\Eventlog\"."
end

