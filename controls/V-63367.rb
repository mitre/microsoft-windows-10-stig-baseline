control "V-63367" do
  title "Standard local user accounts must not exist on a system in a domain."
  desc  "To minimize potential points of attack, local user accounts, other
than built-in accounts and local administrator accounts, must not exist on a
workstation in a domain.  Users must log onto workstations in a domain with
their domain accounts."
  impact 0.3
  tag severity: nil
  tag gtitle: "WN10-00-000085"
  tag gid: "V-63367"
  tag rid: "SV-77857r2_rule"
  tag stig_id: "WN10-00-000085"
  tag fix_id: "F-69287r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]
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
  tag check: "Run \"Computer Management\".
Navigate to System Tools >> Local Users and Groups >> Users.

If local users other than the accounts listed below exist on a workstation in a
domain, this is a finding.

Built-in Administrator account (Disabled)
Built-in Guest account (Disabled)
Built-in DefaultAccount (Disabled)
Built-in defaultuser0 (Disabled)
Built-in WDAGUtilityAccount (Disabled)
Local administrator account(s)

All of the built-in accounts may not exist on a system, depending on the
Windows 10 version."
  tag fix: "Limit local user accounts on domain-joined systems.  Remove any
unauthorized local accounts."
end

