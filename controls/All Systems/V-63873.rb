control "V-63873" do
  title "The Deny log on as a batch job user right on domain-joined
workstations must be configured to prevent access from highly privileged domain
accounts."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high level capabilities.

    The \"Deny log on as a batch job\" right defines accounts that are
prevented from logging on to the system as a batch job, such as Task Scheduler.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower trust systems helps mitigate the risk of
privilege escalation from credential theft attacks which could lead to the
compromise of an entire domain.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-UR-000075"
  tag gid: "V-63873"
  tag rid: "SV-78363r1_rule"
  tag stig_id: "WN10-UR-000075"
  tag fix_id: "F-69801r1_fix"
  tag cci: ["CCI-000213"]
  tag nist: ["AC-3", "Rev_4"]
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
  tag check: "This requirement is applicable to domain-joined systems, for
standalone systems this is NA.

Verify the effective setting in Local Group Policy Editor.
Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the \"Deny log on as a
batch job\" right, this is a finding:

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group"
  tag fix: "This requirement is applicable to domain-joined systems, for
standalone systems this is NA.

Configure the policy value for Computer Configuration >> Windows Settings >>
Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log on
as a batch job\" to include the following.

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group"
get_domain_sid = command('wmic useraccount get sid | FINDSTR /V SID | Select -First 2').stdout.strip
domain_sid = get_domain_sid[9..40]
  describe.one do
    describe security_policy do
      its('SeDenyBatchLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end
    describe security_policy do
      its('SeDenyBatchLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end
    describe security_policy do
      its('SeDenyBatchLogonRight') { should eq [] }
    end
  end
end

