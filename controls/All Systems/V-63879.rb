control "V-63879" do
  title "The Deny log on through Remote Desktop Services user right on Windows
10 workstations must at a minimum be configured to prevent access from highly
privileged domain accounts and local accounts on domain systems and
unauthenticated access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on through Remote Desktop Services\" right defines the
accounts that are prevented from logging on using Remote Desktop Services.

    If Remote Desktop Services is not used by the organization, the Everyone
group must be assigned this right to prevent all access.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower trust systems helps mitigate the risk of
privilege escalation from credential theft attacks, which could lead to the
compromise of an entire domain.

    Local accounts on domain-joined systems must also be assigned this right to
decrease the risk of lateral movement resulting from credential theft attacks.

    The Guests group must be assigned this right to prevent unauthenticated
access.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-UR-000090"
  tag gid: "V-63879"
  tag rid: "SV-78369r4_rule"
  tag stig_id: "WN10-UR-000090"
  tag fix_id: "F-88445r1_fix"
  tag cci: ["CCI-000213", "CCI-002314"]
  tag nist: ["AC-3", "AC-17 (1)", "Rev_4"]
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
  tag check: "Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the \"Deny log on
through Remote Desktop Services\" right, this is a finding:

If Remote Desktop Services is not used by the organization, the \"Everyone\"
group can replace all of the groups listed below.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Privileged Access Workstations (PAWs) dedicated to the management of Active
Directory are exempt from denying the Enterprise Admins and Domain Admins
groups. (See the Windows Privileged Access Workstation STIG for PAW
requirements.)

Note: \"Local account\" is a built-in security group used to assign user rights
and permissions to all local accounts."
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Deny log on through Remote Desktop Services\" to include the following.

If Remote Desktop Services is not used by the organization, assign the Everyone
group this right to prevent all access.

Domain Systems Only:
Enterprise Admins group
Domain Admins group
Local account (see Note below)

All Systems:
Guests group

Privileged Access Workstations (PAWs) dedicated to the management of Active
Directory are exempt from denying the Enterprise Admins and Domain Admins
groups. (See the Windows Privileged Access Workstation STIG for PAW
requirements.)

Note: \"Local account\" is a built-in security group used to assign user rights
and permissions to all local accounts."
is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    describe.one do
      describe security_policy do
        its('SeDenyRemoteInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
      end
      describe security_policy do
        its('SeDenyRemoteInteractiveLogonRight') { should eq [] }
      end
    end

  else
    get_domain_sid = command('wmic useraccount get sid | FINDSTR /V SID | Select -First 2').stdout.strip
    domain_sid = get_domain_sid[9..40]
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end
  end
end

