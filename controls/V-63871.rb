# -*- encoding : utf-8 -*-

control 'V-63871' do
  title "The Deny access to this computer from the network user right on
        workstations must be configured to prevent access from highly privileged domain
        accounts and local accounts on domain systems and unauthenticated access on all
        systems."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high-level capabilities.

        The \"Deny access to this computer from the network\" right defines the
        accounts that are prevented from logging on from the network.

        In an Active Directory Domain, denying logons to the Enterprise Admins and
        Domain Admins groups on lower trust systems helps mitigate the risk of
        privilege escalation from credential theft attacks, which could lead to the
        compromise of an entire domain.

        Local accounts on domain-joined systems must also be assigned this right to
        decrease the risk of lateral movement resulting from credential theft attacks.

        The Guests group must be assigned this right to prevent unauthenticated
        access."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000070'
  tag gid: 'V-63871'
  tag rid: 'SV-78361r3_rule'
  tag stig_id: 'WN10-UR-000070'
  tag fix_id: 'F-88441r1_fix'
  tag cci: ['CCI-000213']
  tag nist: %w[AC-3 Rev_4]
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

  desc 'check', "Verify the effective setting in Local Group Policy Editor.

        Run \"gpedit.msc\".

        Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
        >> Security Settings >> Local Policies >> User Rights Assignment.

        If the following groups or accounts are not defined for the \"Deny access to
        this computer from the network\" right, this is a finding:

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

  desc 'fix', "Configure the policy value for Computer Configuration >> Windows
        Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
        \"Deny access to this computer from the network\" to include the following.

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
    describe security_policy do
      its('SeDenyNetworkLogonRight') { should include 'S-1-5-32-546' }
    end
  else
    domain_sid = input('domain_sid')
    describe security_policy do
      its('SeDenyNetworkLogonRight') { should be_in ["S-1-5-21-#{domain_sid}-519", "S-1-5-21-#{domain_sid}-512", 'S-1-5-32-546'] }
    end
  end
end

