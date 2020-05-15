# -*- encoding : utf-8 -*-

control 'V-63875' do
  title "The Deny log on as a service user right on Windows 10 domain-joined
        workstations must be configured to prevent access from highly privileged domain
        accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Deny log on as a service\" right defines accounts that are denied log
        on as a service.

        In an Active Directory Domain, denying logons to the Enterprise Admins and
        Domain Admins groups on lower trust systems helps mitigate the risk of
        privilege escalation from credential theft attacks which could lead to the
        compromise of an entire domain.

        Incorrect configurations could prevent services from starting and result in
        a DoS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000080'
  tag gid: 'V-63875'
  tag rid: 'SV-78365r2_rule'
  tag stig_id: 'WN10-UR-000080'
  tag fix_id: 'F-100993r1_fix'
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
  desc 'check', "This requirement is applicable to domain-joined systems, for
      standalone systems this is NA.

      Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".

      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
      >> Security Settings >> Local Policies >> User Rights Assignment.

      If the following groups or accounts are not defined for the \"Deny log on as a
      service\" right , this is a finding:

      Domain Systems Only:
      Enterprise Admins Group
      Domain Admins Group"
  desc 'fix', "This requirement is applicable to domain-joined systems, for
      standalone systems this is NA.

      Configure the policy value for Computer Configuration >> Windows Settings >>
      Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log on
      as a service\" to include the following.

      Domain Systems Only:
      Enterprise Admins Group
      Domain Admins Group"

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'This requirement is applicable to domain-joined systems, for standalone systems this is NA' do
      skip 'This requirement is applicable to domain-joined systems, for standalone systems this is NA'
    end
  else
    domain_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Domain Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

      domain_admin_sid = json(command: domain_query).params
      enterprise_admin_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Enterprise Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

      enterprise_admin_sid = json(command: enterprise_admin_query).params

    describe security_policy do
      its('SeDenyServiceLogonRight') { should be_in ["#{domain_admin_sid}", "#{enterprise_admin_sid}"] }
    end
  end
end

