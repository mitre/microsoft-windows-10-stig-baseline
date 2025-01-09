control 'SV-220970' do
  title 'The Deny log on as a service user right on Windows 10 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a service" right defines accounts that are denied log on as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'check', 'This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the "Deny log on as a service" right , this is a finding.

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group'
  desc 'fix', 'This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on as a service" to include the following:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22685r857201_chk'
  tag severity: 'medium'
  tag gid: 'V-220970'
  tag rid: 'SV-220970r958472_rule'
  tag stig_id: 'WN10-UR-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-22674r857202_fix'
  tag 'documentable'
  tag legacy: ['V-63875', 'SV-78365']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

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
