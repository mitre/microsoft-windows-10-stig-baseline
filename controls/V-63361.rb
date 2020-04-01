# -*- encoding : utf-8 -*-

control 'V-63361' do
  title "Only accounts responsible for the administration of a system must have
        Administrator rights on the system."
  desc  "An account that does not have Administrator duties must not have
        Administrator rights.  Such rights would allow the account to bypass or modify
        required security restrictions on that machine and make it vulnerable to attack.

        System administrators must log on to systems only using accounts with the
        minimum level of authority necessary.

        For domain-joined workstations, the Domain Admins group must be replaced by
        a domain workstation administrator group (see V-36434 in the Active Directory
        Domain STIG).  Restricting highly privileged accounts from the local
        Administrators group helps mitigate the risk of privilege escalation resulting
        from credential theft attacks.

        Standard user accounts must not be members of the local administrators
        group."

  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-00-000070'
  tag gid: 'V-63361'
  tag rid: 'SV-77851r2_rule'
  tag stig_id: 'WN10-00-000070'
  tag fix_id: 'F-88437r1_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)', 'Rev_4']
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

  desc "check", "Run \"Computer Management\".
        Navigate to System Tools >> Local Users and Groups >> Groups.
        Review the members of the Administrators group.
        Only the appropriate administrator groups or accounts responsible for
        administration of the system may be members of the group.

        For domain-joined workstations, the Domain Admins group must be replaced by a
        domain workstation administrator group.

        Standard user accounts must not be members of the local administrator group.

        If prohibited accounts are members of the local administrators group, this is a
        finding.

        The built-in Administrator account or other required administrative accounts
        would not be a finding."

  desc "fix", "Configure the system to include only administrator groups or
        accounts that are responsible for the system in the local Administrators group.

        For domain-joined workstations, the Domain Admins group must be replaced by a
        domain workstation administrator group.

        Remove any standard user accounts."

  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split("\r\n")
  administrator_group.each do |user|
    describe user.to_s do
      it { should be_in input('administrators') }
    end
  end
  if administrator_group.empty?
    impact 0.0
    describe 'There are no users with administrative privileges' do
      skip 'This control is not applicable'
    end
  end
end

