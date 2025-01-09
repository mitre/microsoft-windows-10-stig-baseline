control 'SV-220712' do
  title 'Only accounts responsible for the administration of a system must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights.  Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group (see V-36434 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the local administrators group.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Administrators group.
Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.'
  desc 'fix', 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22427r554621_chk'
  tag severity: 'high'
  tag gid: 'V-220712'
  tag rid: 'SV-220712r958726_rule'
  tag stig_id: 'WN10-00-000070'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22416r554622_fix'
  tag 'documentable'
  tag legacy: ['SV-77851', 'V-63361']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

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
