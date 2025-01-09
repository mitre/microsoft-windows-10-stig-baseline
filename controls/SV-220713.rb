control 'SV-220713' do
  title 'Only accounts responsible for the backup operations must be members of the Backup Operators group.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Backup Operators group.

If the group contains no accounts, this is not a finding.

If the group contains any accounts, the accounts must be specifically for backup functions.

If the group contains any standard user accounts used for performing normal user tasks, this is a finding.'
  desc 'fix', 'Create separate accounts for backup operations for users with this privilege.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22428r554624_chk'
  tag severity: 'medium'
  tag gid: 'V-220713'
  tag rid: 'SV-220713r991589_rule'
  tag stig_id: 'WN10-00-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22417r554625_fix'
  tag 'documentable'
  tag legacy: ['V-63363', 'SV-77853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  backup_operators = input('backup_operators')
  backup_operators_group = command("net localgroup Backup Operators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split("\r\n")

  backup_operators_group.each do |user|
    describe user.to_s do
      it { should be_in backup_operators }
    end
  end
  if backup_operators_group.empty?
    impact 0.0
    describe 'There are no users with administrative privileges' do
      skip 'This control is not applicable'
    end
  end
end
