# -*- encoding : utf-8 -*-

control 'V-63363' do
  title "Only accounts responsible for the backup operations must be members of
        the Backup Operators group."
  desc  "Backup Operators are able to read and write to any file in the system,
        regardless of the rights assigned to it.  Backup and restore rights permit
        users to circumvent the file access restrictions present on NTFS disk drives
        for backup and restore purposes.  Members of the Backup Operators group must
        have separate logon accounts for performing backup duties."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000075'
  tag gid: 'V-63363'
  tag rid: 'SV-77853r1_rule'
  tag stig_id: 'WN10-00-000075'
  tag fix_id: 'F-69283r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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
        Review the members of the Backup Operators group.

        If the group contains no accounts, this is not a finding.

        If the group contains any accounts, the accounts must be specifically for
        backup functions.

        If the group contains any standard user accounts used for performing normal
        user tasks, this is a finding."

  desc "fix", "Create separate accounts for backup operations for users with this
        privilege."

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

