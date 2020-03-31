# -*- encoding : utf-8 -*-

control 'V-63357' do
  title "Non system-created file shares on a system must limit access to groups
        that require it."
  desc  "Shares which provide network access, should not typically exist on a
        workstation except for system-created administrative shares, and could
        potentially expose sensitive information.  If a share is necessary, share
        permissions, as well as NTFS permissions, must be reconfigured to give the
        minimum access to those accounts that require it."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000060'
  tag gid: 'V-63357'
  tag rid: 'SV-77847r1_rule'
  tag stig_id: 'WN10-00-000060'
  tag fix_id: 'F-69277r1_fix'
  tag cci: ['CCI-001090']
  tag nist: %w[SC-4 Rev_4]
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

  desc "check", "Non system-created shares should not typically exist on
        workstations.

        If only system-created shares exist on the system this is NA.

        Run \"Computer Management\".
        Navigate to System Tools >> Shared Folders >> Shares.

        If the only shares listed are \"ADMIN$\", \"C$\" and \"IPC$\", this is NA.
        (Selecting Properties for system-created shares will display a message that it
        has been shared for administrative purposes.)

        Right click any non-system-created shares.
        Select \"Properties\".
        Select the \"Share Permissions\" tab.

        Verify the necessity of any shares found.
        If the file shares have not been reconfigured to restrict permissions to the
        specific groups or accounts that require access, this is a finding.

        Select the \"Security\" tab.

        If the NTFS permissions have not been reconfigured to restrict permissions to
        the specific groups or accounts that require access, this is a finding."

  desc "fix", "If a non system-created share is required on a system, configure
        the share and NTFS permissions to limit access to the specific groups or
        accounts that require it.

        Remove any unnecessary non-system created shares."

  share_names = []
  share_paths = []
  get = command('Get-WMIObject -Query "SELECT * FROM Win32_Share" | Findstr /V "Name --"').stdout.strip.split("\n")

  get.each do |share|
    loc_space = share.index(' ')

    names = share[0..loc_space - 1]

    share_names.push(names)
    path = share[9..50]
    share_paths.push(path)
  end

  share_names_string = share_names.join(',')

  if share_names_string != 'ADMIN$,C$,IPC$'

    [share_paths, share_names].each do |path1, _name1|
      describe command("Get-Acl -Path '#{path1}' | Format-List | Findstr /i /C:'Everyone Allow'") do
        its('stdout') { should eq '' }
      end
    end
  end

  if share_names_string == 'ADMIN$,C$,IPC$'
    impact 0.0
    describe 'The default files shares exist' do
      skip 'This control is NA'
    end
  end
end

