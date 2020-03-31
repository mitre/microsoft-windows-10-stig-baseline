# -*- encoding : utf-8 -*-

control 'V-63359' do
  title "Unused accounts must be disabled or removed from the system after
        #{input('max_inactive_days')} days of inactivity."
  desc  "Outdated or unused accounts provide penetration points that may go
        undetected.  Inactive accounts must be deleted if no longer necessary or, if
        still required, disable until needed."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-00-000065'
  tag gid: 'V-63359'
  tag rid: 'SV-77849r1_rule'
  tag stig_id: 'WN10-00-000065'
  tag fix_id: 'F-69279r1_fix'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e', 'Rev_4']
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

  desc "check", "Run \"PowerShell\".
        Copy the lines below to the PowerShell window and enter.

        \"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
        $_.SchemaClassName -eq 'user' } | ForEach {
          $user = ([ADSI]$_.Path)
          $lastLogin = $user.Properties.LastLogin.Value
          $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
          if ($lastLogin -eq $null) {
              $lastLogin = 'Never'
          }
          Write-Host $user.Name $lastLogin $enabled
        }\"

        This will return a list of local accounts with the account name, last logon,
        and if the account is enabled (True/False).
        For example: User1  10/31/2015  5:49:56  AM  True

        Review the list to determine the finding validity for each account reported.

        Exclude the following accounts:
        Built-in administrator account (Disabled, SID ending in 500)
        Built-in guest account (Disabled, SID ending in 501)
        Built-in DefaultAccount (Disabled, SID ending in 503)
        Local administrator account

        If any enabled accounts have not been logged on to within the past 35 days,
        this is a finding.

        Inactive accounts that have been reviewed and deemed to be required must be
        documented with the ISSO."

  desc "fix", "Regularly review local accounts and verify their necessity.
        Disable or delete any active accounts that have not been used in
        the last #{input('max_inactive_days')} days."

  # userList = users.where { uid !~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-50[0-3]/ }
  # PR submitted to return the last logon property via users.
  # https://github.com/inspec/inspec/issues/4723

  users = command("Get-CimInstance -Class Win32_Useraccount -Filter 'LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --'").stdout.strip.split(' ')

  get_sids = []
  get_names = []
  names = []
  inactive_accounts = []

  unless users.empty?
    users.each do |user|
      get_sids = command("wmic useraccount where \"Name='#{user}'\" get name',' sid| Findstr /v SID").stdout.strip
      get_last = get_sids[get_sids.length - 3, 3]

      loc_space = get_sids.index(' ')
      names = get_sids[0, loc_space]
      if get_last != '500' && get_last != '501' && get_last != '503'
        get_names.push(names)
      end
    end
  end

  unless get_names.empty?
    get_names.each do |user|
      get_last_logon = command("Net User #{user} | Findstr /i 'Last Logon' | Findstr /v 'Password script hours'").stdout.strip
      last_logon = get_last_logon[29..33]
      if last_logon != 'Never'
        month = get_last_logon[28..29]
        day = get_last_logon[31..32]
        year = get_last_logon[34..37]

        if get_last_logon[32] == '/'
          month = get_last_logon[28..29]
          day = get_last_logon[31]
          year = get_last_logon[33..37]
        end
        date = day + '/' + month + '/' + year

        date_last_logged_on = DateTime.now.mjd - DateTime.parse(date).mjd
        if date_last_logged_on > input('max_inactive_days')
          inactive_accounts.push(user)
        end

        unless inactive_accounts.empty?
          describe "#{user}'s last logon" do
            describe date_last_logged_on do
              it { should be <= input('max_inactive_days') }
            end
          end
        end
      end

      next if inactive_accounts.empty?

      next unless last_logon == 'Never'

      date_last_logged_on = 'Never'
      describe "#{user}'s last logon" do
        describe date_last_logged_on do
          it { should_not == 'Never' }
        end
      end
    end
  end

  if inactive_accounts.empty?
    impact 0.0
    describe 'The system does not have any inactive accounts, control is NA' do
      skip 'The system does not have any inactive accounts, controls is NA'
    end
  end
end

