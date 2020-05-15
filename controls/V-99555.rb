# encoding: UTF-8

control "V-99555" do
  title "Passwords for the built-in local Administrator account must be changed
at least every 60 days."
  desc  "The longer a password is in use, the greater the opportunity for
someone to gain unauthorized knowledge of the password. The built-in local
Administrator account is not generally used and its password not may be changed
as frequently as necessary. Changing the password for the built-in local
Administrator account on a regular basis will limit its exposure.

    Organizations that use an automated tool, such Microsoft's Local
Administrator Password Solution (LAPS), on domain-joined systems can configure
this to occur more frequently. LAPS will change the password every \"30\" days
by default."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-SO-000280"
  tag gid: "V-99555"
  tag rid: "SV-108659r1_rule"
  tag stig_id: "WN10-SO-000280"
  tag fix_id: "F-105239r1_fix"
  tag cci: ["CCI-000199"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]
  desc  "rationale", ""
  desc  "check", "
    Review the password last set date for the built-in Administrator account.

    On the local domain joined workstation:

    Open \"PowerShell\".

    Enter \"Get-LocalUser –Name * | Select-Object *”

    If the \"PasswordLastSet\" date is greater than \"60\" days old for the
Built-in account for administering the computer/domain, this is a finding"
  desc  "fix", "Change the built-in Administrator account password at least every \"60\"
days.

    Automated tools, such as Microsoft's LAPS, may be used on domain-joined
member servers to meet this requirement."
  
 administrator = input('local_administrator')
 local_password_set_date = json({ command: "Get-LocalUser -name #{administrator} | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-60)} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json"})
   local_date =  local_password_set_date["DateTime"]
    if (local_date == nil)
      describe 'Local Administrator Account is within 365 days since password change' do
        skip 'Local Administrator Account is within 365 days since password change'
      end
    else
       describe 'Password Last Set' do
         it 'Local Administrator Account Password Last Set Date is' do
         failure_message = "Password Date should not be more that 365 Days: #{local_date}"
         expect(local_date).to be_empty, failure_message
        end
       end
      end
end

