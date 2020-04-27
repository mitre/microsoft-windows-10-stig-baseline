# encoding: UTF-8

control "V-99559" do
  title "The convenience PIN for Windows 10 must be disabled.  "
  desc  "This policy controls whether a domain user can sign in using a
convenience PIN to prevent enabling (Password Stuffer)."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-CC-000370"
  tag gid: "V-99559"
  tag rid: "SV-108663r1_rule"
  tag stig_id: "WN10-CC-000370"
  tag fix_id: "F-105243r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as
specified, this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System

    Value Name: AllowDomainPINLogon
    Value Type: REG_DWORD
    Value data: 0 "
  desc  "fix", "Disable the convenience PIN sign-in.

    If this needs to be corrected configure the policy value for Computer
Configuration >> Administrative Templates >> System >> Logon >> Set \"Turn on
convenience PIN sign-in\" to \"Disabled”."
 
   describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
      it { should have_property 'AllowDomainPINLogon' }
      its('AllowDomainPINLogon') { should cmp 0 }
   end
end

