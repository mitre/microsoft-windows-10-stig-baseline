# encoding: UTF-8

control "V-99563" do
  title "Windows 10 should be configured to prevent users from receiving
suggestions for third-party or additional applications. "
  desc  "Windows spotlight features may suggest apps and content from
third-party software publishers in addition to Microsoft apps and content. "
  impact 0.3
  tag severity: nil
  tag gtitle: "WN10-CC-000390"
  tag gid: "V-99563"
  tag rid: "SV-108667r1_rule"
  tag stig_id: "WN10-CC-000390"
  tag fix_id: "F-105247r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as
specified, this is a finding.

    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_CURRENT_USER
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\

    Value Name: DisableThirdPartySuggestions

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for User Configuration >>
Administrative Templates >> Windows Components >> Cloud Content >> \"Do not
suggest third-party content in Windows spotlight\" to \"Enabled"
 
   describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('DisableThirdPartySuggestions') { should cmp 1 }
   end
end

