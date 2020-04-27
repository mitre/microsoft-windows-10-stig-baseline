# encoding: UTF-8

control "V-99561" do
  title "Windows Ink Workspace configured but disallow access above the lock.  "
  desc  "Securing Windows Ink which contains application and features oriented
towards pen computing. "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-CC-000385"
  tag gid: "V-99561"
  tag rid: "SV-108665r1_rule"
  tag stig_id: "WN10-CC-000385"
  tag fix_id: "F-105245r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as
specified, this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\Software\\Policies\\Microsoft\\WindowsInkWorkspace

    Value Name: AllowWindowsInkWorkspace
    Value Type: REG_DWORD
    Value data: 1"
  desc  "fix", "Disable the convenience PIN sign-in.

    If this needs to be corrected configure the policy value for Computer
Configuration >> Administrative Templates >> Windows Components >> Windows Ink
Workspace   >> Set \" Allow Windows Ink Workspace\" to \"Enabled” Set Options
‘On, but disallow access above lock”."

   describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace') do
      it { should have_property 'AllowWindowsInkWorkspace' }
      its('AllowWindowsInkWorkspace') { should cmp 1 }
   end
  end

