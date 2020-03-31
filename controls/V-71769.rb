# -*- encoding : utf-8 -*-

control 'V-71769' do
  title "Remote calls to the Security Account Manager (SAM) must be restricted
        to Administrators."
  desc  "The Windows Security Account Manager (SAM) stores users' passwords.
        Restricting remote rpc connections to the SAM to Administrators helps protect
        those credentials."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000167'
  tag gid: 'V-71769'
  tag rid: 'SV-86393r3_rule'
  tag stig_id: 'WN10-SO-000167'
  tag fix_id: 'F-78121r3_fix'
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

  desc "check", "Windows 10 v1507 LTSB version does not include this setting, it
          is NA for those systems.

          If the following registry value does not exist or is not configured as
          specified, this is a finding:

          Registry Hive: HKEY_LOCAL_MACHINE
          Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

          Value Name: RestrictRemoteSAM

          Value Type: REG_SZ
          Value: O:BAG:BAD:(A;;RC;;;BA)"
  
  desc "fix", "Navigate to the policy Computer Configuration >> Windows Settings
          >> Security Settings >> Local Policies >> Security Options >> \"Network access:
          Restrict clients allowed to make remote calls to SAM\".

          Select \"Edit Security\" to configure the \"Security descriptor:\".

          Add \"Administrators\" in \"Group or user names:\" if it is not already listed
          (this is the default).

          Select \"Administrators\" in \"Group or user names:\".

          Select \"Allow\" for \"Remote Access\" in \"Permissions for \"Administrators\".

          Click \"OK\".

          The \"Security descriptor:\" must be populated with \"O:BAG:BAD:(A;;RC;;;BA)
          for the policy to be enforced."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId != '1507'
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
      it { should have_property 'RestrictRemoteSAM' }
      its('RestrictRemoteSAM') { should cmp 'O:BAG:BAD:(A;;RC;;;BA)' }
    end
  else
    impact 0.0
    describe 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.' do
      skip 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.'
    end
  end
end

