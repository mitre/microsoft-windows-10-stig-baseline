# -*- encoding : utf-8 -*-

control 'V-63917' do
  title "The Load and unload device drivers user right must only be assigned to
        the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Load and unload device drivers\" user right allows device drivers to
        dynamically be loaded on a system by a user. This could potentially be used to
        install malicious code by an attacker."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000120'
  tag gid: 'V-63917'
  tag rid: 'SV-78407r1_rule'
  tag stig_id: 'WN10-UR-000120'
  tag fix_id: 'F-69845r1_fix'
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
  
  desc "check", "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".

      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
      >> Security Settings >> Local Policies >> User Rights Assignment.

      If any groups or accounts other than the following are granted the \"Load and
      unload device drivers\" user right, this is a finding:

      Administrators"
  
      desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Load and unload device drivers\" to only include the following groups or
      accounts:

      Administrators"

    describe security_policy do
      its('SeLoadDriverPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

