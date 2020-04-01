# -*- encoding : utf-8 -*-

control 'V-63721' do
  title "Windows 10 must be configured to require a minimum pin length of six
        characters or greater."
  desc  "Windows allows the use of PINs as well as biometrics for
        authentication without sending a password to a network or website where it
        could be compromised.  Longer minimum PIN lengths increase the available
        combinations an attacker would have to attempt.  Shorter minimum length
        significantly reduces the strength."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000260'
  tag gid: 'V-63721'
  tag rid: 'SV-78211r6_rule'
  tag stig_id: 'WN10-CC-000260'
  tag fix_id: 'F-98469r2_fix'
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

  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding.

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity\\

      Value Name:  MinimumPINLength

      Type:  REG_DWORD
      Value:  6 (or greater)"
      
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> PIN Complexity >> \"Minimum PIN length\"
      to \"6\" or greater.

      v1607 LTSB:
      The policy path is Computer Configuration >> Administrative Templates >>
      Windows Components >> Windows Hello for Business >> Pin Complexity.

      v1507 LTSB:
      The policy path is Computer Configuration >> Administrative Templates >>
      Windows Components >> Microsoft Passport for Work >> Pin Complexity."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity') do
    it { should have_property 'MinimumPINLength' }
    its('MinimumPINLength') { should be >= 6 }
  end
end

