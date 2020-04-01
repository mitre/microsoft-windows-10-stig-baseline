# -*- encoding : utf-8 -*-

control 'V-74413' do
  title 'Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.'
  desc  "Use of weak or untested encryption algorithms undermines the purposes
        of utilizing encryption to protect data. By default Windows uses ECC curves
        with shorter key lengths first.  Requiring ECC curves with longer key lengths
        to be prioritized first helps ensure more secure algorithms are used."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000052'
  tag gid: 'V-74413'
  tag rid: 'SV-89087r2_rule'
  tag stig_id: 'WN10-CC-000052'
  tag fix_id: 'F-80955r1_fix'
  tag cci: ['CCI-000803']
  tag nist: %w[IA-7 Rev_4]
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

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\\

      Value Name: EccCurves

      Value Type: REG_MULTI_SZ
      Value: NistP384 NistP256"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> SSL Configuration Settings >> \"ECC
      Curve Order\" to \"Enabled\" with \"ECC Curve Order:\" including the following
      in the order listed:

      NistP384
      NistP256"

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') do
    it { should have_property 'EccCurves' }
   end
  
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') do
      its('EccCurves') { should include 'NistP384' }
      its('EccCurves') { should include 'NistP256' }
    end
end

