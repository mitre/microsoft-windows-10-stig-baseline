# -*- encoding : utf-8 -*-

control 'V-63797' do
  title "The system must be configured to prevent the storage of the LAN
        Manager hash of passwords."
  desc  "The LAN Manager hash uses a weak encryption algorithm and there are
        several tools available that use this hash to retrieve account passwords.  This
        setting controls whether or not a LAN Manager hash of the password is stored in
        the SAM the next time the password is changed."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-SO-000195'
  tag gid: 'V-63797'
  tag rid: 'SV-78287r1_rule'
  tag stig_id: 'WN10-SO-000195'
  tag fix_id: 'F-69725r1_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)', 'Rev_4']
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
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

      Value Name: NoLMHash

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: Do not store LAN Manager hash value on next password
      change\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'NoLMHash' }
    its('NoLMHash') { should cmp 1 }
  end
end

