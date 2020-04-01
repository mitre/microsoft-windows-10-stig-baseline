# -*- encoding : utf-8 -*-

control 'V-63319' do
  title "Domain-joined systems must use Windows 10 Enterprise Edition 64-bit
        version."
  desc  "Features such as Credential Guard use virtualization based security to
        protect information that could be used in credential theft attacks if
        compromised. There are a number of system requirements that must be met in
        order for Credential Guard to be configured and enabled properly.
        Virtualization based security and Credential Guard are only available with
        Windows 10 Enterprise 64-bit version."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000005'
  tag gid: 'V-63319'
  tag rid: 'SV-77809r3_rule'
  tag stig_id: 'WN10-00-000005'
  tag fix_id: 'F-69237r2_fix'
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

  desc "check", "Verify domain-joined systems are using Windows 10 Enterprise
        Edition 64-bit version.

        For standalone systems, this is NA.

        Open \"Settings\".

        Select \"System\", then \"About\".

        If \"Edition\" is not \"Windows 10 Enterprise\", this is a finding.

        If \"System type\" is not \"64-bit operating system…\", this is a finding."

  desc "fix", 'Use Windows 10 Enterprise 64-bit version for domain-joined systems.'

  describe os.arch do
    it { should eq 'x86_64' }
  end

  describe os.name do
    it { should eq 'windows_10_enterprise' }
  end
end

