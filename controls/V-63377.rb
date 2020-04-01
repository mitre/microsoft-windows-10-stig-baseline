# -*- encoding : utf-8 -*-

control 'V-63377' do
  title "Internet Information System (IIS) or its subcomponents must not be
        installed on a workstation."
  desc  "Installation of Internet Information System (IIS) may allow
        unauthorized internet services to be hosted.  Websites must only be hosted on
        servers that have been designed for that purpose and can be adequately secured."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-00-000100'
  tag gid: 'V-63377'
  tag rid: 'SV-77867r1_rule'
  tag stig_id: 'WN10-00-000100'
  tag fix_id: 'F-69297r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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

  desc "check", "IIS is not installed by default.  Verify it has not been
        installed on the system.

        Run \"Programs and Features\".
        Select \"Turn Windows features on or off\".

        If the entries for \"Internet Information Services\" or \"Internet Information
        Services Hostable Web Core\" are selected, this is a finding.

        If an application requires IIS or a subset to be installed to function, this
        needs be documented with the ISSO.  In addition, any applicable requirements
        from the IIS STIG must be addressed."

  desc "fix", "Uninstall \"Internet Information Services\" or \"Internet
        Information Services Hostable Web Core\" from the system."

  describe windows_feature('Internet Information Services') do
    it { should_not be_installed }
  end
end

