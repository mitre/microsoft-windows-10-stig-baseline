# -*- encoding : utf-8 -*-

control 'V-63681' do
  title 'The Windows dialog box title for the legal banner must be configured.'
  desc  "Failure to display the logon banner prior to a logon attempt will
        negate legal proceedings resulting from unauthorized access to system
        resources."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-SO-000080'
  tag gid: 'V-63681'
  tag rid: 'SV-78171r1_rule'
  tag stig_id: 'WN10-SO-000080'
  tag fix_id: 'F-69609r1_fix'
  tag cci: %w[CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388]
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c3', 'Rev_4']
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
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: LegalNoticeCaption

      Value Type: REG_SZ
      Value: See message title above

      \"DoD Notice and Consent Banner\", \"US Department of Defense Warning
      Statement\" or a site-defined equivalent, this is a finding.

      If a site-defined title is used, it can in no case contravene or modify the
      language of the banner text required in WN10-SO-000075."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Interactive logon: Message title for users attempting to log on\" to \"DoD
      Notice and Consent Banner\", \"US Department of Defense Warning Statement\", or
      a site-defined equivalent.

      If a site-defined title is used, it can in no case contravene or modify the
      language of the banner text required in WN10-SO-000075."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'LegalNoticeCaption' }
  end

  key = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').LegalNoticeCaption.to_s

  legal_notice_caption = input('LegalNoticeCaption')

  describe 'The required legal notice caption' do
    subject { key.scan(/[\w().;,!]/).join }
    it { should cmp legal_notice_caption.scan(/[\w().;,!]/).join }
  end
end

