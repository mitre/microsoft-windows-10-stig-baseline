# -*- encoding : utf-8 -*-

control 'V-63393' do
  title 'Software certificate installation files must be removed from Windows 10.'
  desc  "Use of software certificates and their accompanying installation files
        for end users to access resources is less secure than the use of hardware-based
        certificates."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000130'
  tag gid: 'V-63393'
  tag rid: 'SV-77883r2_rule'
  tag stig_id: 'WN10-00-000130'
  tag fix_id: 'F-100989r1_fix'
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

  desc "check", "Search all drives for *.p12 and *.pfx files.

        If any files with these extensions exist, this is a finding.

        This does not apply to server-based applications that have a requirement for
        .p12 certificate files (e.g., Oracle Wallet Manager) or Adobe PreFlight
        certificate files. Some applications create files with extensions of .p12 that
        are not certificate installation files. Removal of non-certificate installation
        files from systems is not required. These must be documented with the ISSO."

  desc "fix", "Remove any certificate installation files (*.p12 and *.pfx) found
        on a system.

        Note: This does not apply to server-based applications that have a requirement
        for .p12 certificate files (e.g., Oracle Wallet Manager) or Adobe PreFlight
        certificate files."

  describe command('where /R c: *.p12 *.pfx') do
    its('stdout') { should eq '' }
  end
end

