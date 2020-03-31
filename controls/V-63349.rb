# -*- encoding : utf-8 -*-

control 'V-63349' do
  title 'Windows 10 systems must be maintained at a supported servicing level.'
  desc  "Windows 10 is maintained by Microsoft at servicing levels for specific
        periods of time to support Windows as a Service. Systems at unsupported
        servicing levels or releases will not receive security updates for new
        vulnerabilities which leaves them subject to exploitation.

        New versions with feature updates are planned to be released on a
        semi-annual basis with an estimated support timeframe of 18 to 30 months
        depending on the release. Support for previously released versions has been
        extended for Enterprise editions.

        A separate servicing branch intended for special purpose systems is the
        Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive
        security updates for 10 years but excludes feature updates."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-00-000040'
  tag gid: 'V-63349'
  tag rid: 'SV-77839r9_rule'
  tag stig_id: 'WN10-00-000040'
  tag fix_id: 'F-98031r2_fix'
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

  desc "check", "Run \"winver.exe\".

        If the \"About Windows\" dialog box does not display:

        \"Microsoft Windows Version 1703 (OS Build 15063.0)\"

        or greater, this is a finding.

        Note: Microsoft has extended support for previous versions providing critical
        and important updates for Windows 10 Enterprise.

        Microsoft scheduled end of support dates for current Semi-Annual Channel
        versions:
        v1703 - 8 October 2019
        v1709 - 14 April 2020
        v1803 - 10 November 2020
        v1809 - 13 April 2021
        v1903 - 8 December 2020

        No preview versions will be used in a production environment.

        Special purpose systems using the Long-Term Servicing Branch\\Channel (LTSC\\B)
        may be at following versions which are not a finding:

        v1507 (Build 10240)
        v1607 (Build 14393)
        v1809 (Build 17763)"

  desc "fix", "Update systems on the Semi-Annual Channel to \"Microsoft Windows
        Version 1703 (OS Build 15063.0)\" or greater.

        It is recommended systems be upgraded to the most recently released version.

        Special purpose systems using the Long-Term Servicing Branch\\Channel (LTSC\\B)
        may be at the following versions:

        v1507 (Build 10240)
        v1607 (Build 14393)
        v1809 (Build 17763)"

  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion') do
    it { should have_property 'CurrentVersion' }
    its('CurrentVersion') { should be >= '6.3' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion') do
    it { should have_property 'CurrentBuildNumber' }
    its('ReleaseId') { should be >= '1703' }
  end
end

