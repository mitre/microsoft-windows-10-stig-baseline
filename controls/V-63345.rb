# -*- encoding : utf-8 -*-

control 'V-63345' do
  title "The operating system must employ a deny-all, permit-by-exception
        policy to allow the execution of authorized software programs."
  desc  "Utilizing a whitelist provides a configuration management method for
        allowing the execution of only authorized software. Using only authorized
        software decreases risk by limiting the number of potential vulnerabilities.

        The organization must identify authorized software programs and only permit
        execution of authorized software. The process used to identify software
        programs that are authorized to execute on organizational information systems
        is commonly referred to as whitelisting."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000035'
  tag gid: 'V-63345'
  tag rid: 'SV-77835r3_rule'
  tag stig_id: 'WN10-00-000035'
  tag fix_id: 'F-69267r3_fix'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)', 'Rev_4']
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

  desc 'check', "This is applicable to unclassified systems; for other systems
        this is NA.

        Verify the operating system employs a deny-all, permit-by-exception policy to
        allow the execution of authorized software programs. This must include packaged
        apps such as the universals apps installed by default on systems.

        If an application whitelisting program is not in use on the system, this is a
        finding.

        Configuration of whitelisting applications will vary by the program.

        AppLocker is a whitelisting application built into Windows 10 Enterprise.  A
        deny-by-default implementation is initiated by enabling any AppLocker rules
        within a category, only allowing what is specified by defined rules.

        If AppLocker is used, perform the following to view the configuration of
        AppLocker:
        Run \"PowerShell\".

        Execute the following command, substituting [c:\\temp\\file.xml] with a
        location and file name appropriate for the system:
        Get-AppLockerPolicy -Effective -XML > c:\\temp\\file.xml

        This will produce an xml file with the effective settings that can be viewed in
        a browser or opened in a program such as Excel for review.

        Implementation guidance for AppLocker is available in the NSA paper
        \"Application Whitelisting using Microsoft AppLocker\" at the following link:

        https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm"

  desc 'fix', "Configure an application whitelisting program to employ a deny-all,
        permit-by-exception policy to allow the execution of authorized software
        programs.

        Configuration of whitelisting applications will vary by the program.  AppLocker
        is a whitelisting application built into Windows 10 Enterprise.

        If AppLocker is used, it is configured through group policy in Computer
        Configuration >> Windows Settings >> Security Settings >> Application Control
        Policies >> AppLocker.

        Implementation guidance for AppLocker is available in the NSA paper
        \"Application Whitelisting using Microsoft AppLocker\" at the following link:

        https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm"

  ref 'https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm'

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe 'A manual review is required to ensure the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs' do
      skip 'A manual review is required to ensure the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs'
    end
  end
end

