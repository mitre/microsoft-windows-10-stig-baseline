control 'SV-220705' do
  title 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Utilizing an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.'
  desc 'check', 'Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs. This must include packaged apps such as the universal apps installed by default on systems.

If an application allowlisting program is not in use on the system, this is a finding.

Configuration of allowlisting applications will vary by the program.

AppLocker is an allowlisting application built into Windows 10 Enterprise. A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:
Run "PowerShell".

Execute the following command, substituting [c:\\temp\\file.xml] with a location and file name appropriate for the system:
Get-AppLockerPolicy -Effective -XML > c:\\temp\\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available at the following link:

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide'
  desc 'fix', 'Configure an application allowlisting program to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

Configuration of allowlisting applications will vary by the program. AppLocker is an allowlisting application built into Windows 10 Enterprise.

If AppLocker is used, it is configured through group policy in Computer Configuration >> Windows Settings >> Security Settings >> Application Control Policies >> AppLocker.

Implementation guidance for AppLocker is available at the following link:

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22420r951123_chk'
  tag severity: 'medium'
  tag gid: 'V-220705'
  tag rid: 'SV-220705r958808_rule'
  tag stig_id: 'WN10-00-000035'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-22409r890419_fix'
  tag 'documentable'
  tag legacy: ['SV-77835', 'V-63345']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']

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
