control 'SV-256894' do
  title 'Internet Explorer must be disabled for Windows 10.'
  desc 'Internet Explorer 11 (IE11) is no longer supported on Windows 10 semi-annual channel.'
  desc 'check', 'Determine if IE11 is installed or enabled on Windows 10 semi-annual channel.

If IE11 is installed or not disabled on Windows 10 semi-annual channel, this is a finding.

If IE11 is installed on a unsupported operating system and is enabled or installed, this is a finding.

For more information, visit: https://learn.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge#what-is-the-lifecycle-policy-for-internet-explorer-'
  desc 'fix', 'For Windows 10 semi-annual channel, remove or disable the IE11 application. 

To disable IE11 as a standalone browser:

Set the policy value for "Computer Configuration/Administrative Templates/Windows Components/Internet Explorer/Disable Internet Explorer 11 as a standalone browser" to "Enabled" with the option value set to "Never".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-60569r891283_chk'
  tag severity: 'medium'
  tag gid: 'V-256894'
  tag rid: 'SV-256894r958552_rule'
  tag stig_id: 'WN10-CC-000391'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-60512r891284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
