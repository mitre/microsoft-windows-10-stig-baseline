control 'SV-268315' do
  title 'Copilot in Windows must be disabled for Windows 10.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.'
  desc 'check', 'If the following local computer policy is not configured as specified, this is a finding:
User Configuration >> Administrative Templates >> Windows Components >> Windows Copilot >> "Turn off Windows Copilot" to "Enabled".'
  desc 'fix', 'Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Windows Copilot >> "Turn off Windows Copilot" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-72336r1016352_chk'
  tag severity: 'medium'
  tag gid: 'V-268315'
  tag rid: 'SV-268315r1016354_rule'
  tag stig_id: 'WN10-00-000107'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-72239r1016353_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
