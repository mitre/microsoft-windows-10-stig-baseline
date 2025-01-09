control 'SV-220726' do
  title 'Data Execution Prevention (DEP) must be configured to at least OptOut.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications. Data Execution Prevention (DEP) prevents harmful code from running in protected memory locations reserved for Windows and other programs.'
  desc 'check', 'Verify the DEP configuration.
Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
If the value for "nx" is not "OptOut", this is a finding.
(The more restrictive configuration of "AlwaysOn" would not be a finding.)'
  desc 'fix', 'Configure DEP to at least OptOut.

Note: Suspend BitLocker before making changes to the DEP configuration.

Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
Enter "BCDEDIT /set {current} nx OptOut".  (If using PowerShell "{current}" must be enclosed in quotes.)
"AlwaysOn", a more restrictive selection, is also valid but does not allow applications that do not function properly to be opted out of DEP.

Opted out exceptions can be configured in the "System Properties".

Open "System" in Control Panel.
Select "Advanced system settings".
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Applications that are opted out are configured in the window below the selection "Turn on DEP for all programs and services except those I select:".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22441r554663_chk'
  tag severity: 'high'
  tag gid: 'V-220726'
  tag rid: 'SV-220726r958928_rule'
  tag stig_id: 'WN10-00-000145'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-22430r554664_fix'
  tag 'documentable'
  tag legacy: ['SV-83439', 'V-68845']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

 bcdedit = json(command: 'bcdedit /enum "{current}" | FindStr "nx" | ConvertTo-Json').params
  describe 'Verify the DEP configuration' do
    subject { bcdedit }
    it { should eq 'nx                      OptOut' }
  end
end
