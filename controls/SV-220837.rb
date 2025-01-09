control 'SV-220837' do
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  desc 'check', 'The default behavior is for data execution prevention to be turned on for file explorer.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoDataExecutionPrevention

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for data execution prevention to be turned on for file explorer.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> "Turn off Data Execution Prevention for Explorer" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22552r554996_chk'
  tag severity: 'medium'
  tag gid: 'V-220837'
  tag rid: 'SV-220837r958928_rule'
  tag stig_id: 'WN10-CC-000215'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-22541r554997_fix'
  tag 'documentable'
  tag legacy: ['V-63689', 'SV-78179']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should have_property 'NoDataExecutionPrevention' }
      its('NoDataExecutionPrevention') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should_not have_property 'NoDataExecutionPrevention' }
    end
  end
end
