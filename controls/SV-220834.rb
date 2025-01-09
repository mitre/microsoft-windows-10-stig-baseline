control 'SV-220834' do
  title 'Windows Telemetry must not be configured to Full.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. "Basic" sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced" includes additional information on how Windows and apps are used and advanced reliability data. Windows Analytics can use a "limited enhanced" level to provide information such as health data for devices. This requires the configuration of an additional setting available with v1709 and later of Windows 10.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\

Value Name: AllowTelemetry

Type: REG_DWORD
Value: 0x00000000 (0) (Security)
0x00000001 (1) (Basic)

If an organization is using v1709 or later of Windows 10, this may be configured to "Enhanced" to support Windows Analytics. V-220833 must also be configured to limit the Enhanced diagnostic data to the minimum required by Windows Analytics. This registry value will then be 0x00000002 (2).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Data Collection and Preview Builds >> "Allow Telemetry" to "Enabled" with "0 - Security [Enterprise Only]" or "1 - Basic" selected in "Options:". 

If an organization is using v1709 or later of Windows 10, this may be configured to "2 - Enhanced" to support Windows Analytics. V-220833 must also be configured to limit the Enhanced diagnostic data to the minimum required by Windows Analytics.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22549r930671_chk'
  tag severity: 'medium'
  tag gid: 'V-220834'
  tag rid: 'SV-220834r991589_rule'
  tag stig_id: 'WN10-CC-000205'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22538r930672_fix'
  tag 'documentable'
  tag legacy: ['V-63683', 'SV-78173']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 0 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
      it { should have_property 'AllowTelemetry' }
      its('AllowTelemetry') { should cmp 2 }
    end
  end
end
