control 'SV-220728' do
  title 'The Windows PowerShell 2.0 feature must be disabled on the system.'
  desc 'Windows PowerShell 5.0 added advanced logging features which can provide additional detail when malware has been run on a system.  Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.'
  desc 'check', 'Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*

If either of the following have a "State" of "Enabled", this is a finding.

FeatureName : MicrosoftWindowsPowerShellV2
State : Enabled
FeatureName : MicrosoftWindowsPowerShellV2Root
State : Enabled

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

If "Windows PowerShell 2.0" (whether the subcategory of "Windows PowerShell 2.0 Engine" is selected or not) is selected, this is a finding.'
  desc 'fix', 'Disable "Windows PowerShell 2.0" on the system.

Run "Windows PowerShell" with elevated privileges (run as administrator).
Enter the following:
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

This command should disable both "MicrosoftWindowsPowerShellV2Root" and "MicrosoftWindowsPowerShellV2" which correspond to "Windows PowerShell 2.0" and "Windows PowerShell 2.0 Engine" respectively in "Turn Windows features on or off".

Alternately:
Search for "Features".
Select "Turn Windows features on or off".
De-select "Windows PowerShell 2.0".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22443r554669_chk'
  tag severity: 'medium'
  tag gid: 'V-220728'
  tag rid: 'SV-220728r958478_rule'
  tag stig_id: 'WN10-00-000155'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22432r554670_fix'
  tag 'documentable'
  tag legacy: ['V-70637', 'SV-85259']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  powershellv2 = json( command: 'Get-WindowsOptionalFeature -Online | Where FeatureName -eq MicrosoftWindowsPowerShellV2 | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json').params
  powershellv2root = json( command: 'Get-WindowsOptionalFeature -Online | Where FeatureName -eq MicrosoftWindowsPowerShellV2Root | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json').params  

    describe 'Feature Name MicrosoftWindowsPowerShellV2 should not be Enabled' do
      subject { powershellv2 }
      its(['State']) { should_not eq "Enabled" }
    end
    describe 'Feature Name MicrosoftWindowsPowerShellV2Root should not be Enabled' do
      subject { powershellv2root }
      its(['State']) { should_not eq "Enabled" }
    end
end
