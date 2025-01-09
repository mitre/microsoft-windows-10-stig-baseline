control 'SV-220707' do
  title 'The Windows 10 system must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an antivirus solution is installed on the system and in use. The antivirus solution may be bundled with an approved Endpoint Security Solution.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName"

Verify third-party antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName"

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName"
                                      
Enter "get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName" 
                                                           
If there is no antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'If no antivirus software is on the system and in use, install Windows Defender or a third-party antivirus solution.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22422r1016335_chk'
  tag severity: 'high'
  tag gid: 'V-220707'
  tag rid: 'SV-220707r1016358_rule'
  tag stig_id: 'WN10-00-000045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22411r1016336_fix'
  tag 'documentable'
  tag legacy: ['SV-77841', 'V-63351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  anti_virus_product_name = <<-EOH
        #script came from: https://www.404techsupport.com/2015/04/27/powershell-script-detect-antivirus-product-and-status/

        $computername=$env:computername
        $AntiVirusProduct = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $computername

        #Switch to determine the status of antivirus definitions and real-time protection.
        #Write-Output $AntiVirusProduct.productState
        switch ($AntiVirusProduct.productState) {
          "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
          "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }

        Write-Output $AntiVirusProduct.displayName
  EOH

  anti_virus_def_status = <<-EOH
        #script came from: https://www.404techsupport.com/2015/04/27/powershell-script-detect-antivirus-product-and-status/

        $computername=$env:computername
        $AntiVirusProduct = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $computername

        #Switch to determine the status of antivirus definitions and real-time protection.
        #Write-Output $AntiVirusProduct.productState
        switch ($AntiVirusProduct.productState) {
          "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
          "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }

        Write-Output $defstatus
  EOH

  anti_virus_status = <<-EOH
        #script came from: https://www.404techsupport.com/2015/04/27/powershell-script-detect-antivirus-product-and-status/

        $computername=$env:computername
        $AntiVirusProduct = Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $computername

        #Switch to determine the status of antivirus definitions and real-time protection.
        #Write-Output $AntiVirusProduct.productState
        switch ($AntiVirusProduct.productState) {
          "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
          "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
          "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
          "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
          "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
          "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }

        Write-Output $rtstatus
  EOH

  check_product = powershell(anti_virus_product_name).stdout.strip.split("\n").map(&:strip)

  describe "The installed anti-virus: #{check_product} is on the Approved Sofware List" do
    subject { check_product }
    it { should be_in input('av_approved_software') }
  end
  describe 'The anti-virus software is enabled on the system' do
    subject { powershell(anti_virus_status).strip }
    it { should cmp 'Enabled' }
  end
  describe 'The anti-virus signature definitions are up to date' do
    subject { powershell(anti_virus_def_status).strip }
    it { should cmp 'Up to date' }
  end
end
