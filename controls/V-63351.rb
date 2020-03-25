# frozen_string_literal: true

control 'V-63351' do
  title 'The Windows 10 system must use an anti-virus program.'
  desc  "Malicious software can establish a base on individual desktops and
        servers. Employing an automated mechanism to detect this type of software will
        aid in elimination of the software from the operating system."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-00-000045'
  tag gid: 'V-63351'
  tag rid: 'SV-77841r4_rule'
  tag stig_id: 'WN10-00-000045'
  tag fix_id: 'F-83183r1_fix'
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

  desc "check", "Verify an anti-virus solution is installed on the system. The
        anti-virus solution may be bundled with an approved host-based security
        solution.

        If there is no anti-virus solution installed on the system, this is a finding."

  desc "fix", 'Install an anti-virus solution on the system.'

  anti_virus_product_name = <<-EOH
        #script came from: https://www.404techsupport.com/2015/04/27/powershell-script-detect-antivirus-product-and-status/

        $computername=$env:computername
        $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $computername

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


        describe powershell(anti_virus_product_name) do
          its('stdout') { should be_in input('anti_virus_product') }
        end

  #describe.one do
    #describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\McAfee\DesktopProtection\szProductVer') do
      #it { should exist }
    #end
    #describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\McAfee\Endpoint\AV\ProductVersion') do
    #  it { should exist }
    #end
  #end
end
