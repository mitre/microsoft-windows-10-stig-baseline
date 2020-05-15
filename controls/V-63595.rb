# -*- encoding : utf-8 -*-

control 'V-63595' do
  title "Virtualization Based Security must be enabled on Windows 10 with the
        platform security level configured to Secure Boot or Secure Boot with DMA
        Protection."
  desc  "Virtualization Based Security (VBS) provides the platform for the
        additional security features, Credential Guard and Virtualization based
        protection of code integrity.  Secure Boot is the minimum security level with
        DMA protection providing additional memory protection.  DMA Protection requires
        a CPU that supports input/output memory management unit (IOMMU)."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-CC-000070'
  tag gid: 'V-63595'
  tag rid: 'SV-78085r6_rule'
  tag stig_id: 'WN10-CC-000070'
  tag fix_id: 'F-74851r3_fix'
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

  desc "check", "Confirm Virtualization Based Security is enabled and running with
        Secure Boot or Secure Boot and DMA Protection.

        For those devices that support virtualization based security (VBS) features,
        including Credential Guard or protection of code integrity, this must be
        enabled. If the system meets the hardware and firmware dependencies for
        enabling VBS but it is not enabled, this is a CAT III finding.

        Virtualization based security, including Credential Guard, currently cannot be
        implemented in virtual desktop implementations (VDI) due to specific supporting
        requirements including a TPM, UEFI with Secure Boot, and the capability to run
        the Hyper-V feature within the virtual desktop.

        For VDIs where the virtual desktop instance is deleted or refreshed upon
        logoff, this is NA.

        Run \"PowerShell\" with elevated privileges (run as administrator).

        Enter the following:

        \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace
        root\\Microsoft\\Windows\\DeviceGuard\"

        If \"RequiredSecurityProperties\" does not include a value of \"2\" indicating
        \"Secure Boot\" (e.g., \"{1, 2}\"), this is a finding.

        If \"Secure Boot and DMA Protection\" is configured, \"3\" will also be
        displayed in the results (e.g., \"{1, 2, 3}\").

        If \"VirtualizationBasedSecurityStatus\" is not a value of \"2\" indicating
        \"Running\", this is a finding.

        Alternately:

        Run \"System Information\".

        Under \"System Summary\", verify the following:

        If \"Device Guard Virtualization based security\" does not display \"Running\",
        this is finding.

        If \"Device Guard Required Security Properties\" does not display \"Base
        Virtualization Support, Secure Boot\", this is finding.

        If \"Secure Boot and DMA Protection\" is configured, \"DMA Protection\" will
        also be displayed (e.g., \"Base Virtualization Support, Secure Boot, DMA
        Protection\").

        The policy settings referenced in the Fix section will configure the following
        registry values. However due to hardware requirements, the registry values
        alone do not ensure proper function.

        Registry Hive: HKEY_LOCAL_MACHINE
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

        Value Name: EnableVirtualizationBasedSecurity
        Value Type: REG_DWORD
        Value: 1

        Value Name: RequirePlatformSecurityFeatures
        Value Type: REG_DWORD
        Value: 1 (Secure Boot only) or 3 (Secure Boot and DMA Protection)

        A Microsoft article on Credential Guard system requirement can be found at the
        following link:

        https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements

        NOTE:  The severity level for the requirement will be upgraded to CAT II
        starting January 2020."

  desc "fix", "Virtualization based security, including Credential Guard,
        currently cannot be implemented in virtual desktop implementations (VDI) due to
        specific supporting requirements including a TPM, UEFI with Secure Boot, and
        the capability to run the Hyper-V feature within the virtual desktop.

        For VDIs where the virtual desktop instance is deleted or refreshed upon
        logoff, this is NA.

        Configure the policy value for Computer Configuration >> Administrative
        Templates >> System >> Device Guard >> \"Turn On Virtualization Based
        Security\" to \"Enabled\" with \"Secure Boot\" or \"Secure Boot and DMA
        Protection\" selected for \"Select Platform Security Level:\".

        A Microsoft article on Credential Guard system requirement can be found at the
        following link."

  ref 'https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements'

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63595.' do
      skip 'This is a VDI System; This System is NA for Control V-63595.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
      it { should have_property 'EnableVirtualizationBasedSecurity' }
      its('EnableVirtualizationBasedSecurity') { should cmp 1 }
    end
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should have_property 'RequirePlatformSecurityFeatures' }
        its('RequirePlatformSecurityFeatures') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should have_property 'RequirePlatformSecurityFeatures' }
        its('RequirePlatformSecurityFeatures') { should cmp 3 }
      end
    end
  end
end

