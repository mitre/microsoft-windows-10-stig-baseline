# -*- encoding : utf-8 -*-

control 'V-63323' do
  title "Windows 10 domain-joined systems must have a Trusted Platform Module
        (TPM) enabled and ready for use."
  desc  "Credential Guard uses virtualization based security to protect
        information that could be used in credential theft attacks if compromised.
        There are a number of system requirements that must be met in order for
        Credential Guard to be configured and enabled properly. Without a TPM enabled
        and ready for use, Credential Guard keys are stored in a less secure method
        using software."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-00-000010'
  tag gid: 'V-63323'
  tag rid: 'SV-77813r5_rule'
  tag stig_id: 'WN10-00-000010'
  tag fix_id: 'F-71517r1_fix'
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

  desc "check", "Verify domain-joined systems have a TPM enabled and ready for use.

        For standalone systems, this is NA.

        Virtualization based security, including Credential Guard, currently cannot be
        implemented in virtual desktop implementations (VDI) due to specific supporting
        requirements including a TPM, UEFI with Secure Boot, and the capability to run
        the Hyper-V feature within the virtual desktop.

        For VDIs where the virtual desktop instance is deleted or refreshed upon
        logoff, this is NA.

        Verify the system has a TPM and is ready for use.
        Run \"tpm.msc\".
        Review the sections in the center pane.
        \"Status\" must indicate it has been configured with a message such as \"The
        TPM is ready for use\" or \"The TPM is on and ownership has been taken\".
        TPM Manufacturer Information - Specific Version = 2.0 or 1.2

        If a TPM is not found or is not ready for use, this is a finding.

        NOTE:  The severity level for the requirement will be upgraded to CAT II
        starting January 2020."

  desc "fix", "For standalone systems, this is NA.

        Virtualization based security, including Credential Guard, currently cannot be
        implemented in virtual desktop implementations (VDI) due to specific supporting
        requirements including a TPM, UEFI with Secure Boot, and the capability to run
        the Hyper-V feature within the virtual desktop.

        For VDIs where the virtual desktop instance is deleted or refreshed upon
        logoff, this is NA.

        Ensure domain-joined systems must have a Trusted Platform Module (TPM) that is
        configured for use. (Versions 2.0 or 1.2 support Credential Guard.)

        The TPM must be enabled in the firmware.
        Run \"tpm.msc\" for configuration options in Windows."

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if sys_info.manufacturer == "VMware, Inc."
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63323.' do
      skip 'This is a VDI System; This System is NA for Control V-63323.'
    end
  elsif is_domain == 'WORKGROUP'
    impact 0.0
    describe 'This system is not joined to a domain, therefore this control is Not Applicable' do
      skip 'This system is not joined to a domain, therefore this control is Not Applicable'
    end
  else
    tpm_ready = command('Get-Tpm | select -expand TpmReady').stdout.strip
    tpm_present = command('Get-Tpm | select -expand TpmPresent').stdout.strip
    describe 'Trusted Platform Module (TPM) TpmReady' do
      subject { tpm_ready }
      it { should eq 'True' }
    end
    describe 'Trusted Platform Module (TPM) TpmPresent' do
      subject { tpm_present }
      it { should eq 'True' }
    end
  end
end

