# -*- encoding : utf-8 -*-

control 'V-77083' do
  title "Windows 10 systems must have Unified Extensible Firmware Interface
        (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS."
  desc  "UEFI provides additional security features in comparison to legacy
        BIOS firmware, including Secure Boot. UEFI is required to support additional
        security features in Windows 10, including Virtualization Based Security and
        Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will
        not support these security features."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000015'
  tag gid: 'V-77083'
  tag rid: 'SV-91779r3_rule'
  tag stig_id: 'WN10-00-000015'
  tag fix_id: 'F-83781r1_fix'
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
  desc "check", "For virtual desktop implementations (VDIs) where the virtual
      desktop instance is deleted or refreshed upon logoff, this is NA.

      Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

      Run \"System Information\".

      Under \"System Summary\", if \"BIOS Mode\" does not display \"UEFI\", this is
      finding."
  desc "fix", 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode.'

  if sys_info.manufacturer != 'VMware, Inc.'
    describe 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode' do
      skip 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode'
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-77083.' do
      skip 'This is a VDI System; This System is NA for Control V-77083.'
    end
 end
end

