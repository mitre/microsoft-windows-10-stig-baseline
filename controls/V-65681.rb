# -*- encoding : utf-8 -*-

control 'V-65681' do
  title 'Windows Update must not obtain updates from other PCs on the Internet.'
  desc  "Windows 10 allows Windows Update to obtain updates from additional
        sources instead of Microsoft. In addition to Microsoft, updates can be obtained
        from and sent to PCs on the local network as well as on the Internet. This is
        part of the Windows Update trusted process, however to minimize outside
        exposure, obtaining updates from or sending to systems on the Internet must be
        prevented."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-CC-000206'
  tag gid: 'V-65681'
  tag rid: 'SV-80171r3_rule'
  tag stig_id: 'WN10-CC-000206'
  tag fix_id: 'F-83251r4_fix'
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization\\

      Value Name: DODownloadMode

      Value Type: REG_DWORD
      Value: 0x00000000 (0) - No peering (HTTP Only)
      0x00000001 (1) - Peers on same NAT only (LAN)
      0x00000002 (2) - Local Network / Private group peering (Group)
      0x00000063 (99) - Simple download mode, no peering (Simple)
      0x00000064 (100) - Bypass mode, Delivery Optimization not used (Bypass)

      A value of 0x00000003 (3), Internet, is a finding.

      v1507 LTSB:
      Domain joined systems:
      Verify the registry value above.
      If the value is not 0x00000000 (0) or 0x00000001 (1), this is a finding.

      Standalone systems (configured in Settings):
      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\\

      Value Name: DODownloadMode

      Value Type: REG_DWORD
      Value: 0x00000000 (0) - Off
      0x00000001 (1) - LAN"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Delivery Optimization >>
      \"Download Mode\" to \"Enabled\" with any option except \"Internet\" selected.

      Acceptable selections include:
      Bypass (100)
      Group (2)
      HTTP only (0)
      LAN (1)
      Simple (99)

      v1507 (LTSB) does not include this group policy setting locally. For domain
      joined systems, configure through domain group policy as \"HTTP only (0)\" or
      \"Lan (1)\". Standalone systems configure using Settings >> Update & Security
      >> Windows Update >> Advanced Options >> \"Choose how updates are delivered\"
      with either \"Off\" or \"PCs on my local network\" selected."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId == '1507'
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 0 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 1 }
      end
    end
  else
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 0 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 2 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 99 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config') do
        it { should have_property 'DODownloadMode' }
        its('DODownloadMode') { should cmp 100 }
      end
    end
  end
end

