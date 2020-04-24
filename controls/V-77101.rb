# -*- encoding : utf-8 -*-

control 'V-77101' do
  title 'Windows 10 Exploit Protection system-level mitigation, Validate exception chains (SEHOP), must be on.'
  desc  "Exploit protection in Windows 10 enables mitigations against potential
        threats at the system and application level.  Several mitigations, including
        \"Validate exception chains (SEHOP)\", are enabled by default at the system
        level. SEHOP (structured exception handling overwrite protection) ensures the
        integrity of an exception chain during exception dispatch. If this is turned
        off, Windows 10 may be subject to various exploits."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-EP-000050'
  tag gid: 'V-77101'
  tag rid: 'SV-91797r3_rule'
  tag stig_id: 'WN10-EP-000050'
  tag fix_id: 'F-86723r2_fix'
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
  desc 'check', "This is NA prior to v1709 of Windows 10.

      This is applicable to unclassified systems, for other systems this is NA.

      The default configuration in Exploit Protection is \"On by default\" which
      meets this requirement.  The PowerShell query results for this show as
      \"NOTSET\".

      Run \"Windows PowerShell\" with elevated privileges (run as administrator).

      Enter \"Get-ProcessMitigation -System\".

      If the status of \"SEHOP: Enable\" is \"OFF\", this is a finding.

      Values that would not be a finding include:
      ON
      NOTSET (Default configuration)"

  desc 'fix', "Ensure Exploit Protection system-level mitigation, \"Validate
      exception chains (SEHOP)\", is turned on. The default configuration in Exploit
      Protection is \"On by default\" which meets this requirement.

      Open \"Windows Defender Security Center\".

      Select \"App & browser control\".

      Select \"Exploit protection settings\".

      Under \"System settings\", configure \"Validate exception chains (SEHOP)\" to
      \"On by default\" or \"Use default (<On>)\".

      The STIG package includes a DoD EP XML file in the \"Supporting Files\" folder
      for configuring application mitigations defined in the STIG.  This can also be
      modified to explicitly enforce the system level requirements.  Adding the
      following to the XML file will explicitly turn SEHOP on (other system level EP
      requirements can be combined under <SystemConfig>):

      <SystemConfig>
        <SEHOP Enable=\"true\"></SEHOP>
      </SystemConfig>

      The XML file is applied with the group policy setting Computer Configuration >>
      Administrative Settings >> Windows Components >> Windows Defender Exploit Guard
      >> Exploit Protection >> \"Use a common set of exploit protection settings\"
      configured to \"Enabled\" with file name and location defined under
      \"Options:\". It is recommended the file be in a read-only network location."

  if input('sensitive_system') == 'true' || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  elsif registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId < '1709'
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1709.' do
      skip 'This STIG does not apply to Prior Versions before 1709.'
    end
  else
   sehop = json( command: 'Get-ProcessMitigation -System | Select SEHOP | ConvertTo-Json').params
     describe 'SEHOP is required to be enabled on System' do
       subject { sehop }
       its(['Enable']) { should_not eq '2' }
    end
  end
end