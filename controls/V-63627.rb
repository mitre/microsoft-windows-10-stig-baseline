# -*- encoding : utf-8 -*-

control 'V-63627' do
  title "Systems must at least attempt device authentication using
        certificates."
  desc  "Using certificates to authenticate devices to the domain provides
        increased security over passwords.  By default systems will attempt to
        authenticate using certificates and fall back to passwords if the domain
        controller does not support certificates for devices.  This may also be
        configured to always use certificates for device authentication."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000115'
  tag gid: 'V-63627'
  tag rid: 'SV-78117r1_rule'
  tag stig_id: 'WN10-CC-000115'
  tag fix_id: 'F-69557r1_fix'
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
  
  desc "check", "This requirement is applicable to domain-joined systems, for
        standalone systems this is NA.

        The default behavior for \"Support device authentication using certificate\" is
        \"Automatic\".

        If the registry value name below does not exist, this is not a finding.

        If it exists and is configured with a value of \"1\", this is not a finding.

        If it exists and is configured with a value of \"0\", this is a finding.

        Registry Hive:  HKEY_LOCAL_MACHINE
        Registry Path:
        \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

        Value Name:  DevicePKInitEnabled
        Value Type:  REG_DWORD
        Value:  1 (or if the Value Name does not exist)"

  desc "fix", "This requirement is applicable to domain-joined systems, for
        standalone systems this is NA.

        The default behavior for \"Support device authentication using certificate\" is
        \"Automatic\".

        If this needs to be corrected, configured the policy value for Computer
        Configuration >> Administrative Templates >> System >> Kerberos >> \"Support
        device authentication using certificate\" to \"Not Configured or \"Enabled\"
        with either option selected in \"Device authentication behavior using
        certificate:\"."

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
      it { should have_property 'DevicePKInitEnabled' }
      its('DevicePKInitEnabled') { should cmp 1 }
    end
  end
end

