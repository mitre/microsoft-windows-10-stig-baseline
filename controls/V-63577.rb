# -*- encoding : utf-8 -*-

control 'V-63577' do
  title "Hardened UNC Paths must be defined to require mutual authentication
        and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares."
  desc  "Additional security requirements are applied to Universal Naming
        Convention (UNC) paths specified in Hardened UNC paths before allowing access
        them.  This aids in preventing tampering with or spoofing of connections to
        these paths."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000050'
  tag gid: 'V-63577'
  tag rid: 'SV-78067r1_rule'
  tag stig_id: 'WN10-CC-000050'
  tag fix_id: 'F-69507r1_fix'
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

  desc 'check', "This requirement is applicable to domain-joined systems, for
      standalone systems this is NA.

      If the following registry values do not exist or are not configured as
      specified, this is a finding.

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths\\

      Value Name:  \\\\*\\NETLOGON
      Value Type:  REG_SZ
      Value:  RequireMutualAuthentication=1, RequireIntegrity=1

      Value Name:  \\\\*\\SYSVOL
      Value Type:  REG_SZ
      Value:  RequireMutualAuthentication=1, RequireIntegrity=1

      Additional entries would not be a finding."

  desc 'fix', "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> Network Provider >> \"Hardened UNC
      Paths\" to \"Enabled\" with at least the following configured in \"Hardened UNC
      Paths:\" (click the \"Show\" button to display).

      Value Name: \\\\*\\SYSVOL
      Value: RequireMutualAuthentication=1, RequireIntegrity=1

      Value Name: \\\\*\\NETLOGON
      Value: RequireMutualAuthentication=1, RequireIntegrity=1"

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip
  keyvalue_netlogon = '\\\\*\\NETLOGON'
  keyvalue_sysvol = '\\\\*\\SYSVOL'

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  elsif
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
      it { should have_property keyvalue_sysvol.gsub('\\', '\\\\\\\\') }
      its (keyvalue_sysvol.gsub('\\', '\\\\\\\\')) { should cmp 'RequireMutualAuthentication=1, RequireIntegrity=1'}
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
      it { should have_property keyvalue_netlogon.gsub('\\', '\\\\\\\\') }
      its (keyvalue_netlogon.gsub('\\', '\\\\\\\\')) { should cmp 'RequireMutualAuthentication=1, RequireIntegrity=1'}
    end
  end
end

