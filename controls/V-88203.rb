# -*- encoding : utf-8 -*-

control 'V-88203' do
  title "OneDrive must only allow synchronizing of accounts for DoD
        organization instances."
  desc  "OneDrive provides access to external services for data storage, which
        must be restricted to authorized instances if enabled. Configuring this setting
        will restrict synchronizing of OneDrive accounts to DoD organization instances."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000360'
  tag gid: 'V-88203'
  tag rid: 'SV-98853r2_rule'
  tag stig_id: 'WN10-CC-000360'
  tag fix_id: 'F-94945r4_fix'
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
  desc "check", "If the organization is using a DoD instance of OneDrive, verify
      synchronizing is only allowed to the organization's DoD instance.

      If the organization does not have an instance of OneDrive, verify this is
      configured with the noted dummy entry to prevent synchronizing with other
      instances.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\OneDrive\\AllowTenantList\\

      Value Name: Organization's Tenant GUID

      Value Type: REG_SZ
      Value: Organization's Tenant GUID

      If the organization does not have an instance of OneDrive the Value Name and
      Value must be 1111-2222-3333-4444, if not this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> OneDrive >> \"Allow syncing OneDrive accounts for
      only specific organizations\", with the Tenant GUID of the organization's DoD
      instance in the format 1111-2222-3333-4444.

      If the organization does not have an instance of OneDrive, configure the Tenant
      GUID with \"1111-2222-3333-4444\".

      Group policy files for OneDrive are located on a system with OneDrive in
      \"%localappdata%\\Microsoft\\OneDrive\\BuildNumber\\adm\\\".

      Copy the OneDrive.admx and .adml files to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList') do
    it { should have_property input('onedrive_tenant_guid') }
    its(input('onedrive_tenant_guid')) { should cmp input('onedrive_tenant_guid') }
  end
end