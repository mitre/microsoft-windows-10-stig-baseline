control 'SV-220904' do
  title 'The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.'
  desc 'To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is established for server certificates issued from the External CAs. This requirement only applies to unclassified systems.'
  desc 'check', 'Verify the ECA Root CA certificates are installed on unclassified systems as Trusted Root Certification Authorities.

Run "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US
Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
NotAfter: 12/30/2029

Alternately use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates", click "Add".

Select "Computer account", click "Next".

Select "Local computer: (the computer this console is running on)", click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

For each of the ECA Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" Tab.

Scroll to the bottom and select "Thumbprint".

If the ECA Root CA certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

ECA Root CA 4
Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
Valid to: Sunday, December 30, 2029'
  desc 'fix', 'Install the ECA Root CA certificate on unclassified systems.
ECA Root CA 4

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22619r894652_chk'
  tag severity: 'medium'
  tag gid: 'V-220904'
  tag rid: 'SV-220904r958448_rule'
  tag stig_id: 'WN10-PK-000010'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-22608r894327_fix'
  tag 'documentable'
  tag legacy: ['V-63583', 'SV-78073']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    dod_eca_certificates = JSON.parse(input('dod_eca_certificates').to_json)
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\root | Where {$_.Subject -Like "*ECA Root*"} | Select Subject, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' })
    describe 'The ECA Root CA certificates cross-certificates installed' do
      subject { query.params }
      it { should be_in dod_eca_certificates }
    end
   end
end
