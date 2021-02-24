# -*- encoding : utf-8 -*-

control 'V-63587' do
  title "The DoD Interoperability Root CA cross-certificates must be installed
        in the Untrusted Certificates Store on unclassified systems."
  desc  "To ensure users do not experience denial of service when performing
        certificate-based authentication to DoD websites due to the system chaining to
        a root other than DoD Root CAs, the DoD Interoperability Root CA
        cross-certificates must be installed in the Untrusted Certificate Store. This
        requirement only applies to unclassified systems."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-PK-000015'
  tag gid: 'V-63587'
  tag rid: 'SV-78077r5_rule'
  tag stig_id: 'WN10-PK-000015'
  tag fix_id: 'F-98441r3_fix'
  tag cci: %w[CCI-000185 CCI-002470]
  tag nist: ['IA-5 (2) (a)', 'SC-23 (5)', 'Rev_4']
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

  desc 'check', "Verify the DoD Interoperability cross-certificates are installed
      on unclassified systems as Untrusted Certificates.

      Run \"PowerShell\" as an administrator.

      Execute the following command:

      Get-ChildItem -Path Cert:Localmachine\\disallowed | Where {$_.Issuer -Like
      \"*DoD Interoperability*\" -and $_.Subject -Like \"*DoD*\"} | FL Subject,
      Issuer, Thumbprint, NotAfter

      If the following certificate \"Subject\", \"Issuer\", and \"Thumbprint\",
      information is not displayed, this is finding.

      If an expired certificate (\"NotAfter\" date) is not listed in the results,
      this is not a finding.


      Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
      Issuer: CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government,
      C=US
      Thumbprint: 22BBE981F0694D246CC1472ED2B021DC8540A22F
      NotAfter: 9/6/2019

      Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
      Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government,
      C=US
      Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
      NotAfter: 1/22/2022

      Alternately use the Certificates MMC snap-in:

      Run \"MMC\".

      Select \"File\", \"Add/Remove Snap-in\".

      Select \"Certificates\", click \"Add\".

      Select \"Computer account\", click \"Next\".

      Select \"Local computer: (the computer this console is running on)\", click
      \"Finish\".

      Click \"OK\".

      Expand \"Certificates\" and navigate to \"Untrusted Certificates >>
      Certificates\".

      For each certificate with \"DoD Root CA…\" under \"Issued To\" and \"DoD
      Interoperability Root CA…\" under \"Issued By\":

      Right-click on the certificate and select \"Open\".

      Select the \"Details\" Tab.

      Scroll to the bottom and select \"Thumbprint\".

      If the certificates below are not listed or the value for the \"Thumbprint\"
      field is not as noted, this is a finding.

      If an expired certificate (\"Valid to\" date) is not listed in the results,
      this is not a finding.

      Issued To: DoD Root CA 2
      Issued By: DoD Interoperability Root CA 1
      Thumbprint: 22BBE981F0694D246CC1472ED2B021DC8540A22F
      Valid to: Friday, September 6, 2019

      Issued To: DoD Root CA 3
      Issued By: DoD Interoperability Root CA 2
      Thumbprint: AC06108CA348CC03B53795C64BF84403C1DBD341
      Valid to: Saturday, January 22, 2022"

  desc 'fix', "Install the DoD Interoperability Root CA cross-certificates on
      unclassified systems.

      Issued To - Issued By - Thumbprint
      DoD Root CA 2 - DoD Interoperability Root CA 1 -
      22BBE981F0694D246CC1472ED2B021DC8540A22F
      DoD Root CA 3 - DoD Interoperability Root CA 2 -
      AC06108CA348CC03B53795C64BF84403C1DBD341

      The certificates can be installed using the InstallRoot tool. The tool and user
      guide are available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx."

  # NOTE:  DoD Root CA 2 - DoD Interoperability Root CA 1 - 22BBE981F0694D246CC1472ED2B021DC8540A22F does not exist on Install Root 5.5

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    dod_certificates = JSON.parse(input('dod_certificates').to_json)
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | Select Subject, Issuer, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' })
    describe 'The DoD Interoperability Root CA cross-certificates are installed' do
      subject { query.params }
      it { should be_in dod_certificates }
    end
  end
end

