# -*- encoding : utf-8 -*-

control 'V-63589' do
  title "The US DoD CCEB Interoperability Root CA cross-certificates must be
        installed in the Untrusted Certificates Store on unclassified systems."
  desc  "To ensure users do not experience denial of service when performing
        certificate-based authentication to DoD websites due to the system chaining to
        a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA
        cross-certificates must be installed in the Untrusted Certificate Store. This
        requirement only applies to unclassified systems."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-PK-000020'
  tag gid: 'V-63589'
  tag rid: 'SV-78079r4_rule'
  tag stig_id: 'WN10-PK-000020'
  tag fix_id: 'F-98443r3_fix'
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

  desc 'check', "Verify the US DoD CCEB Interoperability Root CA cross-certificate
      is installed on unclassified systems as an Untrusted Certificate.

      Run \"PowerShell\" as an administrator.

      Execute the following command:

      Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like \"*CCEB
      Interoperability*\" | FL Subject, Issuer, Thumbprint, NotAfter

      If the following certificate \"Subject\", \"Issuer\", and \"Thumbprint\",
      information is not displayed, this is finding.

      If an expired certificate (\"NotAfter\" date) is not listed in the results,
      this is not a finding.

      Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
      Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.
      Government, C=US
      Thumbprint: 929BF3196896994C0A201DF4A5B71F603FEFBF2E
      NotAfter: 9/27/2019

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

      For each certificate with \"US DoD CCEB Interoperability Root CA …\" under
      \"Issued By\":

      Right-click on the certificate and select \"Open\".

      Select the \"Details\" tab.

      Scroll to the bottom and select \"Thumbprint\".

      If the certificate below is not listed or the value for the \"Thumbprint\"
      field is not as noted, this is a finding.

      If an expired certificate (\"Valid to\" date) is not listed in the results,
      this is not a finding.

      Issued To: DoD Root CA 3
      Issuer by: US DoD CCEB Interoperability Root CA 2
      Thumbprint: 929BF3196896994C0A201DF4A5B71F603FEFBF2E
      Valid: Friday, September 27, 2019"

  desc 'fix', "Install the US DoD CCEB Interoperability Root CA cross-certificate
      on unclassified systems.

      Issued To - Issued By - Thumbprint
      DoD Root CA 3 - US DoD CCEB Interoperability Root CA 2 -
      929BF3196896994C0A201DF4A5B71F603FEFBF2E

      The certificates can be installed using the InstallRoot tool. The tool and user
      guide are available on IASE at http://iase.disa.mil/pki-pke/Pages/tools.aspx."

  ref 'http://iase.disa.mil/pki-pke/Pages/tools.aspx'

  dod_cceb_certificates = JSON.parse(input('dod_cceb_certificates').to_json)

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\disallowed | Where {$_.Issuer -Like "*DoD CCEB Interoperability*" -and $_.Subject -Like "*DoD*"} | Select Subject, Issuer, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' })
    describe 'The DoD CCEB Interoperability CA cross-certificates installed' do
      subject { query.params }
      it { should be_in dod_cceb_certificates }
    end
  end
end

