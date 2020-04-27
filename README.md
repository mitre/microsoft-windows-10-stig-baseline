# microsoft-windows-10-stig-baseline

InSpec profile to validate the secure configuration of Microsoft Windows 10, against DISA's Microsoft Windows 10 Security Technical Implementation Guide (STIG) Version 1, Release 20.

## Getting Started

It is intended and recommended that InSpec run this profile from a "runner" host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over winrm.

For the best security of the runner, always install on the runner the latest version of InSpec and supporting Ruby language components.

Latest versions and installation options are available at the InSpec site.

## Required Inputs **_prior_** to running the profile

For the best results with your system, we _highly_ suggest that you adjust the values of these profile inputs prior to running the profile.

Many of the inputs have good defaults but some must be set my the end-user.

### Please review and set these `inputs` as best fits your target

The profile _will_ run without updating these values but you will get the _best_ results if you provide the profile with the following data.

- sensitive_system (false) - set to either the string `"true"` or `"false"`
- domain_sid (NULL) - set to your Domain SID as a string in the form `xxxxxxxxxx-xxxxxxx-xxxxxxxxxx`
- backup_operators (NULL) - add your usernames as needed
- administrators (NULL) - add your usernames as needed
- hyper_v_admin (NULL) - add your usernames as needed
- av_approved_software(List of AV Software) - add your AV Software Product to this list

## Using your `input` data with the profile

Use the `inputs.example.yml` file as a starting point, and use the `--input-files` flag _or_ set the input via the `CLI` using the `--input` flag.

See <https://www.inspec.io/docs/reference/inputs/> for further information.

## Running your profile

To run the profile:

1. Install InSpec on your runner
2. Ensure you have WinRM https access to your traget
3. Ensure you have the 'Admin User' and 'Admin Password' for your system.
4. From your 'InSpec Runner',
   a. if you are using an `input-file`:

   - `inspec exec https://github.com/mitre/microsoft-windows-10-stig-baseline.git -t winrm://<user>@<host> --password <your password> --input-files <your-input-yml> --reporter cli json:<your-results-filename>.json`

   b. if you are using `cli` inputs:

   - `inspec exec https://github.com/mitre/microsoft-windows-10-stig-baseline.git -t winrm://<user>@<host> --password <your password> --reporter cli json:<your-results-filename>.json --input sensitive_system='true' domain_sid='xxxxxxxxxxxxxxxxxxx'`

## Reviewing your Results

### Reviewing Single Runs

The **recommended** review format for for **security review** or **accrediation discussions** or the Security Engineer is the `JSON` results format using the InSpec `JSON` reporter and the MITRE open-souce `heimdall-lite` viewer. You can use heimdall-lite any-time anywhere from: <https://heimdall-lite.mitre.org>.

Heimdall-Lite is a Single Page Client Side JavaScript app that runs completely in your browser and was designed to help make reviewing, sorting and sharing your InSpec results easier.

### Reviewing Large amounts of Runs

If you are scanning large numbers of systems - we recommend you use the [MITRE Heimdall Enterprise Sever](https://heimdall.mitre.org/) which ....

## Inputs used in the profile

+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|             Input Name             |               Value               |                                     Description                                     | Required | Allowed Values |   Type  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|        av_approved_software        |         Windows Defender,         |                             This is a list of Approved                              |     X    |     String     |  Array  |
|                                    | Mcafee Host Intrusion Prevention, |                                 Anti-Virus Software                                 |          |                |         |
|                                    |     Mcafee Endpoint Security,     |                                                                                     |          |                |         |
|                                    |            Mcafee Agent           |                                                                                     |          |                |         |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|             domain_sid             |                NULL               |                              This is for the Domain SID                             |     X    |     String     |  String |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|         local_administrator        |                NULL               |                             Local Administrator Account                             |     X    |     String     |  String |
|                                    |                                   |                                  on Windows Server                                  |          |                |         |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          bitlocker_pin_len         |                 6                 |                     The minimum length for the BitLocker Pin [6]                    |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|            min_pass_len            |                 14                |                      Sets the minimum length of passwords [14]                      |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|       enable_pass_complexity       |                 1                 |               If windows should enforce password complexity (0/1) [1]               |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|            min_pass_age            |                 1                 |                       Sets the minimum age for a password [1]                       |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|            max_pass_age            |                 60                |                       Sets the maximum age for a password [60]                      |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|           pass_lock_time           |                 15                |              Sets the number of min before a session is locked out [15]             |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|           pass_hist_size           |                 24                |             Number of passwords remembered in the password history [24]             |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          max_pass_lockout          |                 3                 | Account lockout threshold is recommended to be 3 or less invalid logon attempts [3] |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          max_inactive_days         |                 35                |             Max number of days an account is allowed to be inactive [35]            |     X    |   Any Integer  | Numeric |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|           LegalNoticeText          |          see 'inspec.yml'         |                     The default full banner text for the system                     |     X    |     String     |  String |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|         LegalNoticeCaption         |          see 'inspec.yml'         |                     The default short banner text for the system                    |     X    |     String     |  String |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          dod_certificates          |          see 'inspec.yml'         |                    List of DoD Interoperability Root Certificates                   |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|        dod_cceb_certificates       |          see 'inspec.yml'         |                              List of CCEB Certificates                              |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|        dod_eca_certificates        |          see 'inspec.yml'         |                    List of ECA Root CA certificates Certificates                    |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|      dod_trusted_certificates      |          see 'inspec.yml'         |                   List of DOD Trusted CA certificates Certificates                  |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          sensitive_system          |               False               |                  Set flag to true if the target system is sensitive                 |     X    |     String     |  String |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          backup_operators          |                NULL               |             List of authorized users in the local Backup Operators Group            |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|           administrators           |                NULL               |              List of authorized users in the local Administrators group             |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|            hyper_v_admin           |                NULL               |                    List of authorized users in the Hyper-V Group                    |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|         reg_software_perms         |          see 'inspec.yml'         |                  The required Registry Software Permission Settings                 |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|         reg_security_perms         |          see 'inspec.yml'         |                 The required Registry Security Permissions Settings                 |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|          reg_system_perms          |          see 'inspec.yml'         |                  The required Registry System Permissions Settings                  |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|        c_folder_permissions        |          see 'inspec.yml'         |                       Default Permissions for C:\ Folder on OS                      |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|    c_windows_folder_permissions    |          see 'inspec.yml'         |                   Default Permissions for C:\Windows Folder on OS                   |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
| c_program_files_folder_permissions |          see 'inspec.yml'         |                   Default Permissions for C:\Windows Folder on OS                   |     X    |     String     |  Array  |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+
|        onedrive_tenant_guid        |                NULL               |                    This is the OneDrive GUID for the Organization                   |     X    |     String     |  String |
+------------------------------------+-----------------------------------+-------------------------------------------------------------------------------------+----------+----------------+---------+

## Contribution

Please feel free to submit a PR or Issue on the board. To get an idea of our style and best practices, please see our InSpec training at:

- https://mitre-inspec-developer.netlify.com/
- https://mitre-inspec-advanced-developer.netlify.com/

## Useful References

- <https://lonesysadmin.net/2017/08/10/fix-winrm-client-issues/>
- <https://www.hurryupandwait.io/blog/understanding-and-troubleshooting-winrm-connection-and-authentication-a-thrill-seekers-guide-to-adventure>

### NOTICE

© 2019 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
