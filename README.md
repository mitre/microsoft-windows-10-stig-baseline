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


| Input                       | Description                                                                                                                                                      | Type               | Default                                                                                    | Required | Allowed Values                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------ | -------- | ----------------------------- |
| av_approved_software        | List of organizationally approved AV Software                                                                                                                    | Array              | Windows Defender, McAfee Host Intrusion Prevention, McAfee Endpoint Security, McAfee Agent | x        | Any String                    |
| bitlocker_pin_len           | The minimum length for the BitLocker Pin                                                                                                                         | Number             | 6                                                                                          | x        | Any Integer                   |
| min_pass_len                | Minimum length of system passwords                                                                                                                               | Number             | 14                                                                                         | x        | Any Integer                   |
| enable_pass_complexity      | If windows should enforce password complexity                                                                                                                    | Number             | 1                                                                                          | x        | 0 or 1                        |
| min_pass_age                | Defines the tested minimum password age for the system in days                                                                                                   | Number             | 1                                                                                          | x        | Any Integer                   |
| max_pass_age                | Defined the tested maximum age for a password on the system in days                                                                                              | Number             | 60                                                                                         | x        | Any Integer                   |
| pass_lock_time              | Sets the number of min before a session is locked out on the system                                                                                              | Number             | 15                                                                                         | x        | Any Integer                   |
| pass_hist_size              | Defines the number of passwords that are remembered in the password history for the system                                                                       | Number             | 24                                                                                         | x        | Any Integer                   |
| max_pass_lockout            | Sets the maximum threshold for invalid login attempts to the system                                                                                              | Number             | 3                                                                                          | x        | Any Integer                   |
| max_inactive_days           | Defines the number of days an account on the system is allowed to be inactive                                                                                    | Number             | 35                                                                                         | x        | Any Integer                   |
| sensitive_system            | Defines if the system is considered Sensitive by the organization                                                                                                | String             | 'false'                                                                                    | x        | 'true' or 'false'             |
| backup_operators            | The list of usernames that are allowed in the local Backup Operators Group                                                                                       | Array              | NULL                                                                                       |          | List of LOCAL usernames       |
| administrators              | The list of usernames that are allowed in the local Administrators Group                                                                                         | Array              | NULL                                                                                       |          | List of LOCAL usernames       |
| hyper_v_admin               | The list of usernames that are allowed in the local Hyper-V Group                                                                                                | Array              | NULL                                                                                       |          | List of LOCAL usernames       |
| LegalNoticeText             | The default full banner text for the system                                                                                                                      | String             | see `inspec.yml`                                                                           | x        | Any block of text             |
| LegalNoticeCaption          | The default short banner text for the system                                                                                                                     | String             | see `inspec.yml`                                                                           | x        | Any block of text             |
| dod_cceb_certificates       | List of approved DoD CCEB Interoperability CA Root Certificates                                                                                                  | Array of Hashes    | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| dod_certificates            | List of approved DoD Interoperability Root Certificates                                                                                                          | Array of Hashes    | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| dod_eca_certificates        | List of approved ECA Root CA certificates Certificates                                                                                                           | Array of Hashes    | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| dod_trusted_certificates    | List of approved ECA Root CA certificates Certificates                                                                                                           | Array of Hashes    | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| c_windows_permissions       | Permission set allowed for the `C:\Windows` folder as returned by the `something --<flags here>` command                                                         | Array String Block | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| c_permissions               | Permission set allowed for the `C:\` folder as returned by the `something --<flags here>` command | Array String Block | see `inspec.yml` | x | see `inspec.yml` |
| c_program_files_permissions | Permission set allowed for the Windows `C:\Program Files` folder as returned by the `something --<flags here>` command                                           | Array String Block | see `inspec.yml`                                                                           | x        | see `inspec.yml`              |
| reg_software_perms          | The allowed registry Software Permission Settings                                                                                                                | Array              | see `inspec.yml`                                                                           | x        | Any valid registry key        |
| reg_security_perms          | The allowed registry Security Permission Settings                                                                                                                | Array              | see `inspec.yml`                                                                           | x        | Any valid registry key        |
| reg_system_perms            | The allowed registry System Permission Settings                                                                                                                  | Array              | see `inspec.yml`                                                                           | x        | Any valid registry key        |
| onedrive_tenant_guid        | This is the OneDrive GUID for the Organization Settings                                                                                                                  | String             | see `inspec.yml`                                                                           | x        | Any String        |


## Contribution

Please feel free to submit a PR or Issue on the board. To get an idea of our style and best practices, please see our InSpec training at:

- The MITRE InSpec Team
- Jared Burns, VMware.Inc

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
