# microsoft-windows-10-stig-baseline
InSpec profile to validate the secure configuration of Microsoft Windows 10, against [DISA](https://iase.disa.mil/stigs/) Microsoft Windows 10 Security Technical Implementation Guide (STIG) Version 1, Release 20.

## Getting Started
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
- set to either the string "true" or "false"
sensitive_system: false

- add your usernames as needed
backup_operators: (NULL)

- add your usernames as needed
administrators: (NULL)

- add your usernames as needed
hyper_v_admin: (NULL)

- add your AV Software Product to this list
av_approved_software: <List of AV Software>
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/microsoft-windows-10-stig-baseline/archive/master.tar.gz --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-windows-10-stig-baseline
inspec archive microsoft-windows-10-stig-baseline
inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd microsoft-windows-10-stig-baseline
git pull
cd ..
inspec archive microsoft-windows-10-stig-baseline --overwrite
inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Aaron Lippold, Mitre - [aaronlippold](https://github.com/aaronlippold)
* Jared Burns, VMware.Inc - [burnsjared0415](https://github.com/burnsjared0415)

## Special Thanks
* Shivani Karikar, DIFZ - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/microsoft-windows-10-stig-baseline/issues/new).

## Background design of the profile

| Input | Description | Type | STIG-Compliant Default | Required | Allowed Values |
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

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx