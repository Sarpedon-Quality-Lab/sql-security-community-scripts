# Get-SqlSafe.ps1: The Sarpedon SQL Server Security Community Assessment
**Logic & Engine by Andreas Wolter (MCSM)**

Version 2026.2

\---

## What this tool does

`Get-SqlSafe` is a simple, robust PowerShell script that safely scans your SQL Server environment for 25 core vulnerabilities and helps identify high-level security posture indicators for SQL Server.

This Community Edition is designed to:
* Operate under strict least privilege principles (no `sysadmin` rights required where supported).
* Output a clean, visual HTML report.
* Be completely transparent and easy to review (plain-text PowerShell and T-SQL).
* Avoid automatic dependency installation.

<img width="900" height="584" alt="SecurityAssessment_CommunityEdition_Screenshots" src="https://github.com/user-attachments/assets/3402a013-3c86-4055-8b99-275048424873" />

> **Note:** This Community Edition is intended to provide a practical first look at your security posture. It does not replace a full security audit.

\---

## Quick Start

1. Download the repository.
2. Open Windows PowerShell.
3. Unblock the files if they were downloaded from the internet:

```powershell
Unblock-File .\Get-SqlSafe.ps1
```

4. Run the assessment launcher:

```powershell
.\Get-SqlSafe.ps1
```

5. Enter your SQL Server connection details.
6. The generated html-Report opens automatically in the default browser.
7. The report is stored in the `Results` subfolder.

If your system blocks script execution, you may run the script with an explicit execution policy for this process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-SqlSafe.ps1
```

This only allows the script to run in that PowerShell process. It does not unblock files permanently and does not install missing dependencies.

\---

## Contents

* `Get-SqlSafe.ps1` — PowerShell orchestrator and report generator
* `SqlSafe.sql` — T-SQL assessment logic
* `LICENSE.md` — Sarpedon Community License
* `README.md` — Documentation

\---

## Requirements

* Windows PowerShell 5.1 or higher
* Microsoft `SqlServer` PowerShell module
* `Invoke-Sqlcmd` cmdlet
* SQL Server 2012 or newer
* Read-only SQL Server permissions where supported by the target SQL Server version

`Invoke-Sqlcmd` is provided by the Microsoft `SqlServer` PowerShell module.

Get-SqlSafe does not install dependencies automatically.

\---

## PowerShell Dependency: Invoke-Sqlcmd

Get-SqlSafe Community Edition requires the PowerShell cmdlet `Invoke-Sqlcmd`.

To check whether it is available in the current PowerShell session, run:

```powershell
Get-Command Invoke-Sqlcmd
```

If the command is not found, install the Microsoft `SqlServer` PowerShell module.

### Typical Current User installation

Run this from the same PowerShell environment that you use to run Get-SqlSafe:

```powershell
Install-Module SqlServer -Scope CurrentUser
```

Then verify:

```powershell
Get-Module -ListAvailable SqlServer
Import-Module SqlServer
Get-Command Invoke-Sqlcmd
```

### Fresh Windows Server installation

On a fresh Windows Server installation, PowerShell may first ask for the NuGet package provider. If that happens, run:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201
Install-Module SqlServer -Scope CurrentUser
```

If your organization permits non-interactive installation, you may add `-Force` to the `Install-PackageProvider` command to suppress confirmation prompts.

### Administrator-controlled machine-wide installation

For shared admin machines, jump boxes, or controlled server environments, an administrator may prefer a machine-wide installation:

```powershell
Install-Module SqlServer -Scope AllUsers
```

In enterprise environments, install the `SqlServer` module through your organization's approved software deployment process or internal PowerShell repository.

\---

## Troubleshooting Invoke-Sqlcmd

### Installed module, but Invoke-Sqlcmd is still missing

PowerShell modules must be installed in a location visible to the PowerShell session that runs Get-SqlSafe.

First verify what PowerShell can see:

```powershell
Get-Module -ListAvailable SqlServer
Import-Module SqlServer
Get-Command Invoke-Sqlcmd
```

If `Get-Module -ListAvailable SqlServer` returns nothing, but you believe the module was installed, check where PowerShellGet installed it:

```powershell
Get-InstalledModule SqlServer | Format-List Name, Version, InstalledLocation
```

Then inspect the module search path:

```powershell
$env:PSModulePath -split ';'
```

If the installed module location is not under one of the listed module paths, PowerShell may not discover it by name.

Example: if the module was installed under the current user's profile, but the CurrentUser module path is missing from `PSModulePath`, import the module manifest directly:

```powershell
Import-Module "C:\Users\<user>\Documents\WindowsPowerShell\Modules\SqlServer\<version>\SqlServer.psd1" -Force
Get-Command Invoke-Sqlcmd
```

Replace `<user>` and `<version>` with the values shown by `Get-InstalledModule`.

### Windows PowerShell vs PowerShell 7

If you run Get-SqlSafe with `powershell.exe`, you are using Windows PowerShell.

If you installed the module from `pwsh`, you installed it from PowerShell 7 or later. Windows PowerShell may not see the same module location.

Install and verify the module in the same PowerShell environment that will run Get-SqlSafe.

\---

## Required SQL Server Permissions

The assessment is designed to run with least privilege using a dedicated login where supported by the SQL Server version.

Recommended practices:

* Use a dedicated assessment login.
* Do not use personal or shared administrator accounts.
* Grant only the permissions needed for the target SQL Server version.
* Remove the assessment login after use if it is not part of an approved recurring process.

The examples below use `SqlAssessmentReader` as the assessment principal.

### SQL Server 2022+

```sql
GRANT VIEW SERVER SECURITY STATE TO SqlAssessmentReader;
GRANT VIEW ANY SECURITY DEFINITION TO SqlAssessmentReader;
GRANT VIEW SERVER PERFORMANCE STATE TO SqlAssessmentReader;
GRANT CONNECT ANY DATABASE TO SqlAssessmentReader;

ALTER SERVER ROLE securityadmin ADD MEMBER SqlAssessmentReader;

DENY CREATE LOGIN TO SqlAssessmentReader;
DENY ALTER ANY LOGIN TO SqlAssessmentReader;
```

### SQL Server 2014–2019

```sql
GRANT VIEW SERVER STATE TO SqlAssessmentReader;
GRANT VIEW ANY DEFINITION TO SqlAssessmentReader;
GRANT CONNECT ANY DATABASE TO SqlAssessmentReader;

ALTER SERVER ROLE securityadmin ADD MEMBER SqlAssessmentReader;

DENY ALTER ANY LOGIN TO SqlAssessmentReader;
```

### SQL Server 2012

```sql
ALTER SERVER ROLE sysadmin ADD MEMBER SqlAssessmentReader;
```

SQL Server 2012 has fewer granular metadata visibility options. Review this requirement carefully before running the Community Edition against SQL Server 2012 systems.

\---

## Enterprise Usage \& Trust

This tool is distributed as plain-text PowerShell and SQL files so organizations can review it according to internal security and change-control processes.

### Behavior Summary

Get-SqlSafe Community Edition:

* runs locally from the extracted folder
* connects to SQL Server using Windows or SQL authentication
* executes the included local SQL assessment file
* validates the SQL file using a SHA256 hash
* writes a local HTML report to the `Results` folder
* does not install PowerShell modules automatically
* does not modify SQL Server configuration as part of the assessment

### Recommended enterprise process

#### 1\. Review

Review the PowerShell and T-SQL files before running them in production or customer environments.

#### 2\. Verify file integrity

```powershell
Get-FileHash .\Get-SqlSafe.ps1 -Algorithm SHA256
Get-FileHash .\SqlSafe.sql -Algorithm SHA256
```

#### 3\. Unblock downloaded files

```powershell
Unblock-File .\Get-SqlSafe.ps1
Unblock-File .\SqlSafe.sql
```

#### 4\. Confirm PowerShell dependency

```powershell
Get-Command Invoke-Sqlcmd
```

If the command is missing, install the Microsoft `SqlServer` PowerShell module using your organization's approved process.

#### 5\. Test first

Run the assessment against a non-production SQL Server instance before using it in a production environment.

#### 6\. Re-sign internally if required

If your organization enforces `AllSigned`, sign the approved PowerShell file with your internal code-signing certificate after review.

Example only:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Get-SqlSafe.ps1 -Certificate $cert
```

Follow your internal process for code review, signing, packaging, and deployment.

\---

## Output

The tool generates a local HTML report in the `Results` folder.

The report may contain environment-specific security details, including server configuration, permissions, principals, role memberships, and assessment findings.

Handle generated reports according to your organization's data handling and confidentiality requirements.

\---

## Notes

* The SQL file must not be modified if hash validation is enforced.
* Output may contain sensitive environment-specific information.
* The tool identifies indicators of risk; it does not enforce configuration changes.
* Some checks may require permissions that are not available on older SQL Server versions without elevated access.
* Community Edition focuses on high-level indicators and does not represent a complete security audit.


\---

## Beyond the Baseline: Need the Complete Picture?
`Get-SqlSafe.ps1` covers 25 essential baseline checks. However, enterprise environments require deeper architectural scrutiny. 

The full **Sarpedon SQL Server Security Assessment** executes up to **140+ advanced architectural checks**, including:
* Deep database-level configuration audits
* OS-level and Backup security reviews
* Advanced Account Attribution & lateral movement mapping

[Explore Full-Scope Security Assessments at Sarpedon Quality Lab](https://sarpedonqualitylab.us/sql-server-security-assessment/)


\---

## License

This project is distributed under the Sarpedon Community License.

Use is permitted for internal business or personal purposes. Redistribution, white-labeling, or commercial resale of modified versions or generated reports is restricted by the license terms.

See `LICENSE.md` for the full license text.

\---

## Disclaimer

This tool is provided "as is", without warranty of any kind.

It identifies indicators of risk and does not replace a full security audit, penetration test, compliance assessment, or professional security review.

Use at your own risk.

