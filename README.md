# Get-SqlSafe.ps1: The Sarpedon SQL Server Security Community Assessment

**Logic & Engine by Andreas Wolter (MCSM)**  
Version 2026.3

A standalone PowerShell-based SQL Server security assessment collector that gathers high-level security indicators from a SQL Server instance and generates a local HTML report.

> **Note:** This Community Edition identifies indicators of risk. It is not a full security audit, penetration test, compliance assessment, or guarantee of security.

---

## What this tool does

`Get-SqlSafe.ps1` is a simple, reviewable PowerShell script that helps identify high-level SQL Server security posture indicators. It focuses on common security-relevant areas such as authentication, privileged access, server-level permissions, risky configuration, audit visibility, ownership risks, and orphaned accounts.

This Community Edition is designed to:

* Operate under least privilege principles where supported by the target SQL Server version.
* Output a clean, visual local HTML report.
* Be transparent and easy to review as plain-text PowerShell with embedded T-SQL.
* Avoid automatic dependency installation.
* Run without the Microsoft `SqlServer` PowerShell module or `Invoke-Sqlcmd`.
* Support both GUI-based and console-based execution.

<img width="900" height="584" alt="SecurityAssessment_CommunityEdition_Screenshots" src="https://github.com/user-attachments/assets/3402a013-3c86-4055-8b99-275048424873" />

---

## What Changed in 2026.3

Version 2026.3 is a significant update from the 2026.2 public release:

* The assessment SQL is now embedded in the PowerShell script, removing the former external file dependency on `SqlSafe.sql`.
* The `Invoke-Sqlcmd` / Microsoft `SqlServer` PowerShell module dependency was removed.
* SQL execution now uses .NET `System.Data.SqlClient`.
* Console mode and optional report launch control were added to better support automation-friendly execution, controlled endpoints, and EDR/XDR-controlled environments where UI prompts or automatic browser launch may be restricted.
* Optional run logging was added.
* Alternate Windows credential relaunch support was added.
* The GUI connection test now also checks and displays the permissions of the connected SQL Server principal.
<img width="500" height="402" alt="image" src="https://github.com/user-attachments/assets/90918bd2-e522-41de-a078-a4b6974556a5" />

* Additional checks and refined rule logic were added, including improved handling for sessions using NTLM.

Upgrade note: if you used an earlier version, replace the previous script package with `Get-SqlSafe.ps1`. The separate `SqlSafe.sql` file should be removed because it is no longer used.

See `CHANGELOG.md` for the public changelog summary.

---

## Contents

The public Community Edition package contains:

* `Get-SqlSafe.ps1` — standalone PowerShell collector, embedded SQL assessment logic, and report generator
* `README.md` — usage documentation
* `CHANGELOG.md` — public release summary
* `LICENSE.md` — Sarpedon Community License

Generated reports and logs are written to:

```text
.\Results
```

The public Community Edition package does not require a separate SQL file.

---

## Requirements

* Windows PowerShell 5.1
* Windows operating system with .NET Framework support
* Network access to the target SQL Server instance
* SQL Server 2012 or newer
* Permissions sufficient to read the assessed security metadata

No PowerShell module installation is required for SQL execution in this version.

---

## Quick Start - GUI Mode

1. Download the repository or release package.
2. Open Windows PowerShell.
3. Unblock the script if it was downloaded from the internet:

```powershell
Unblock-File .\Get-SqlSafe.ps1
```

4. Run the assessment:

```powershell
.\Get-SqlSafe.ps1
```

5. Enter your SQL Server connection details.
6. Optionally test the connection and permissions.
7. Start the assessment.
8. The generated HTML report is written to the `Results` subfolder and opens automatically unless report launch is disabled.

If your system blocks script execution, you may run the script with an explicit execution policy for this PowerShell process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-SqlSafe.ps1
```

This only allows the script to run in that PowerShell process. It does not unblock files permanently and does not install dependencies.

---

## Quick Start - Console Mode

Supplying `-SqlInstance` automatically runs the script in console mode.

Windows authentication:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001" -NoAutoOpenReport
```

SQL authentication:

```powershell
$pwd = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001" -Auth SQL -SqlUser "assessment_user" -SqlPass $pwd -NoAutoOpenReport
```

Mandatory encryption with trusted server certificate:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001" -Encrypt Mandatory -TrustServerCert -NoAutoOpenReport
```

Write a run log:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001" -WriteLog -NoAutoOpenReport
```

Console mode and `-NoAutoOpenReport` are useful for controlled endpoints, automation-friendly execution, and EDR/XDR-controlled environments where UI prompts or automatic browser launch may be restricted.

---

## Parameters

`-NoAutoOpenReport`

Prevents the generated HTML report from opening automatically.

`-ConsoleOnly`

Runs without the WPF dialog. Aliases: `-NoUI`, `-NonInteractive`.

`-SqlInstance`

Target SQL Server instance. Supplying this parameter enables console mode.

`-Auth`

Authentication method. Valid values:

```text
Windows
SQL
```

Default is `Windows`.

`-SqlUser`

SQL login name. Required when `-Auth SQL` is used.

`-SqlPass`

SQL login password as a `SecureString`. If omitted for SQL authentication, the script prompts interactively.

`-Encrypt`

Connection encryption behavior. Valid values:

```text
Optional
Mandatory
```

Default is `Optional`.

`-TrustServerCert`

Trusts the SQL Server certificate without certificate-chain validation.

`-WindowsCredential`

Relaunches the assessment under an alternate Windows account. Only valid with Windows authentication and requires `-SqlInstance`.

`-WriteLog`

Writes run output to a log file in the `Results` folder. Alias: `-LogFile`.

`-Verbose`

Shows verbose progress output in the console. This is independent of `-WriteLog`.

---

## Authentication Modes

### Windows Authentication

Use Windows authentication when the current Windows account has the required SQL Server permissions:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001"
```

### Alternate Windows Account

Use `-WindowsCredential` to relaunch the assessment under another Windows identity:

```powershell
$cred = Get-Credential
.\Get-SqlSafe.ps1 -ConsoleOnly -SqlInstance "PRDSQL001" -Auth Windows -WindowsCredential $cred -NoAutoOpenReport
```

### SQL Authentication

Use SQL authentication with a secure password prompt:

```powershell
$pwd = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "PRDSQL001" -Auth SQL -SqlUser "assessment_user" -SqlPass $pwd
```

---

## Required SQL Server Permissions

The assessment is designed to run with least privilege using a dedicated login where supported by the SQL Server version.

Recommended practices:

* Use a dedicated assessment login.
* Do not use personal or shared administrator accounts unless required by the target environment and approved by your process.
* Grant only the permissions needed for the target SQL Server version.
* Remove or disable the assessment login after use if it is not part of an approved recurring process.
* Review generated reports as sensitive security output.

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

### SQL Server 2014-2019

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

The script includes a connection and permission test in the GUI. In console mode, missing permissions are typically discovered during SQL execution.

---

## Checks and Report Content

The assessment covers high-level indicators across areas such as:

* Authentication configuration
* SQL authentication and NTLM usage
* Sysadmin and powerful server role memberships
* Server-level permissions
* TRUSTWORTHY and cross-database ownership chaining
* Powerful features such as `xp_cmdshell`, ad hoc distributed queries, and OLE Automation
* Orphaned Windows logins and database users
* SQL Server security audit configuration
* Database ownership risks
* SQL Server error log retention
* System overview and informational context

The report includes:

* Target server and report metadata
* Outcome badges: `PASS`, `OBSERVE`, `WARNING`, `FAIL`, `INFO`
* Detail tables for findings
* Recommendations and reference links where applicable
* Informational context for version and system overview checks

---

## Output

The tool generates a local HTML report in the `Results` folder.

The report filename includes the target server and timestamp.

When `-WriteLog` is used, a `.log` file is also written to the same folder.

Generated reports may contain environment-specific security details, including:

* Server configuration details
* Login and role membership details
* Permission details
* Database ownership details
* Security findings and recommendations

Handle generated reports according to your organization's data handling and confidentiality requirements.

---

## SQL Integrity Validation

The embedded SQL assessment text is validated before execution using SHA-256.

The required hash is stored in the script and compared against the embedded SQL text before execution. If the embedded SQL text does not match the required hash, execution stops.

This helps detect accidental edits, copy/paste damage, or mismatched build artifacts. For enterprise tamper protection, use your normal file-hash validation and code-signing process.

---

## Exit Codes

```text
0 = completed successfully
2 = startup, parameter, credential, or assessment source validation failure
3 = SQL connection or SQL execution failure
```

---

## Enterprise Usage & Trust

This tool is distributed as a plain-text PowerShell script so organizations can review it according to internal security and change-control processes.

### Behavior Summary

Get-SqlSafe Community Edition:

* runs locally from the extracted folder
* connects to SQL Server using Windows or SQL authentication
* executes embedded SQL assessment logic
* validates the embedded SQL text using SHA-256 before execution
* writes a local HTML report to the `Results` folder
* can optionally write a run log to the `Results` folder
* does not install PowerShell modules automatically
* does not modify SQL Server configuration as part of the assessment

### Recommended enterprise process

#### 1. Review

Review the PowerShell script before running it in production or customer environments.

#### 2. Verify file integrity

```powershell
Get-FileHash .\Get-SqlSafe.ps1 -Algorithm SHA256
```

#### 3. Unblock downloaded files

```powershell
Unblock-File .\Get-SqlSafe.ps1
```

#### 4. Test first

Run the assessment against a non-production SQL Server instance before using it in a production environment.

#### 5. Re-sign internally if required

If your organization enforces `AllSigned`, sign the approved PowerShell file with your internal code-signing certificate after review.

Example only:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Get-SqlSafe.ps1 -Certificate $cert
```

Follow your internal process for code review, signing, packaging, and deployment.

---

## Notes

* Output may contain sensitive environment-specific information.
* The tool identifies indicators of risk; it does not enforce configuration changes.
* Some checks may require permissions that are not available on older SQL Server versions without elevated access.
* Community Edition focuses on high-level indicators and does not represent a complete security audit.

---

## Beyond the Baseline: Need the Complete Picture?

`Get-SqlSafe.ps1` covers a focused set of essential baseline indicators. Enterprise environments often require deeper architectural scrutiny.

The full **Sarpedon SQL Server Security Assessment** can include advanced architectural checks such as:

* Deep database-level configuration audits
* OS-level and backup security reviews
* Advanced account attribution and lateral movement mapping
* High availability, operational, and governance-focused review areas

[Explore Full-Scope Security Assessments at Sarpedon Quality Lab](https://sarpedonqualitylab.us/sql-server-security-assessment/)

---

## License

This project is distributed under the Sarpedon Community License.

Use is permitted for internal business or personal purposes. Redistribution, white-labeling, or commercial resale of modified versions or generated reports is restricted by the license terms.

See `LICENSE.md` for the full license text.

---

## Disclaimer

This tool is provided "as is", without warranty of any kind.

It identifies indicators of risk and does not replace a full security audit, penetration test, compliance assessment, or professional security review.

Use at your own risk.
