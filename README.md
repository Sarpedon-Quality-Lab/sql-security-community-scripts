# Get-SqlSafe.ps1: The Sarpedon SQL Server Security Community Assessment

**Logic & Engine by Andreas Wolter (MCSM)**  
Version 2026.5

Get-SqlSafe Community Edition is a standalone PowerShell-based SQL Server security assessment collector. It gathers selected high-level security indicators from a SQL Server instance and generates a local HTML report for review and remediation discussions.

The Community Edition is designed as a practical first look at SQL Server security posture. It focuses on baseline indicators such as authentication exposure, auditing gaps, excessive privileges, risky configuration settings, orphaned or dependent accounts, and database ownership drift.

> **Note:** This tool identifies indicators of risk. It is not a full security audit, penetration test, compliance assessment, or guarantee of security.

Read the [original public introduction to Get-SqlSafe Community Edition](https://andreas-wolter.com/en/2605_get-sqlsafe_communityedition_sqlserver_security_asssessment_tool/).

---

## What This Tool Does

`Get-SqlSafe.ps1` is a simple, reviewable PowerShell script that helps identify high-level SQL Server security posture indicators. It focuses on common security-relevant areas such as authentication, privileged access, server-level permissions, risky configuration, audit visibility, ownership risks, and orphaned accounts.

This Community Edition is designed to:

- Operate under least-privilege principles where supported by the target SQL Server version.
- Output a clean, visual local HTML report.
- Be transparent and easy to review as plain-text PowerShell with embedded T-SQL.
- Avoid automatic dependency installation.
- Run without the Microsoft `SqlServer` PowerShell module or `Invoke-Sqlcmd`.
- Support both GUI-based and console-based execution.
- Support selected checks against SQL Server on Amazon RDS through an explicit compatibility mode.

<img width="1287" height="1092" alt="Get-SqlSafe Community Edition security assessment report" src="https://github.com/user-attachments/assets/a645177a-a70b-45b7-8c81-7d6a8e0a5524" />

---

## What Changed in 2026.5

Version 2026.5 builds on 2026.4 and adds:

- Individual database-level reports through `-CreateIndividualDBLevelReports` and the GUI checkbox. Each report covers the database-scoped checks for one database and is written to a `<ServerName>__<Timestamp>__DatabaseLevelReports` sub-folder next to the main report, which also links to that folder.
- New included Check `130` - `Db_owner database role members`, which reports members of the `db_owner` database role across all online databases.

See [`CHANGELOG.md`](CHANGELOG.md) for the complete public changelog summary.

---

## What Changed in 2026.4

Version 2026.4 builds on the self-contained 2026.3 collector and adds:

- AWS RDS compatibility mode through `-AwsRdsCompat` and the GUI checkbox.
- `AWS managed` labels for selected findings where SQL Server behavior may be controlled by AWS.
- Check `006` for SQL logins without password policy enforcement.
- Improved contained availability group reporting in Check `802`, including listener DNS/port details and guidance about the separate contained availability group security context.
- Improved availability group handling.
- A category summary table in the HTML report.
- A report legend explaining the result labels.

<img width="576" height="419" alt="Connection Dialogue with AWS compatibility mode" src="https://github.com/user-attachments/assets/f75c5418-8708-4a10-b4da-64df193f6a12" />


See [`CHANGELOG.md`](CHANGELOG.md) for the complete public changelog summary.

---

## Contents

The public Community Edition package contains:

- `Get-SqlSafe.ps1` — standalone PowerShell collector, embedded SQL assessment logic, and report generator
- `README.md` — usage documentation
- `CHANGELOG.md` — public release history
- `LICENSE.md` — Sarpedon Community License

Generated reports and logs are written to:

```text
.\Results
.\Results\<ServerName>__<Timestamp>__DatabaseLevelReports   (only with -CreateIndividualDBLevelReports)
```

The public package does not require a separate SQL file.

---

## Requirements

- Windows PowerShell 5.1
- Windows operating system with .NET Framework support
- Network access to the target SQL Server instance
- SQL Server 2016 or newer recommended
- Permissions sufficient to read the assessed security metadata

SQL Server 2012 and SQL Server 2014 may work for selected scenarios, but older versions can require higher privileges for some checks.

No PowerShell module installation is required for SQL execution. The collector uses .NET `System.Data.SqlClient`.

---

## Supported Targets and Known Limitations

Get-SqlSafe Community Edition currently supports SQL Server on-premises, SQL Server running in a virtual machine, and selected assessment scenarios for SQL Server on Amazon RDS. Use Windows or SQL authentication as supported by the target platform.

For SQL Server on Amazon RDS, explicitly enable `-AwsRdsCompat` or select the corresponding GUI option. This mode adjusts or skips selected checks where AWS controls the underlying SQL Server behavior or restricts access to required metadata.

Microsoft Entra authentication scenarios are not currently supported. In current SQL Server versions, Entra-authenticated sessions can expose the session authentication scheme as `NTLM`, which does not accurately describe the authentication protocol. Because Get-SqlSafe uses SQL Server authentication-scheme metadata for NTLM/Kerberos interpretation, authentication-related findings may be misleading for Entra-authenticated sessions.

Contained availability group metadata is available only when the target SQL Server version exposes the required catalog views. Security-context-dependent checks may need to be run through the contained availability group connection context for complete results.

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

5. Enter the SQL Server name or instance.
6. Select Windows or SQL authentication.
7. Choose the encryption options required by the target.
8. Enable AWS RDS compatibility mode when assessing SQL Server on Amazon RDS.
9. Optionally enable additional per-database reports.
10. Optionally test the connection and permissions.
11. Start the assessment.

The generated HTML report is written to the `Results` subfolder and opens automatically unless report launch is disabled.

<img width="500" height="402" alt="Get-SqlSafe connection and permission test" src="https://github.com/user-attachments/assets/90918bd2-e522-41de-a078-a4b6974556a5" />

If your system blocks script execution, you may run the script with an explicit execution policy for this PowerShell process:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-SqlSafe.ps1
```

This permits the script to run in that PowerShell process. It does not unblock files permanently and does not install dependencies.

---

## Quick Start - Console Mode

Supplying `-SqlInstance` automatically runs the script in console mode.

Windows authentication:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01"
```

Run without opening the report automatically:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -NoAutoOpenReport
```

SQL authentication:

```powershell
$pwd = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Auth SQL -SqlUser "assessment_user" -SqlPass $pwd -NoAutoOpenReport
```

Mandatory encryption while trusting the server certificate:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Encrypt Mandatory -TrustServerCert -NoAutoOpenReport
```

AWS RDS compatibility mode:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "my-rds-instance.example.rds.amazonaws.com" -AwsRdsCompat -Encrypt Mandatory -TrustServerCert
```

Write a run log:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -WriteLog -Verbose -NoAutoOpenReport
```

Console mode and `-NoAutoOpenReport` are useful for controlled endpoints, automation-friendly execution, and EDR/XDR-controlled environments where UI prompts or automatic browser launches may be restricted.

---

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-SqlInstance` | Target SQL Server name or instance. Supplying this parameter enables console mode. |
| `-ConsoleOnly` | Runs without the WPF dialog. Aliases: `-NoUI`, `-NonInteractive`. |
| `-Auth` | Authentication method: `Windows` or `SQL`. Defaults to `Windows`. |
| `-SqlUser` | SQL login name. Required when `-Auth SQL` is used. |
| `-SqlPass` | SQL login password as a `SecureString`. If omitted for SQL authentication, the script prompts interactively. |
| `-Encrypt` | Connection encryption mode: `Optional` or `Mandatory`. Defaults to `Optional`. |
| `-TrustServerCert` | Trusts the SQL Server certificate without certificate-chain validation. Only takes effect together with `-Encrypt Mandatory`; see [Connection Encryption](#connection-encryption). |
| `-CreateIndividualDBLevelReports` | Additionally writes one report per database into a sub-folder next to the main report. |
| `-AwsRdsCompat` | Enables AWS RDS compatibility behavior and `AWS managed` labels. |
| `-WindowsCredential` | Relaunches the assessment under another Windows account. Valid with Windows authentication and requires `-SqlInstance`. |
| `-WriteLog` | Writes run output to a log file in the `Results` folder. Alias: `-LogFile`. |
| `-Verbose` | Shows verbose progress output in the console independently of `-WriteLog`. |
| `-NoAutoOpenReport` | Prevents the generated HTML report from opening automatically. |

---

## Connection Encryption

`-Encrypt` and `-TrustServerCert` work together, and the second only means something in combination with the first:

| Encryption | Trust certificate | Result |
| --- | --- | --- |
| `Optional` (default) | off or on | No practical difference. The certificate is not validated either way. |
| `Mandatory` | off | The session is encrypted and the certificate is validated: the chain must be trusted, the certificate unexpired, and its name must match the server name as typed. A stock instance using its auto-generated self-signed certificate will fail this. |
| `Mandatory` | on | The session is encrypted, but any certificate is accepted. This protects against passive interception, not against an active man-in-the-middle. |

The login packet, including the password when `-Auth SQL` is used, is encrypted during the TDS pre-login handshake regardless of these settings. `Optional` means the rest of the session — the queries and all result rows — is unencrypted and no certificate is verified.

One exception to the first row: if the instance has `ForceEncryption` enabled, the server imposes encryption even when `Optional` was requested, and certificate validation then applies. That is the usual reason an `Optional` connection unexpectedly fails on certificate trust.

For an assessment run across an untrusted network, prefer `-Encrypt Mandatory` with a properly issued certificate and without `-TrustServerCert`.

---

## Authentication Modes

### Windows Authentication

Use Windows authentication when the current Windows account has the required SQL Server permissions:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01"
```

### Alternate Windows Account

Use `-WindowsCredential` to relaunch the assessment under another Windows identity:

```powershell
$cred = Get-Credential
.\Get-SqlSafe.ps1 -ConsoleOnly -SqlInstance "SQLPROD01" -Auth Windows -WindowsCredential $cred -NoAutoOpenReport
```

### SQL Authentication

Use SQL authentication with a secure password prompt:

```powershell
$pwd = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Auth SQL -SqlUser "assessment_user" -SqlPass $pwd
```

---

## AWS RDS Compatibility Mode

Use `-AwsRdsCompat` when assessing SQL Server on Amazon RDS.

When enabled, the collector:

- Adjusts selected permission checks for restricted AWS-managed environments.
- Skips Check `046` because the required server-level access is not normally available on SQL Server on Amazon RDS.
- Excludes AWS-managed objects such as `rdsadmin` where applicable.
- Excludes the `model` database from selected owner checks.
- Marks selected findings with an `AWS managed` label when the target is detected as RDS.

AWS RDS compatibility mode does not imply that every control managed by AWS is secure or correctly configured. It distinguishes selected platform-managed conditions from findings under direct customer control.

---

## Contained Availability Groups

Check `802` reports contained availability group names and listener DNS/port details when SQL Server 2022 or newer exposes the required metadata.

> **Important:** Contained availability groups maintain security principals and metadata separately from the host SQL Server instance. Checks that depend on this security context, such as identifying orphaned database users, must be executed through the contained availability group context to produce accurate results.

---

## Required SQL Server Permissions

The assessment is designed to run with least privilege using a dedicated login where supported by the SQL Server version.

Recommended practices:

- Use a dedicated assessment login.
- Do not use personal or shared administrator accounts unless required by the target environment and approved by your process.
- Grant only the permissions needed for the target SQL Server version.
- Remove or disable the assessment login after use if it is not part of an approved recurring process.
- Review generated reports as sensitive security output.

The examples below use `SqlAssessmentReader` as the assessment principal. They apply to self-managed SQL Server. SQL Server on Amazon RDS has a different permission model; use an account with the available metadata permissions and enable `-AwsRdsCompat`.

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

`CONNECT ANY DATABASE` is required for the checks that enumerate database-scoped information across all databases, including Check `130`.

The script includes a connection and permission test in the GUI. The test checks the permission set that applies to the detected SQL Server version. In console mode, missing permissions are typically discovered during SQL execution.

---

## Checks and Report Content

The assessment covers high-level indicators across areas such as:

- Authentication configuration
- SQL authentication, password-policy enforcement, and NTLM usage
- Sysadmin and powerful server role memberships
- Server-level permissions
- `TRUSTWORTHY` and cross-database ownership chaining
- Powerful features such as `xp_cmdshell`, ad hoc distributed queries, and OLE Automation
- Orphaned Windows logins and database users
- `db_owner` database role membership
- SQL Server security audit configuration
- Database ownership risks
- SQL Server error log retention
- Availability groups and contained availability groups
- System overview and informational context

The HTML report includes:

- Execution metadata and target summary, with separate control and informational item counts
- Outcome distribution chart
- Outcome filters showing the number of results per outcome
- Category summary table with status counts and total indicators
- Outcome definition legend
- Detailed findings grouped by category
- Recommendations and references for actionable findings
- Informational context for version and system overview checks

When per-database reports are requested, each database additionally receives its own report containing the database-scoped checks for that database, with a compact outcome summary in place of the distribution chart.

---

## Result Meanings

The report uses five outcome states:

| Outcome | Meaning |
| --- | --- |
| `INFO` | Provides useful context. It does not indicate a security finding. |
| `PASS` | The assessed condition met the expected rule. |
| `OBSERVE` | Marks a condition that is not necessarily risky by itself but should be reviewed or monitored. Impact depends on environment, intent, and compensating controls. |
| `WARNING` | Indicates a security-relevant finding that should be reviewed and usually remediated, but does not by itself indicate immediate high risk. |
| `FAIL` | Indicates a clear security risk that requires prompt attention. |

For `OBSERVE`, `WARNING`, and `FAIL` findings, the report includes recommendation text and, where available, reference links.

---

## Output, Security, and Data Handling

The tool generates a local HTML report in the `Results` folder. The report filename includes the target server and timestamp. When `-WriteLog` is used, a `.log` file is also written to the same folder.

With `-CreateIndividualDBLevelReports`, the per-database reports are written to a `<ServerName>__<Timestamp>__DatabaseLevelReports` sub-folder inside `Results`, and the main report links to that folder. These reports contain the same findings as the main report, scoped to a single database.

Generated reports and logs may include sensitive environment-specific information, including:

- Server and database names
- Login and role membership details
- Permission details
- Configuration values
- Database ownership details
- Security findings and recommendations

Handle generated reports according to your organization's data handling and confidentiality requirements.

The collector does not intentionally change SQL Server configuration or data. It reads metadata and reports high-level indicators.

---

## SQL Integrity Validation

The embedded SQL assessment text is validated before execution using SHA-256.

The required hash is stored in the script and compared against the embedded SQL text before execution. If the embedded SQL text does not match the required hash, execution stops.

This helps detect accidental edits, copy/paste damage, or mismatched build artifacts. For enterprise tamper protection, use your normal file-hash validation and code-signing process.

The required hash changes whenever the embedded SQL text changes, including its version banner, so it differs between releases.

---

## Exit Codes

```text
0 = completed successfully
2 = startup, parameter, credential, or assessment source validation failure
3 = SQL connection or SQL execution failure
```

---

## Enterprise Usage and Trust

This tool is distributed as a plain-text PowerShell script so organizations can review it according to internal security and change-control processes.

### Behavior Summary

Get-SqlSafe Community Edition:

- Runs locally from the extracted folder.
- Connects to SQL Server using Windows or SQL authentication.
- Executes embedded SQL assessment logic.
- Validates the embedded SQL text using SHA-256 before execution.
- Writes a local HTML report to the `Results` folder.
- Can optionally write a run log to the `Results` folder.
- Does not install PowerShell modules automatically.
- Does not intentionally modify SQL Server configuration or data as part of the assessment.

### Recommended Enterprise Process

#### 1. Review

Review the PowerShell script before running it in production or customer environments.

#### 2. Verify File Integrity

```powershell
Get-FileHash .\Get-SqlSafe.ps1 -Algorithm SHA256
```

#### 3. Unblock Downloaded Files

```powershell
Unblock-File .\Get-SqlSafe.ps1
```

#### 4. Test First

Run the assessment against a non-production SQL Server instance before using it in a production environment.

#### 5. Re-sign Internally if Required

If your organization enforces `AllSigned`, sign the approved PowerShell file with your internal code-signing certificate after review.

Example only:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath .\Get-SqlSafe.ps1 -Certificate $cert
```

Follow your internal process for code review, signing, packaging, and deployment.

---

## Scope and Limitations

The Community Edition is intentionally limited. It is not:

- A penetration test.
- A compliance assessment.
- A full SQL Server security review.
- A guarantee that the target SQL Server is secure.

A clean report means that the covered baseline indicators did not identify findings. SQL Server's real attack surface is broader and depends on combinations of permissions, ownership, impersonation, SQL Agent, linked servers, database configuration, service accounts, backups, operating-system security posture, and platform-specific controls.

Some checks may require permissions that are not available on older SQL Server versions or managed platforms without elevated access. Use the report as a starting point for deeper review and remediation planning.

---

## Upgrade Notes from 2026.4

- Replace the previous collector with the new `Get-SqlSafe.ps1` file.
- Grant `CONNECT ANY DATABASE` to the assessment login if it does not have it. Check `130` needs it to enumerate `db_owner` membership across databases.
- Reports generated by 2026.4 remain readable. The report layout changes apply to newly generated reports only.
- Enable `-CreateIndividualDBLevelReports` only when per-database reports are wanted; the option adds one HTML file per database.

---

## Upgrade Notes from 2026.3

- Review [`CHANGELOG.md`](CHANGELOG.md) before replacing older scripts.
- Replace the previous collector with the new `Get-SqlSafe.ps1` file.
- Remove the old `SqlSafe.sql` file if it remains in a working folder; it is no longer used.
- Test the collector against a non-production SQL Server before broad use.
- Use `-AwsRdsCompat` when assessing SQL Server on Amazon RDS.

---

## Beyond the Baseline: Need the Complete Picture?

`Get-SqlSafe.ps1` covers a focused set of essential baseline indicators. Enterprise environments often require deeper architectural scrutiny.

The full **Sarpedon SQL Server Security Assessment** can include advanced architectural checks such as:

- Deep database-level configuration audits
- OS-level and backup security reviews
- Advanced account attribution and lateral-movement mapping
- High availability, operational, and governance-focused review areas

[Explore full-scope SQL Server security assessments at Sarpedon Quality Lab](https://sarpedonqualitylab.us/sql-server-security-assessment/).

---

## License and Attribution

Logic & Engine by Andreas Wolter (MCSM), Sarpedon Quality Lab.

This project is distributed under the Sarpedon Community License. Use is permitted for internal business or personal purposes. Unmodified generated reports may be shared provided that all branding, attribution, Community Edition designation, and version information remain intact. Redistribution of modified scripts or reports is governed by the license terms.

See [`LICENSE.md`](LICENSE.md) for the full license text. Use the tool only on systems where you have authorization to run security assessment tooling.

---

## Disclaimer

This tool is provided "as is", without warranty of any kind.

It identifies indicators of risk and does not replace a full security audit, penetration test, compliance assessment, or professional security review.

Use at your own risk.
