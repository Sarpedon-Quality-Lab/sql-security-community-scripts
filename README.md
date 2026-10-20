# Get-SqlSafe Community Edition - SQL Server Security Assessment

**Logic & Engine by Andreas Wolter (MCSM)**
Version 2026.6

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
- Run SQL Server and Amazon RDS assessments without external PowerShell modules. Azure SQL Database uses one optional module and separately installed Microsoft prerequisites.
- Support both GUI-based and console-based execution.
- Support selected checks against SQL Server on Amazon RDS through an explicit compatibility mode, and Azure SQL Database through an optional component.


---

## What Changed in 2026.6

Version 2026.6 builds on the previous public release, 2026.5.

- Added Azure SQL Database with browser-based Microsoft Entra sign-in/MFA and SQL authentication. The standalone script remains sufficient for SQL Server and Amazon RDS.
- Added an optional PowerShell module, `Get-SqlSafe.Azure.psm1`, which is loaded only for Azure SQL Database assessments. It uses installed Microsoft modules and contains no embedded binary bundle or custom dependency cache.
- Added three target selectors: SQL Server, AWS RDS and Azure SQL Database, with platform-specific authentication, encryption and compatibility options.
- Added Check `030` for instance-wide cross-database ownership chaining.
- Added database names as the first result column for Check `113`, matching Check `130`.
- Improved report counts, skipped-check presentation, printing and filtering. Zero-count outcomes now have no colored bar fill.

See [CHANGELOG.md](CHANGELOG.md) for the 2026.6 changes and the preserved history of earlier public releases.

## Earlier Releases

2026.5 introduced individual database reports and Check `130` for `db_owner` role members. 2026.4 added AWS RDS compatibility and other report and assessment improvements. Their history is retained in [CHANGELOG.md](CHANGELOG.md).

## Contents

There is one 2026.6 download, `Get-SqlSafe.zip`, containing:

```text
Get-SqlSafe.ps1
Get-SqlSafe.Azure.psm1
README.md
CHANGELOG.md
LICENSE.md
```

`Get-SqlSafe.ps1` is the same script for all targets. SQL Server and Amazon RDS users can omit or delete `Get-SqlSafe.Azure.psm1`. They do not need the Microsoft Azure prerequisites.

Only Azure SQL Database needs the optional module beside the script and the Microsoft modules listed below. The optional module is plain PowerShell code, with no bundled DLLs, separate SQL file or Get-SqlSafe dependency cache. If it is missing when Azure is selected, the script reports the missing optional component. Reports and optional logs are written beneath `Results` next to the script. Keep the script and optional module from the same release together.

## Requirements

- Windows PowerShell 5.1 on Windows.
- Network access to the database target and permissions to read the assessed metadata.
- SQL Server 2016 or newer is recommended for SQL Server/RDS. SQL Server 2012 and 2014 may require broader permissions for selected checks.
- SQL Server and Amazon RDS use .NET `System.Data.SqlClient` and require no external PowerShell modules.
- Azure SQL Database requires .NET Framework 4.7.2 or later and the Microsoft `SqlServer` module, version 22.4.5.1 or later. Microsoft Entra authentication additionally requires `Az.Accounts`, version 5.3.4 or later.

Install the Azure prerequisites once as the account that runs the assessment:

```powershell
Install-Module SqlServer -MinimumVersion 22.4.5.1 -Scope CurrentUser
Install-Module Az.Accounts -MinimumVersion 5.3.4 -Scope CurrentUser
```

Use `-RequiredVersion` instead of `-MinimumVersion` to install those exact versions. For Azure SQL Database, SQL authentication requires the Microsoft `SqlServer` module but not `Az.Accounts`. The collector never installs or updates modules automatically. An administrator can provision them offline where PowerShell Gallery access is restricted.

Neither Microsoft module is imported for SQL Server or Amazon RDS. For Azure, the optional component uses the driver supplied by `SqlServer`; `Az.Accounts` handles browser-based sign-in/MFA and SQL access tokens. Microsoft modules maintain their own dependencies and authentication state. No Get-SqlSafe-specific library download, cache or compiled helper is used.

## Supported Targets and Known Limitations

Supported targets are SQL Server on-premises or in a virtual machine, SQL Server on Amazon RDS, and Azure SQL Database. Azure SQL Managed Instance is not an Azure SQL Database target in this release.

Use Windows or SQL authentication for SQL Server/RDS. Use SQL authentication or Microsoft Entra Interactive for Azure SQL Database. Azure Entra sign-in opens the system browser and supports MFA. Complete sign-in in the browser, then return to PowerShell.

For RDS, select AWS RDS in the dialog or supply `-Platform AwsRds`. For Azure, use the optional module and select Azure SQL Database or supply `-Platform AzureSQLDatabase`.
In GUI mode, Azure SQL Database assessments target databases discoverable through `master` by the connected identity. Console mode also supports an explicit database. A visible database inventory is not a guarantee that every database on the logical server is listed or accessible.

Some SQL Server checks do not apply to Azure SQL Database and are omitted entirely. Other Azure entries describe service-managed behavior or settings outside SQL metadata visibility. Checks `003`, `004` and `015` are not executed when the indirect administrator-visibility probe is negative or unavailable. The probe does not deterministically establish Server admin or Microsoft Entra administrator status. Verify administrator status and service-level configuration through the Azure control plane; the collector does not read that configuration.

On SQL Server/RDS, authentication-scheme metadata can be misleading for Microsoft Entra-authenticated sessions. Azure SQL Database support does not extend Microsoft Entra authentication support to SQL Server instances or Azure SQL Managed Instance.

Contained availability group metadata requires the relevant SQL Server catalog views. Checks affected by a contained availability group's separate security context may require assessment through that connection context.

## Quick Start - GUI Mode

1. Extract the selected package and open Windows PowerShell. For Azure, install the prerequisites listed above.
2. If required by your organization's download-handling process, unblock the files:

   ```powershell
   Unblock-File .\Get-SqlSafe.ps1
   # Only when using Azure SQL Database:
   Unblock-File .\Get-SqlSafe.Azure.psm1
   ```

3. Run the script:

   ```powershell
   .\Get-SqlSafe.ps1
   ```

4. Select SQL Server, AWS RDS or Azure SQL Database and enter the server name.
5. Choose an authentication method supported by that target. Azure Entra sign-in uses the browser when a connection is opened.
6. Review encryption and compatibility settings in Advanced. The securityadmin skip option applies to SQL Server/RDS; the Server admin or Entra administrator skip option applies to Azure and skips Checks `004` and `015`.
7. Optionally request per-database reports or use Test Connection and Permissions. On Azure, select the administrator-check skip option to enable that limited permission test.
8. Start the assessment.

The HTML report opens automatically unless `-NoAutoOpenReport` is supplied. Azure does not show an additional completion popup after writing the report. A failed authentication or assessment still reports the failure.

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
$sqlPassword = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Auth SQL -SqlUser "assessment_user" -SqlPass $sqlPassword -NoAutoOpenReport
```

Mandatory encryption while trusting the server certificate:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Encrypt Mandatory -TrustServerCert -NoAutoOpenReport
```

AWS RDS compatibility mode:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "my-rds-instance.example.rds.amazonaws.com" -Platform AwsRds -Encrypt Mandatory -TrustServerCert
```

Write a run log:

```powershell
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -WriteLog -Verbose -NoAutoOpenReport
```

Console mode and `-NoAutoOpenReport` are useful for controlled endpoints, automation-friendly execution, and EDR/XDR-controlled environments where UI prompts or automatic browser launches may be restricted.

---

### Azure SQL Database with Microsoft Entra Interactive

```powershell
.\Get-SqlSafe.ps1 -Platform AzureSQLDatabase -Auth EntraInteractive -SqlInstance 'contoso.database.windows.net' -AzureAllVisibleDatabases -NoAutoOpenReport
```

For a single database, replace `-AzureAllVisibleDatabases` with `-AzureDatabase 'appdb'`. Entra authentication remains interactive even in console mode, so complete the browser sign-in/MFA.

### Azure SQL Database with SQL Authentication

```powershell
$password = Read-Host 'Azure SQL password' -AsSecureString
.\Get-SqlSafe.ps1 -Platform AzureSQLDatabase -Auth SQL -SqlUser 'SecurityAssessment' -SqlPass $password -SqlInstance 'contoso.database.windows.net' -AzureDatabase 'appdb' -NoAutoOpenReport
```

Azure connections always enforce `Encrypt=Strict` with certificate validation, regardless of the non-Azure default encryption setting. `-TrustServerCert` cannot weaken the Azure connection.

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-SqlInstance` | Target SQL Server instance or Azure SQL logical server. Supplying it enables console mode. |
| `-ConsoleOnly` | Runs without the WPF dialog. Aliases: `-NoUI`, `-NonInteractive`. Entra sign-in still requires interaction. |
| `-Platform` | `SQLServer` (default), `AwsRds`, or `AzureSQLDatabase`. |
| `-Auth` | `Windows` (default for SQL Server/RDS), `SQL`, or `EntraInteractive` (default for Azure SQL Database). EntraInteractive requires Azure SQL Database. |
| `-SqlUser` | SQL login name, required for SQL authentication. |
| `-SqlPass` | SQL login password as a SecureString. SQL Server/RDS prompts if omitted. Azure SQL authentication requires an explicit `-SqlPass`; omission stops execution. |
| `-AzureDatabase` | Explicit Azure database to assess. |
| `-AzureAllVisibleDatabases` | Assess the Azure databases visible to this identity in master. Do not combine with `-AzureDatabase`. |
| `-Encrypt` | `Optional`, `Mandatory` or `Strict`. Optional is the SQL Server/RDS default; Azure always enforces Strict. Strict requires Azure. |
| `-TrustServerCert` | SQL Server/RDS certificate-trust option. Azure always validates its certificate. |
| `-SkipChecks` | Explicit check IDs to skip, such as `-SkipChecks 046` or `-SkipChecks 004,015`. Skipped entries are shown as Not checked. |
| `-CreateIndividualDBLevelReports` | Additionally write reports containing database-scoped checks for individual databases. |
| `-AwsRdsCompat` | Backwards compatibility only: Use -Platform AwsRds instead. Enable AWS RDS compatibility behavior and AWS managed labels. |
| `-WindowsCredential` | Relaunch under another Windows account. Requires Windows authentication and `-SqlInstance`. |
| `-WriteLog` | Write a run log under Results. Alias: `-LogFile`. |
| `-Verbose` | Show verbose progress independently of file logging. |
| `-NoAutoOpenReport` | Write reports without launching the browser to display them. |

Use `Get-Help .\Get-SqlSafe.ps1 -Full` for script help. The Azure component contains the Azure-specific queries and connection handling.

## Connection Encryption

For SQL Server and Amazon RDS, `-Encrypt` and `-TrustServerCert` work together:

| Encryption | Trust certificate | Result |
| --- | --- | --- |
| `Optional` (default) | off or on | No practical difference. The certificate is not validated either way. |
| `Mandatory` | off | The session is encrypted and the certificate is validated: the chain must be trusted, the certificate unexpired, and its name must match the server name as typed. A stock instance using its auto-generated self-signed certificate will fail this. |
| `Mandatory` | on | The session is encrypted, but any certificate is accepted. This protects against passive interception, not against an active man-in-the-middle. |

The login packet, including the password when `-Auth SQL` is used, is encrypted during the TDS pre-login handshake regardless of these settings. `Optional` means the rest of the session - the queries and all result rows - is unencrypted and no certificate is verified.

One exception to the first row: if the instance has `ForceEncryption` enabled, the server imposes encryption even when `Optional` was requested, and certificate validation then applies. That is the usual reason an `Optional` connection unexpectedly fails on certificate trust.

For an assessment run across an untrusted network, prefer `-Encrypt Mandatory` with a properly issued certificate and without `-TrustServerCert`.

---

Azure SQL Database always uses Strict encryption with certificate validation. Its connection ignores the non-Azure Optional default and does not permit TrustServerCertificate to weaken validation.

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
$sqlPassword = Read-Host "SQL password" -AsSecureString
.\Get-SqlSafe.ps1 -SqlInstance "SQLPROD01" -Auth SQL -SqlUser "assessment_user" -SqlPass $sqlPassword
```

---

## AWS RDS Compatibility Mode

Use `-Platform AwsRds` when assessing SQL Server on Amazon RDS.

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

## Azure SQL Database Permissions

For the broadest available assessment coverage, use a Microsoft Entra administrator or the SQL server administrator. For limited coverage, use an assessment account with the following server-role memberships:

```sql
ALTER SERVER ROLE ##MS_DatabaseConnector## ADD MEMBER [SecurityAssessment];
ALTER SERVER ROLE ##MS_SecurityDefinitionReader## ADD MEMBER [SecurityAssessment];
ALTER SERVER ROLE ##MS_ServerSecurityStateReader## ADD MEMBER [SecurityAssessment];
ALTER SERVER ROLE ##MS_ServerPerformanceStateReader## ADD MEMBER [SecurityAssessment];
```


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

The report uses five outcome states and a separate Not checked display for skipped checks:

| Outcome | Meaning |
| --- | --- |
| `INFO` | Provides useful context. It does not indicate a security finding. |
| `PASS` | The assessed condition met the expected rule. |
| `OBSERVE` | Marks a condition that is not necessarily risky by itself but should be reviewed or monitored. Impact depends on environment, intent, and compensating controls. |
| `WARNING` | Indicates a security-relevant finding that should be reviewed and usually remediated, but does not by itself indicate immediate high risk. |
| `FAIL` | Indicates a clear security risk that requires prompt attention. |
| `Not checked` | The included check was skipped. Grey, with no PASS/failure assignment or expandable findings. |

For `OBSERVE`, `WARNING`, and `FAIL` findings, the report includes recommendation text and, where available, reference links.

---


A query failure or missing evidence is not a PASS. Azure reports may indicate that a check was not assessed or only partially assessed when required evidence is unavailable. Successful PASS entries show only the heading and outcome, with no empty results panel.

For Check `004`, fewer than ten eligible connections produces WARNING on SQL Server/RDS and OBSERVE on Azure, with only the recommendation to repeat the scan during representative activity. With at least ten connections, SQL Server/RDS uses the NTLM percentage rules and Kerberos guidance. Azure uses Entra guidance and changes the SQL Server FAIL outcome to OBSERVE because visible NTLM connections can be associated with Azure services and features. Connection samples reflect observed metadata, not guaranteed complete server coverage.

Zero-count outcomes retain their count and grey chart track but have no colored fill or percentage label. Print output includes collapsed evidence and recommendations; Expand All and Collapse All operate on the currently visible expandable sections.

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

The assessment does not modify SQL Server or database configuration or user data. Azure Entra authentication selects browser login only for the current PowerShell process. It reads metadata and reports high-level indicators.

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
2 = startup, parameter, credential, assessment source validation failure, or some Azure connection/authentication exceptions
3 = SQL connection or execution failure, including Azure assessments that produce no publishable report
```

---

## Enterprise Usage and Trust

This tool is distributed as a plain-text PowerShell script so organizations can review it according to internal security and change-control processes.

### Behavior Summary

Get-SqlSafe Community Edition:

- Runs locally from the extracted folder.
- Connects to SQL Server/RDS using Windows or SQL authentication, or Azure SQL Database using SQL authentication or browser-based Microsoft Entra authentication.
- Executes embedded SQL assessment logic.
- Validates the embedded SQL text using SHA-256 before execution.
- Writes a local HTML report to the `Results` folder.
- Can optionally write a run log to the `Results` folder.
- Does not install PowerShell modules automatically.
- Does not modify SQL Server or database configuration or user data.

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

## Upgrade from 2026.5

1. Replace the old script with the 2026.6 `Get-SqlSafe.ps1` and use the updated README, changelog and license. SQL Server and RDS still require only the standalone script at runtime.
2. For Azure SQL Database, put `Get-SqlSafe.Azure.psm1` beside the script and install the Microsoft prerequisites described above.
3. Use a fresh PowerShell process after replacing the script, optional component or Microsoft modules. Already loaded .NET assemblies cannot be replaced inside the existing process.
4. Review the new Check `030`, the database categorization of `031`, and the changed treatment of skipped checks. A Not checked entry is not a PASS.
5. Validate the new release on a non-production target before broader use.

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
