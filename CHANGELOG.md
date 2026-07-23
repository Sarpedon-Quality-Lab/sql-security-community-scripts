# Get-SqlSafe Community Edition — Changelog

## 2026.5

### Major Changes

- Added individual database-level reports.
  `-CreateIndividualDBLevelReports` and a matching GUI option additionally write one report per database. Each report contains only the database-scoped checks for that database and is written to a `<ServerName>__<Timestamp>__DatabaseLevelReports` sub-folder next to the main report. The server-level report contains a link to that folder.

### Report Changes

- Reworked the report header boxes.
  `Sections Analyzed` now comes first, and the boxes stay on a single row. `Core Security Controls` and `Informational Items` are reported separately in one box, so the control count matches the totals shown in the outcome chart. Previously the control count and the chart counted different sets of checks.

- Reorganized report sections so that server-scoped and database-scoped findings are separated.

### Assessment and SQL Changes

- Added Check `130` - `Db_owner database role members`.
  The check enumerates members of the `db_owner` database role across all online databases, excluding `dbo`, and reports them as `OBSERVE` when rows are returned. Membership in `db_owner` grants full control over a database and can be abused to elevate permissions to server-level.

- Corrected the version branch in the GUI connection and permission test.
  The SQL Server 2022 permission set (`VIEW SERVER SECURITY STATE`, `VIEW ANY SECURITY DEFINITION`, `VIEW SERVER PERFORMANCE STATE`) was previously tested against SQL Server 2014 and newer, where those permissions do not exist. It is now tested on SQL Server 2022 and newer only, and SQL Server 2014-2019 is tested for `VIEW SERVER STATE` and `VIEW ANY DEFINITION`.

- The permission test now also checks `CONNECT ANY DATABASE`, which Check `130` requires to enumerate role members across databases. The permission was already documented in the README grant examples.

### Documentation Changes

- Clarified `-TrustServerCert`.
  The switch only takes effect together with `-Encrypt Mandatory`. With `-Encrypt Optional`, the default, the server certificate is not validated in the first place and the switch changes nothing, except against an instance with `ForceEncryption` enabled, where the server imposes encryption and validation applies regardless. The README now documents the encryption and certificate combinations.

### Upgrade Notes

- Replace the previous collector with the new `Get-SqlSafe.ps1` file.
- No changes to required SQL Server permissions.
- Reports produced by 2026.4 remain readable; the layout changes apply to newly generated reports only.

### Compatibility Notes

- Windows PowerShell 5.1 remains the expected runtime.
- SQL Server 2016 or newer is recommended for least-privilege modern use.
- SQL Server 2012 and 2014 require higher privileges for some checks.
- Database-level reports contain the same findings as the main report, scoped to one database, and should be handled with the same confidentiality requirements.

---

## 2026.4

### Major Changes

- Added AWS RDS compatibility support.
  The collector now has an `-AwsRdsCompat` switch and a GUI option for AWS RDS compatible checks. When enabled, the assessment adjusts selected checks for AWS-managed SQL Server behavior and skips the Windows-login orphan check that requires server-level access not normally available on RDS.

### Assessment and SQL Changes

- Added Check `006` - `SQL Logins without password policy enforcement`.
  The check reports SQL logins where password policy enforcement is disabled and fails when one or more rows are returned.

- Updated Check `028` - `Databases with Trustworthy property set`.
  The check now excludes contained availability group `_msdb` databases.

- Updated Check `059` - `Security Auditing minimal setup`.
  `EXTGOV_OPERATION_GROUP` was removed from the minimum audit action baseline.

- Updated Check `802` - `Contained Availability Groups`.
  The check now returns contained availability group names and listener DNS/port information instead of just a number. The recommendation now also includes a note that contained availability groups maintain security principals and metadata separately from the host instance.

- Improved availability group handling.

### AWS RDS Behavior

- Added an `AWS managed` visual label for selected checks when the target is AWS RDS.

- AWS RDS compatibility mode adjusts selected collection and filtering behavior:
  - Skips Check `046` by design because of security limitations on AWS RDS SQL Server.
  - Excludes AWS-managed rows such as `rdsadmin` where applicable.
  - Excludes the model database from selected owner checks.

### Report Changes

- Added a category summary section between the outcome filter and the first detail area.
  The table shows per-category counts for `INFO`, `PASS`, `OBSERVE`, `WARNING`, `FAIL`, and total `Indicators`.

- Added an outcome definition legend.

- Improved category placement for several checks.


### Compatibility Notes

- Windows PowerShell 5.1 remains the expected runtime.
- SQL Server 2016 or newer is recommended for least-privilege modern use.
- SQL Server 2012 and 2014 may require higher privileges for some checks.
- Contained availability group details only surface in SQL Server 2022 or newer.
- The generated HTML reports may contain sensitive environment information and should be handled accordingly.
- The Community Edition remains a high-level indicator assessment and does not replace a full SQL Server security audit.

---

## 2026.3

### Major Changes

- Converted the assessment to a self-contained PowerShell script.  
  The SQL assessment logic is now embedded in the PowerShell collector, so the public package no longer needs a separate `SqlSafe.sql` file.

- Removed the `Invoke-Sqlcmd` / Microsoft `SqlServer` PowerShell module dependency.  
  SQL execution now uses .NET `System.Data.SqlClient`, reducing setup friction on clean systems and controlled enterprise endpoints.

- Added command-line / console execution.  
  The assessment can now run without the WPF logon dialog by supplying `-SqlInstance`. Console mode supports Windows and SQL authentication and helps with automation-friendly execution in controlled endpoint environments.

- Added optional report launch control.  
  `-NoAutoOpenReport` prevents automatic browser launch after report creation, which is useful in EDR/XDR-controlled environments where automatic browser launches may be restricted or flagged.

- Added optional execution logging.  
  `-WriteLog` / `-LogFile` writes diagnostic run output to a log file next to the generated report. `-Verbose` controls console verbosity separately.

- Added alternate Windows credential execution.  
  `-WindowsCredential` can relaunch the assessment under another Windows account for Windows-authenticated assessments.

- Added a combined GUI connection and permission test.  
  The GUI test button now verifies connectivity, shows the connected login, displays the SQL Server version, and reports key permission checks before the assessment starts.

- Added explicit process exit codes.  
  The collector now distinguishes successful runs, startup/validation failures, and SQL connection/execution failures.

### Packaging and Dependency Changes

- The public package now centers on a single collector script: `Get-SqlSafe.ps1`.
- The previous external `SqlSafe.sql` file is no longer required and is no longer used.
- The embedded SQL assessment text is validated before execution using SHA-256.
- The embedded SQL hash validation is intended to detect accidental edits, copy/paste damage, or mismatched build artifacts. For tamper protection, use normal file-hash validation and code signing.

### Assessment and SQL Changes

- Added Check `800` - `System Overview`.  
  The report now includes contextual instance metadata such as version, edition, uptime, availability group counts, database count, login count, and active connections.

- Added Check `011` - `Server role membership with direct Elevation-of-Privilege Risk`.  
  This highlights server role memberships that can directly lead to privilege escalation risk.

- Updated Check `004` - `NTLM Authentication usage`.  
  NTLM usage is now evaluated with staged severity:
  - Greater than `0%`: `OBSERVE`
  - `10%` to `30%`: `WARNING`
  - Greater than `30%`: `FAIL`

- Updated Check `015` naming.  
  The check is now labeled `Powerful server role membership individual accounts` to better describe the finding.

- Improved Check `026` filtering.  
  Default/service-account and selected built-in permission rows are excluded before outcome evaluation, including selected `DENY` rows.

- Fixed a bug in Check `050` which reported the wrong number of error logs in some environments.

- Improved data collection and multi-result-set handling.

- Added version-based applicability handling for selected informational checks.

### Report Changes

- Updated the HTML report generation flow.

- Improved report table layout.

### Operational Changes

- Added early log file initialization when logging is enabled.  
  Startup, validation, relaunch, and SQL execution messages can now be captured in the run log.

- Added redaction protections for credentials and sensitive header values.

- Improved SQL login handling.  
  SQL authentication uses `SqlCredential` and `SecureString` instead of embedding SQL passwords into connection strings.

### Acknowledgements

Thanks to Danny de Haan for the suggestion that led to the alternate Windows credential execution option.

### Upgrade Notes

- Replace the previous package with `Get-SqlSafe.ps1`.
- Remove the old `SqlSafe.sql` file if it exists in a local working folder.
- No `SqlServer` PowerShell module installation is required for SQL execution.
- Test the script against a non-production SQL Server before broad use.

### Compatibility Notes

- Windows PowerShell 5.1 remains the expected runtime.
- SQL Server 2012 or newer is expected.
- The tool still writes local HTML reports to a `Results` subfolder.
- The generated reports may contain sensitive environment information and should be handled accordingly.
- The Community Edition remains a high-level indicator assessment and does not replace a full security audit.
