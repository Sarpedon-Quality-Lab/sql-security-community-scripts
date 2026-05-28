# Get-SqlSafe Community Edition 2026.3 - Public Changelog Summary

## Major Changes

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

## Packaging and Dependency Changes

- The public package now centers on a single collector script: `Get-SqlSafe.ps1`.
- The previous external `SqlSafe.sql` file is no longer required and is no longer used.
- The embedded SQL assessment text is validated before execution using SHA-256.
- The embedded SQL hash validation is intended to detect accidental edits, copy/paste damage, or mismatched build artifacts. For tamper protection, use normal file-hash validation and code signing.

## Assessment and SQL Changes

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

## Report Changes

- Updated the HTML report generation flow.

- Improved report table layout.

## Operational Changes

- Added early log file initialization when logging is enabled.  
  Startup, validation, relaunch, and SQL execution messages can now be captured in the run log.

- Added redaction protections for credentials and sensitive header values.

- Improved SQL login handling.  
  SQL authentication uses `SqlCredential` and `SecureString` instead of embedding SQL passwords into connection strings.

## Acknowledgements

Thanks to Danny de Haan for the suggestion that led to the alternate Windows credential execution option.

## Upgrade Notes

- Replace the previous package with `Get-SqlSafe.ps1`.
- Remove the old `SqlSafe.sql` file if it exists in a local working folder.
- No `SqlServer` PowerShell module installation is required for SQL execution.
- Test the script against a non-production SQL Server before broad use.

## Compatibility Notes

- Windows PowerShell 5.1 remains the expected runtime.
- SQL Server 2012 or newer is expected.
- The tool still writes local HTML reports to a `Results` subfolder.
- The generated reports may contain sensitive environment information and should be handled accordingly.
- The Community Edition remains a high-level indicator assessment and does not replace a full security audit.
