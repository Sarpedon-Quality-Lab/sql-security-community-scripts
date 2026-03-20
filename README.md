# SQL Server Security Assessment (Community Edition)
**Logic & Engine by Andreas Wolter (MCSM)**  
**Version 2026.1**

Thank you for participating in this preview. The scripts are designed to identify  
**High-Level Security Indicators** for SQL Server instances.

---

## 1. Contents of this Package
- `Get-SqlSafe.ps1`: The PowerShell orchestrator  
- `SqlSafe_202601.sql`: The T-SQL collection script  
- `LICENSE.md`: Sarpedon Community License  
- `README.md`: You are reading it — good choice.  

---

## 2. Prerequisites
- **Permissions:** See section below. In short: `sysadmin` is not required (and preferably avoided)  
- **Environment:** PowerShell 5.1 or higher  

---

## 3. How to Run
1. Right-click `Get-SqlSafe.ps1` and select **Run with PowerShell**  
2. A connection dialog will appear  
3. Enter your SQL Instance and authentication options  
4. Click **Start Assessment**  
5. The interactive HTML report will be stored with a timestamp and server name in `/Results` (created automatically)  

---

## 4. Required Permissions

The assessment is designed to run with **least privilege** using a dedicated login.

- Do **not** use personal or shared administrator accounts  
- Permissions are **read-only by design**  
- The model prevents unintended changes while allowing full visibility into security-relevant metadata  

### General Notes

- `SqlAssessmentReader` is an example login name and should be replaced by the Login of your choice
- Least Permissions vary depending on SQL Server version  

---

### SQL Server 2022 and later

```sql
-- Grant required permissions
GRANT VIEW SERVER SECURITY STATE TO SqlAssessmentReader;
GRANT VIEW ANY SECURITY DEFINITION TO SqlAssessmentReader;
GRANT VIEW SERVER PERFORMANCE STATE TO SqlAssessmentReader;
GRANT CONNECT ANY DATABASE TO SqlAssessmentReader;

-- Required for specific system procedures
ALTER SERVER ROLE securityadmin
    ADD MEMBER SqlAssessmentReader;

-- Reduce inherited privileges to ensure that the login cannot create or modify other logins
DENY CREATE LOGIN TO SqlAssessmentReader;
DENY ALTER ANY LOGIN TO SqlAssessmentReader;
```

---

### SQL Server 2014 to SQL Server 2019

```sql
-- Grant required permissions
GRANT VIEW SERVER STATE TO SqlAssessmentReader;
GRANT VIEW ANY DEFINITION TO SqlAssessmentReader;
GRANT CONNECT ANY DATABASE TO SqlAssessmentReader;

-- Required for role and permission enumeration
ALTER SERVER ROLE securityadmin
    ADD MEMBER SqlAssessmentReader;

-- Reduce inherited privileges to ensure that the login cannot create or modify other logins
DENY ALTER ANY LOGIN TO SqlAssessmentReader;
```

---

### SQL Server 2012

```sql
/*
CONNECT ANY DATABASE does not exist.
Therefore the only practical approach is to make the account a member of the `sysadmin` server role unless you want to create a user in every database
*/

ALTER SERVER ROLE sysadmin
    ADD MEMBER SqlAssessmentReader;
```

---

### SQL Server 2005 – 2008 R2

```sql
-- Not supported by this assessment
```

---

> [!NOTE]  
> The permission model is intentionally restrictive:  
> it allows reading security and configuration data while preventing modification of server principals.

---

## 4. Troubleshooting: If the script is blocked
If Windows prevents the script from launching due to security policies or "Downloaded File" flags, open a PowerShell window in this folder and run:

**To unblock the orchestrator script:**
```powershell
Unblock-File -Path .\Get-SqlSafe.ps1
```

**allow execution for this session:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

---

## 5. Notes

> [!NOTE]  
> This tool identifies high-level indicators of risk.  
> It does not replace a full security audit — but it will tell you where to start looking.

---

## 6. Disclaimer

This tool is provided **"as is"** for informational purposes only.  
It identifies high-level indicators of risk and does not constitute a comprehensive security audit, legal advice, or a guarantee of security.

Use at your own risk.
