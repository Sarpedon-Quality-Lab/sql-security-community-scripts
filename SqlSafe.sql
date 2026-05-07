/******************************************************************************
* SQL Server Security Assessment - Community Edition
* Logic & Engine by Andreas Wolter (MCSM)
* Version:    2026.2
* Scope:      High-Level Security Indicators
* License:    Sarpedon Community License (See LICENSE.md)
* Resources:  https://www.SarpedonQualityLab.US/resources
* * DESCRIPTION:
* This script collects metadata and executes core security checks to identify 
* high-level indicators of risk. It is a foundational baseline designed for 
* community and internal organizational use.
*
* DISCLAIMER:
* This tool is provided "as is" for informational purposes only. It identifies 
* high-level indicators of risk and does not constitute a comprehensive security 
* audit, legal advice, or a guarantee of security. The author and Sarpedon 
* Quality Lab LLC assume no liability for any inaccuracies, system impacts, 
* or security incidents occurring after its use. Use at your own risk.
* 
* --- DO NOT EDIT !
* --- The Assessment will be blocked if the file has been manipulated !
* ---
******************************************************************************/



SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
SET NOCOUNT ON;


SELECT
    '002' AS [Check ID],
    'Authentication Mode' AS [Check Name],
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication'
        WHEN 0 THEN 'Windows and SQL Server Authentication (Mixed Mode)'
        ELSE 'Unknown'
    END AS Result1,
	SERVERPROPERTY('IsIntegratedSecurityOnly')AS Result2,
    (
        SELECT SERVERPROPERTY('IsExternalAuthenticationOnly') AS IsExternalAuthenticationOnly
		, SERVERPROPERTY('IsExternalGovernanceEnabled') AS IsExternalGovernanceEnabled
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
;
GO

WITH Connections AS
(
    SELECT *
    FROM sys.dm_exec_connections
    WHERE protocol_type <> 'Database Mirroring'
      AND net_transport <> 'Shared memory'
)
SELECT
    '003' AS [Check ID],
    'SQL Authentication usage' AS [Check Name],
    SUM(CASE WHEN auth_scheme = 'SQL' THEN 1 ELSE 0 END) AS Result1,
    CAST(
        100.0 * SUM(CASE WHEN auth_scheme = 'SQL' THEN 1 ELSE 0 END)
        / NULLIF(COUNT(*), 0)
        AS DECIMAL(5,2)
    ) AS Result2
FROM Connections;

GO

WITH Connections AS
(
    SELECT *
    FROM sys.dm_exec_connections
    WHERE protocol_type <> 'Database Mirroring'
      AND net_transport <> 'Shared memory'
)
SELECT
    '004' AS [Check ID],
    'NTLM Authentication usage' AS [Check Name],
    SUM(CASE WHEN auth_scheme = 'NTLM' THEN 1 ELSE 0 END) AS Result1,
    CAST(
        100.0 * SUM(CASE WHEN auth_scheme = 'NTLM' THEN 1 ELSE 0 END)
        / NULLIF(COUNT(*), 0)
        AS DECIMAL(5,2)
    ) AS Result2
FROM Connections;

GO

SELECT
    '008' AS [Check ID],
    'SA Login Name' AS [Check Name],
    name AS Result1,
    modify_date AS Result2
FROM sys.server_principals
WHERE sid = 0x01;

GO

SELECT
    '010' AS [Check ID],
    'Sysadmin-members individual accounts' AS [Check Name],
    server_principals.type_desc AS Result1,
    name AS Result2,
    (
        SELECT
            is_disabled,
            create_date
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_role_members AS server_role_members
JOIN sys.server_principals AS server_principals
    ON server_role_members.member_principal_id = server_principals.principal_id
WHERE server_role_members.role_principal_id = SUSER_ID('sysadmin')
  AND server_principals.name <> SUSER_SNAME(0x01)
  AND server_principals.name NOT IN ('NT SERVICE\SQLWriter', 'NT SERVICE\Winmgmt')
  AND server_principals.type NOT IN ('G', 'C', 'K', 'X')
ORDER BY server_principals.type_desc;

GO

SELECT
    '015' AS [Check ID],
    'Powerful server role membership' AS [Check Name],
    serverrole.name AS Result1,
    rolemember.name AS Result2,
    (
        SELECT
            rolemember.type_desc AS MemberType,
            rolemember.create_date,
            rolemember.modify_date,
            rolemember.is_disabled
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_role_members AS rm
INNER JOIN sys.server_principals AS serverrole
    ON rm.role_principal_id = serverrole.principal_id
INNER JOIN sys.server_principals AS rolemember
    ON rm.member_principal_id = rolemember.principal_id
WHERE serverrole.name IN (
        N'serveradmin',
        N'securityadmin',
        N'processadmin',
        N'setupadmin',
        N'bulkadmin',
        N'diskadmin',
        N'dbcreator'
)
ORDER BY serverrole.name, rolemember.name;

GO

SELECT
    '026' AS [Check ID],
    'Server permissions granted to Logins' AS [Check Name],
    server_principals.name AS Result1,
    server_permissions.permission_name AS Result2,
    (
        SELECT
            server_principals.is_disabled,
            server_principals.type_desc AS LoginType,
            server_permissions.state_desc,
            grantor.name AS grantor_name,
            server_permissions.class_desc,
            server_permissions.major_id,
            dm_server_services.service_account
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_permissions AS server_permissions
INNER JOIN sys.server_principals AS server_principals
    ON server_permissions.grantee_principal_id = server_principals.principal_id
INNER JOIN sys.server_principals AS grantor
    ON server_permissions.grantor_principal_id = grantor.principal_id
LEFT JOIN sys.dm_server_services AS dm_server_services
    ON dm_server_services.service_account = server_principals.name
WHERE
    NOT (
        server_permissions.class_desc = 'ENDPOINT'
        AND server_permissions.major_id = 5
        AND server_permissions.permission_name = 'CONNECT'
    )
    AND dm_server_services.service_account IS NULL
    AND server_principals.is_disabled = 0
    AND NOT (
        (server_principals.name = N'NT SERVICE\SQLWriter' AND server_permissions.permission_name = N'CONNECT SQL')
        OR (server_principals.name = N'NT SERVICE\Winmgmt' AND server_permissions.permission_name = N'CONNECT SQL')
        OR (server_principals.name = N'public' AND server_permissions.permission_name = N'CONNECT')

        OR (server_principals.name = N'##MS_AgentSigningCertificate##' AND server_permissions.permission_name = N'CONNECT SQL')
        OR (server_principals.name = N'##MS_PolicyEventProcessingLogin##' AND server_permissions.permission_name = N'CONNECT SQL')
        OR (server_principals.name = N'##MS_PolicySigningCertificate##' AND server_permissions.permission_name = N'CONTROL SERVER')
        OR (server_principals.name = N'##MS_PolicySigningCertificate##' AND server_permissions.permission_name = N'VIEW ANY DEFINITION')
        OR (server_principals.name = N'##MS_PolicyTsqlExecutionLogin##' AND server_permissions.permission_name = N'CONNECT SQL')
        OR (server_principals.name = N'##MS_PolicyTsqlExecutionLogin##' AND server_permissions.permission_name = N'VIEW ANY DEFINITION')
        OR (server_principals.name = N'##MS_PolicyTsqlExecutionLogin##' AND server_permissions.permission_name = N'VIEW SERVER STATE')
        OR (server_principals.name = N'##MS_SmoExtendedSigningCertificate##' AND server_permissions.permission_name = N'VIEW ANY DEFINITION')
        OR (server_principals.name = N'##MS_SQLAuthenticatorCertificate##' AND server_permissions.permission_name = N'AUTHENTICATE SERVER')
        OR (server_principals.name = N'##MS_SQLReplicationSigningCertificate##' AND server_permissions.permission_name = N'AUTHENTICATE SERVER')
        OR (server_principals.name = N'##MS_SQLReplicationSigningCertificate##' AND server_permissions.permission_name = N'VIEW ANY DEFINITION')
        OR (server_principals.name = N'##MS_SQLReplicationSigningCertificate##' AND server_permissions.permission_name = N'VIEW SERVER STATE')
        OR (server_principals.name = N'##MS_SQLResourceSigningCertificate##' AND server_permissions.permission_name = N'VIEW ANY DEFINITION')
    )
ORDER BY server_principals.name, server_permissions.permission_name;

GO

SELECT
    '027' AS [Check ID],
    'Custom server roles without members' AS [Check Name],
    name AS Result1,
    principal_id AS Result2,
    (
        SELECT
            create_date,
            modify_date
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_principals
WHERE
    type_desc = 'SERVER_ROLE'
    AND is_fixed_role = 0
    AND name <> 'public'
    AND NOT EXISTS (
        SELECT 1
        FROM sys.server_role_members AS rm
        WHERE rm.role_principal_id = principal_id
    )
ORDER BY name;

GO

SELECT
    '028' AS [Check ID],
    'Databases with Trustworthy property set' AS [Check Name],
    name AS Result1,
    is_trustworthy_on AS Result2,
    (
        SELECT
            state_desc AS State,
            create_date,
            database_id
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.databases
WHERE is_trustworthy_on = 1
  AND name <> 'msdb'
ORDER BY name;

GO

SELECT
    '031' AS [Check ID],
    'Cross Database ownership chaining setting' AS [Check Name],
    name Result1,
    CAST(is_db_chaining_on AS INT) AS Result2,
    (
        SELECT
            state_desc AS State,
            create_date,
            database_id
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.databases
WHERE is_db_chaining_on = 1
  AND name NOT IN ('master', 'msdb', 'tempdb')
ORDER BY name;

GO

SELECT
    '034' AS [Check ID],
    'XP_cmdshell setting' AS [Check Name],
    value AS Result1,
    value_in_use AS Result2
FROM sys.configurations
WHERE name = 'xp_cmdshell'
AND (value = 1 OR value_in_use =  1)
;

GO

SELECT
    '036' AS [Check ID],
    'Ad Hoc distributed queries setting' AS [Check Name],
    name AS Result1,
    value AS Result2,
    (
        SELECT
            value_in_use AS RunningValue,
            description
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.configurations
WHERE name = 'Ad Hoc Distributed Queries'
  AND (value = 1 OR value_in_use = 1)
;

GO

SELECT
    '038' AS [Check ID],
    'OLE Automation Procedures setting' AS [Check Name],
    name AS Result1,
    value AS Result2,
    (
        SELECT
            value_in_use AS RunningValue,
            description
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.configurations
WHERE name = 'Ole Automation Procedures'
  AND (value = 1 OR value_in_use = 1)
;

GO

DECLARE @ValidateLogins TABLE
(
    SID varbinary(85),
    OrphanedUser SYSNAME
);

INSERT INTO @ValidateLogins
EXEC sp_validatelogins;

SELECT
    '046' AS [Check ID],
    'Orphaned Windows Logins' AS [Check Name],
    SID AS Result1,
    OrphanedUser AS Result2
FROM @ValidateLogins;

GO

DECLARE @NumberOfErrorLogs INT = NULL;
DECLARE @RegReadResult INT = NULL;

BEGIN TRY
    EXEC @RegReadResult = master.dbo.xp_instance_regread
        @rootkey = 'HKEY_LOCAL_MACHINE',
        @key = N'Software\Microsoft\MSSQLServer\MSSQLServer',
        @value_name = 'NumberOfErrorLogs',
        @value = @NumberOfErrorLogs OUTPUT;
END TRY
BEGIN CATCH
    SET @RegReadResult = -1;
    SET @NumberOfErrorLogs = NULL;
END CATCH;

SELECT
    '050' AS [Check ID],
    'Number of Error Logs kept' AS [Check Name],
    CASE
        WHEN @RegReadResult <> 0 OR @NumberOfErrorLogs IS NULL THEN 'Not set. Using default.'
        ELSE 'custom'
    END AS Result1,
    CASE
        WHEN @RegReadResult <> 0 OR @NumberOfErrorLogs IS NULL THEN 7
        ELSE @NumberOfErrorLogs
    END AS Result2;

GO

IF CAST(LEFT(CAST(SERVERPROPERTY('ProductVersion') AS varchar(50)),
             CHARINDEX('.', CAST(SERVERPROPERTY('ProductVersion') AS varchar(50))) - 1) AS int) >= 10
BEGIN
    DECLARE @sql nvarchar(max) = N'
    ;WITH AllAuditActions AS
    (
        SELECT ''AUDIT_CHANGE_GROUP'' AS AuditActionName UNION ALL
        SELECT ''DBCC_GROUP'' UNION ALL
        SELECT ''EXTGOV_OPERATION_GROUP'' UNION ALL
        SELECT ''SERVER_OBJECT_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_OBJECT_PERMISSION_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_OPERATION_GROUP'' UNION ALL
        SELECT ''SERVER_PERMISSION_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_PRINCIPAL_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_PRINCIPAL_IMPERSONATION_GROUP'' UNION ALL
        SELECT ''SERVER_ROLE_MEMBER_CHANGE_GROUP'' UNION ALL
        SELECT ''SERVER_STATE_CHANGE_GROUP'' UNION ALL
        SELECT ''LOGIN_CHANGE_PASSWORD_GROUP'' UNION ALL
        SELECT ''FAILED_LOGIN_GROUP'' UNION ALL
        SELECT ''SUCCESSFUL_LOGIN_GROUP'' UNION ALL
        SELECT ''FAILED_DATABASE_AUTHENTICATION_GROUP'' UNION ALL
        SELECT ''DATABASE_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_OWNERSHIP_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_ROLE_MEMBER_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_PRINCIPAL_CHANGE_GROUP'' UNION ALL
        SELECT ''DATABASE_PRINCIPAL_IMPERSONATION_GROUP'' UNION ALL
        SELECT ''APPLICATION_ROLE_CHANGE_PASSWORD_GROUP''
    ),
    ConfiguredAuditDetails AS
    (
        SELECT
            sa.name AS AuditName,
            sa.is_state_enabled AS AuditEnabled,
            sas.name AS AuditSpecificationName,
            sas.is_state_enabled AS SpecificationEnabled,
            sasd.audit_action_name AS AuditActionName
        FROM sys.server_audit_specifications AS sas
        JOIN sys.server_audits AS sa
            ON sas.audit_guid = sa.audit_guid
        JOIN sys.server_audit_specification_details AS sasd
            ON sas.server_specification_id = sasd.server_specification_id
    )
    SELECT
        ''059'' AS [Check ID],
        ''Security Auditing minimal setup'' AS [Check Name],
        aaa.AuditActionName AS Result1,
        CASE
            WHEN cad.AuditActionName IS NULL THEN ''Not Covered''
            WHEN cad.AuditEnabled = 0 AND cad.SpecificationEnabled = 0 THEN ''Covered but Audit AND Specification Disabled''
            WHEN cad.AuditEnabled = 0 THEN ''Covered but Audit Disabled''
            WHEN cad.SpecificationEnabled = 0 THEN ''Covered but Specification Disabled''
        END AS Result2,
        (
            SELECT
                cad.AuditName,
                cad.AuditEnabled,
                cad.AuditSpecificationName,
                cad.SpecificationEnabled
            FOR XML PATH(''AdditionalInfo''), TYPE
        ) AS AdditionalInfo
    FROM AllAuditActions AS aaa
    LEFT JOIN ConfiguredAuditDetails AS cad
        ON aaa.AuditActionName = cad.AuditActionName
    WHERE cad.AuditActionName IS NULL
       OR cad.AuditEnabled = 0
       OR cad.SpecificationEnabled = 0
    ORDER BY aaa.AuditActionName;
    ';

    EXEC sys.sp_executesql @sql;
END;

GO

DECLARE @InstanceName NVARCHAR(128);
DECLARE @RegPath NVARCHAR(400);
DECLARE @AuditLevel INT;

SET @InstanceName = CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128));

SET @RegPath = N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer';

EXEC master.dbo.xp_instance_regread
    @rootkey = 'HKEY_LOCAL_MACHINE',
    @key = @RegPath,
    @value_name = 'AuditLevel',
    @value = @AuditLevel OUTPUT;

SELECT
    '069' AS [Check ID],
    'Basic Login-Failure logging status' AS [Check Name],
    @AuditLevel AS Result1,
    CASE @AuditLevel
                        WHEN 0 THEN 'None'
                        WHEN 2 THEN 'Failed logins only'
                        WHEN 1 THEN 'Successful logins only'
                        WHEN 3 THEN 'Both successful and failed logins'
                        ELSE 'Unknown'
                     END AS Result2
	;
GO

DECLARE @DatabaseOwners TABLE
(
      dbname          sysname         NOT NULL
    , matched_owner   nvarchar(128)   NULL
);

DECLARE @PreparedOwners TABLE
(
      database_id                      int             NULL
    , dbname                           sysname         NOT NULL
    , principal_id                     int             NULL
    , principal_name                   sysname         NULL
    , matched_owner                    nvarchar(128)   NULL
    , server_principal_type            nvarchar(60)    NULL
    , db_owner_valid                   varchar(20)     NOT NULL
    , powerful_server_role_membership  varchar(30)     NULL
);

INSERT INTO @DatabaseOwners
EXEC sp_MSforeachdb '
SELECT
      ''?'' AS dbname
    , SUSER_SNAME(database_principals.sid) AS matched_owner
FROM [?].sys.database_principals
WHERE database_principals.name = ''dbo''
';

INSERT INTO @PreparedOwners
(
      database_id
    , dbname
    , principal_id
    , principal_name
    , matched_owner
    , server_principal_type
    , db_owner_valid
	, powerful_server_role_membership
)
SELECT
      d.database_id
    , dbo_src.dbname
    , sp.principal_id
    , sp.name AS principal_name
    , dbo_src.matched_owner
    , sp.type_desc AS server_principal_type
    , CASE
          WHEN dbo_src.matched_owner IS NULL THEN 'not valid (!)'
          ELSE 'valid'
      END AS db_owner_valid
    , CASE
          WHEN srm.role_principal_id = 3  THEN 'sysadmin'
          WHEN srm.role_principal_id = 4  THEN 'securityadmin'
          WHEN srm.role_principal_id = 5  THEN 'serveradmin'
          WHEN srm.role_principal_id = 6  THEN 'setupadmin'
          WHEN srm.role_principal_id = 7  THEN 'processadmin'
          WHEN srm.role_principal_id = 8  THEN 'diskadmin'
          WHEN srm.role_principal_id = 9  THEN 'dbcreator'
          WHEN srm.role_principal_id = 10 THEN 'bulkadmin'
          ELSE NULL
      END AS powerful_server_role_membership
FROM @DatabaseOwners AS dbo_src
LEFT JOIN sys.databases AS d
    ON dbo_src.dbname COLLATE SQL_Latin1_General_CP1_CI_AS
     = d.name COLLATE SQL_Latin1_General_CP1_CI_AS
LEFT JOIN sys.server_principals AS sp
    ON d.owner_sid = sp.sid
LEFT JOIN sys.server_role_members AS srm
    ON sp.principal_id = srm.member_principal_id;

SELECT
      '072' AS [Check ID]
    , 'Database Owner sysadmin' AS [Check Name]
    , dbname AS Result1
    , principal_name AS Result2
    , (
        SELECT
            server_principal_type AS [Principal_Type],
            db_owner_valid,
            powerful_server_role_membership
        FOR XML PATH('AdditionalInfo'), TYPE
      ) AS AdditionalInfo
FROM @PreparedOwners
WHERE powerful_server_role_membership = 'sysadmin'
AND dbname NOT IN ('master', 'msdb', 'tempdb', 'model')
ORDER BY database_id ASC;

SELECT
      '078' AS [Check ID]
    , 'Database Owner Windows Account' AS [Check Name]
    , dbname AS Result1
    , principal_name AS Result2
    , (
        SELECT
            server_principal_type AS [Principal_Type],
            db_owner_valid,
            powerful_server_role_membership
        FOR XML PATH('AdditionalInfo'), TYPE
      ) AS AdditionalInfo
FROM @PreparedOwners
WHERE server_principal_type = 'WINDOWS_LOGIN'
ORDER BY database_id ASC;

SELECT
    '155' AS [Check ID],
    'Invalid database owner' AS [Check Name],
    dbname AS Result1,
    matched_owner AS Result2,
    (
        SELECT
            server_principal_type AS [Principal_Type],
            db_owner_valid,
            powerful_server_role_membership
        FOR XML PATH('AdditionalInfo'), TYPE
      ) AS AdditionalInfo
FROM @PreparedOwners
WHERE db_owner_valid = 'not valid (!)'
ORDER BY database_id ASC;

GO

SELECT
    '079' AS [Check ID],
    'SA Login State' AS [Check Name],
    name AS Result1,
    is_disabled AS Result2,
    (
        SELECT
            modify_date
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_principals
WHERE sid = 0x01;

GO

DECLARE @Check113 TABLE
(
      [Check ID]      varchar(10)
    , [Check Name]    nvarchar(200)
    , Result1         sysname
    , Result2         int
    , AdditionalInfo  xml
);

DECLARE @DatabaseName113 sysname;
DECLARE @Sql113 nvarchar(max);

DECLARE db_cursor_113 CURSOR LOCAL FAST_FORWARD FOR
SELECT name
FROM sys.databases
WHERE database_id > 4
  AND state_desc = 'ONLINE';

OPEN db_cursor_113;
FETCH NEXT FROM db_cursor_113 INTO @DatabaseName113;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @Sql113 = N'
    SELECT
          ''113''
        , ''Custom database roles without members''
        , roles.name
        , roles.principal_id
        , (
            SELECT
                  ''' + REPLACE(@DatabaseName113, '''', '''''') + ''' AS DatabaseName
                , roles.create_date
                , roles.owning_principal_id
                , owners.name
            FOR XML PATH(''AdditionalInfo''), TYPE
          )
    FROM ' + QUOTENAME(@DatabaseName113) + N'.sys.database_principals AS roles
    LEFT JOIN ' + QUOTENAME(@DatabaseName113) + N'.sys.database_role_members AS members
        ON roles.principal_id = members.role_principal_id
    LEFT JOIN ' + QUOTENAME(@DatabaseName113) + N'.sys.database_principals AS owners
        ON roles.owning_principal_id = owners.principal_id
    WHERE roles.type = ''R''
      AND members.member_principal_id IS NULL
      AND roles.is_fixed_role = 0
      AND roles.name <> ''public'';';

    INSERT INTO @Check113
    EXEC sys.sp_executesql @Sql113;

    FETCH NEXT FROM db_cursor_113 INTO @DatabaseName113;
END

CLOSE db_cursor_113;
DEALLOCATE db_cursor_113;

SELECT * FROM @Check113;

GO

DECLARE @Check129 TABLE
(
      [Check ID]              varchar(10)
    , [Check Name]    nvarchar(200)
    , Result1         sysname
    , Result2         nvarchar(60)
    , AdditionalInfo  xml
);

DECLARE @DatabaseName129 sysname;
DECLARE @Sql129 nvarchar(max);

DECLARE db_cursor_129 CURSOR LOCAL FAST_FORWARD FOR
SELECT name
FROM sys.databases
WHERE database_id > 4
  AND state_desc = 'ONLINE'
ORDER BY name;

OPEN db_cursor_129;
FETCH NEXT FROM db_cursor_129 INTO @DatabaseName129;

WHILE @@FETCH_STATUS = 0
BEGIN
    SET @Sql129 = N'
    SELECT
          ''129'' AS [Check ID]
        , ''Orphaned Database Users'' AS [Check Name]
        , database_principals.name AS Result1
        , database_principals.type_desc AS Result2
        , (
            SELECT
                  ' + QUOTENAME(@DatabaseName129,'''') + N' AS DatabaseName
                , database_principals.authentication_type_desc AS AuthType
                , database_principals.create_date
                , database_principals.modify_date
            FOR XML PATH(''AdditionalInfo''), TYPE
          ) AS AdditionalInfo
    FROM ' + QUOTENAME(@DatabaseName129) + N'.sys.database_principals AS database_principals
    LEFT JOIN sys.server_principals AS server_principals
        ON database_principals.sid = server_principals.sid
    WHERE server_principals.sid IS NULL
      AND database_principals.type IN (''S'', ''U'', ''G'')
      AND database_principals.authentication_type <> 0
      AND database_principals.name NOT IN (''dbo'', ''guest'', ''INFORMATION_SCHEMA'', ''sys'');';

    INSERT INTO @Check129
    EXEC sys.sp_executesql @Sql129;

    FETCH NEXT FROM db_cursor_129 INTO @DatabaseName129;
END

CLOSE db_cursor_129;
DEALLOCATE db_cursor_129;

SELECT
      [Check ID]
    , [Check Name]
    , Result1
    , Result2
    , AdditionalInfo
FROM @Check129
ORDER BY
    AdditionalInfo.value('(/AdditionalInfo/DatabaseName/text())[1]', 'sysname'),
    Result1;

GO

SELECT
    '123' AS [Check ID],
    'Databases with AUTO_CLOSE setting on' AS [Check Name],
    name AS Result1,
    is_auto_close_on AS Result2,
    (
        SELECT
            state_desc AS State,
            create_date,
            database_id
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.databases
WHERE is_auto_close_on = 1
ORDER BY name;

GO

IF CAST(LEFT(CAST(SERVERPROPERTY('ProductVersion') AS varchar(50)),
             CHARINDEX('.', CAST(SERVERPROPERTY('ProductVersion') AS varchar(50))) - 1) AS int) >= 16
BEGIN
    DECLARE @sql nvarchar(max) = N'
    SELECT
        ''802'' AS [Check ID],
        ''Contained Availability Groups'' AS [Check Name]
		,	COUNT(*) AS Result1
		FROM sys.availability_groups WHERE is_contained = 1
		GROUP BY is_contained
		'
    EXEC sys.sp_executesql @sql;
END

GO

SELECT
    '806' AS [Check ID],
    'Outstanding configuration changes' AS [Check Name],
    name AS Result1,
    value AS Result2,
    (
        SELECT
            value_in_use AS RunningValue,
            description
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.configurations
WHERE value_in_use <> value
  AND name NOT LIKE '%server memory (MB)%';

GO
