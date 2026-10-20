Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Microsoft modules are loaded only through the optional Azure component.
Import-Module SqlServer -MinimumVersion 22.4.5.1 -Scope Local -ErrorAction Stop
$script:AzureConnectionType = [Microsoft.Data.SqlClient.SqlConnection]
$script:AzureContext = $null

function Get-SqlSafeAzureAccessToken {
    try{Import-Module Az.Accounts -MinimumVersion 5.3.4 -Scope Local -ErrorAction Stop}
    catch{throw [InvalidOperationException]::new('AZURE-AZ-ACCOUNTS-REQUIRED')}
    if($null -eq $script:AzureContext){
        # Use Microsoft's browser-based sign-in for this process only.
        $null=Az.Accounts\Update-AzConfig -EnableLoginByWam $false -Scope Process -ErrorAction Stop
        # Skip subscription enumeration: SQL access does not require subscription roles.
        $login=Az.Accounts\Connect-AzAccount -Scope Process -SkipContextPopulation -AuthScope 'https://database.windows.net/' -ErrorAction Stop
        if($null -eq $login -or $null -eq $login.Context -or $null -eq $login.Context.Account){
            throw [InvalidOperationException]::new('AZURE-ENTRA-SIGNIN-INCOMPLETE')
        }
        $script:AzureContext=$login
    }
    Az.Accounts\Get-AzAccessToken -ResourceUrl 'https://database.windows.net/' -DefaultProfile $script:AzureContext -ErrorAction Stop
}

function New-AzureSqlConnectionString {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Server,
          [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Database,
          [ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive')
    $builder = New-Object Microsoft.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $Server
    $builder['Initial Catalog'] = $Database
    $builder['Encrypt'] = 'Strict'
    $builder['TrustServerCertificate'] = $false
    $builder['Connect Timeout'] = 90

    if (-not $builder.ConnectionString.Contains('Encrypt=Strict') -or $builder.TrustServerCertificate) {
        throw [InvalidOperationException]::new('Azure SQL strict encryption and certificate validation could not be enforced.')
    }
    return $builder.ConnectionString
}

function New-AzureSqlConnection {
    param([string]$Server,[string]$Database,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password,[scriptblock]$ConnectionFactory)
    if ($ConnectionFactory) { return (& $ConnectionFactory $Server $Database $AuthMethod $Username $Password) }
    $connectionString=New-AzureSqlConnectionString -Server $Server -Database $Database -AuthMethod $AuthMethod
    if ($AuthMethod -eq 'SQL') {
        if ([string]::IsNullOrWhiteSpace($Username) -or $null -eq $Password -or $Password.Length -eq 0) { throw [ArgumentException]::new('Azure SQL Authentication requires a username and SecureString password.') }
        if(-not $Password.IsReadOnly()){$Password.MakeReadOnly()}
        $credential=New-Object Microsoft.Data.SqlClient.SqlCredential($Username,$Password)
        return New-Object Microsoft.Data.SqlClient.SqlConnection($connectionString,$credential)
    }
    $accessToken=Get-SqlSafeAzureAccessToken
    $connection=New-Object Microsoft.Data.SqlClient.SqlConnection($connectionString)
    $tokenPointer=[IntPtr]::Zero
    try {
        if($accessToken.Token -is [Security.SecureString]){
            $tokenPointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken.Token)
            $connection.AccessToken=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
        }else{
            $connection.AccessToken=[string]$accessToken.Token
        }
        if([string]::IsNullOrWhiteSpace($connection.AccessToken)){throw [InvalidOperationException]::new('AZURE-ENTRA-TOKEN-UNAVAILABLE')}
        return $connection
    }catch{$connection.Dispose();throw}
    finally{if($tokenPointer -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)}}
}

function New-AzureSqlResult {
    param([string]$Server,[string]$Scope,[string]$Principal,[object[]]$DatabaseResults,[object]$Inventory,[datetime]$Started)
    $collected = @($DatabaseResults | Where-Object Status -eq 'Collected').Count
    $requested = @($DatabaseResults | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Database) }).Count
    $failed = @($DatabaseResults | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Database) -and $_.Status -ne 'Collected' }).Count
    $inventoryComplete = ($null -ne $Inventory -and $Inventory.Succeeded)
    if ([string]::IsNullOrWhiteSpace($Principal)) { $principalRecord=@($DatabaseResults | Where-Object { $_.AuthenticatedPrincipal } | Select-Object -First 1); if ($principalRecord.Count -gt 0) { $Principal=[string]$principalRecord[0].AuthenticatedPrincipal } }
    $summary = if ($Scope -eq 'ExplicitDatabase') {
        'Only the explicitly requested database was targeted. No server-wide or other-database coverage is implied.'
    } elseif ($inventoryComplete) {
        'Databases listed are those visible to this identity in master; metadata visibility may make the list incomplete.'
    } else {
        'Master inventory could not be completed. All-visible scope is incomplete and cannot claim comprehensive database coverage.'
    }
    [pscustomobject]@{
        Platform='AzureSQLDatabase'; LogicalServer=$Server; RequestedScope=$Scope
        AuthenticatedPrincipal=$Principal; StartedAt=$Started; EndedAt=[datetime]::UtcNow
        Inventory=[pscustomobject]@{ Status=$(if ($inventoryComplete) {'Collected'} elseif ($null -eq $Inventory) {'NotRequested'} else {'Failed'}); Databases=$(if ($inventoryComplete) {@($Inventory.Databases)} else {@()}); ServerEvidence=$(if ($inventoryComplete) {@($Inventory.ServerEvidence)} else {@()}); MetadataVisibilitySufficient=$false; ErrorCategory=$(if ($null -ne $Inventory) {$Inventory.ErrorCategory} else {$null}); SupportCode=$(if ($null -ne $Inventory) {$Inventory.SupportCode} else {$null}); UserMessage=$(if ($null -ne $Inventory) {$Inventory.UserMessage} else {$null}); VisibilityNote='sys.databases returns only metadata visible to the current identity; the list may be incomplete.' }
        Databases=@($DatabaseResults); Coverage=[pscustomobject]@{ Requested=$requested; Collected=$collected; NotCollected=$failed; InventoryComplete=$inventoryComplete; Summary=$summary }
        Succeeded=($collected -gt 0); UserMessage=$summary
    }
}

function Get-AzureSqlQueryMatrix {
    [pscustomobject[]]@(
        [pscustomobject]@{ Id='AZ-DB-PRINCIPALS-001'; Scope='Database'; Purpose='Visible database users, roles, external/Entra principals, and principal metadata'; Sql="SELECT principal_id, name, type, type_desc, authentication_type_desc, default_schema_name, create_date, modify_date FROM sys.database_principals WHERE principal_id > 4 ORDER BY principal_id" },
        [pscustomobject]@{ Id='AZ-DB-ROLE-MEMBERSHIPS-001'; Scope='Database'; Purpose='Visible database role memberships'; Sql="SELECT rolep.name AS RoleName, memberp.name AS MemberName, memberp.type_desc AS MemberType FROM sys.database_role_members drm JOIN sys.database_principals rolep ON rolep.principal_id=drm.role_principal_id JOIN sys.database_principals memberp ON memberp.principal_id=drm.member_principal_id ORDER BY rolep.name,memberp.name" },
        [pscustomobject]@{ Id='AZ-DB-EMPTY-CUSTOM-ROLES-001'; Scope='Database'; Purpose='Custom database roles with no members (Standard Check 113)'; Sql="SELECT rolep.name AS RoleName, rolep.principal_id AS PrincipalId, rolep.owning_principal_id AS OwningPrincipalId, ownerp.name AS OwnerName, rolep.create_date AS CreateDate FROM sys.database_principals rolep LEFT JOIN sys.database_role_members drm ON rolep.principal_id=drm.role_principal_id LEFT JOIN sys.database_principals ownerp ON rolep.owning_principal_id=ownerp.principal_id WHERE rolep.type='R' AND rolep.is_fixed_role=0 AND rolep.name<>'public' AND drm.member_principal_id IS NULL ORDER BY rolep.name" },
        [pscustomobject]@{ Id='AZ-DB-PERMISSIONS-001'; Scope='Database'; Purpose='Explicit database-scoped permissions and grantees'; Sql="SELECT grantee.name AS GranteeName, grantee.type_desc AS GranteeType, permission.state_desc, permission.permission_name, permission.class_desc, permission.major_id, permission.minor_id FROM sys.database_permissions permission LEFT JOIN sys.database_principals grantee ON grantee.principal_id=permission.grantee_principal_id ORDER BY grantee.name,permission.permission_name" },
        [pscustomobject]@{ Id='AZ-DB-OWNERSHIP-001'; Scope='Database'; Purpose='Current database identity, owner SID mapping where visible, and database properties'; Sql="SELECT DB_NAME() AS DatabaseName, ORIGINAL_LOGIN() AS AuthenticatedPrincipal, ownerp.name AS OwnerName, ownerp.type_desc AS OwnerType, d.owner_sid AS OwnerSid, d.state_desc AS State, d.compatibility_level AS CompatibilityLevel, d.collation_name AS CollationName FROM sys.databases d LEFT JOIN sys.database_principals ownerp ON ownerp.sid=d.owner_sid WHERE d.name=DB_NAME()" },
        [pscustomobject]@{ Id='AZ-DB-METADATA-PROBE-001'; Scope='Database'; Purpose='Check effective database-scoped VIEW DEFINITION permission; this does not prove Azure directory or control-plane completeness'; Sql="SELECT HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'VIEW DEFINITION') AS HasViewDefinition, IS_MEMBER('db_securityadmin') AS IsDbSecurityAdmin, IS_MEMBER('db_owner') AS IsDbOwner" },
        [pscustomobject]@{ Id='AZ-MASTER-SERVER-PRINCIPALS-001'; Scope='MasterOptional'; Purpose='Visible server principals'; Sql="SELECT principal_id,name,type_desc,is_disabled,create_date,modify_date FROM sys.server_principals WHERE principal_id > 4 ORDER BY principal_id" },
        [pscustomobject]@{ Id='AZ-MASTER-SERVER-ROLES-001'; Scope='MasterOptional'; Purpose='Visible server role memberships'; Sql="SELECT rolep.name AS RoleName,memberp.name AS MemberName,memberp.type_desc AS MemberType FROM sys.server_role_members rm JOIN sys.server_principals rolep ON rolep.principal_id=rm.role_principal_id JOIN sys.server_principals memberp ON memberp.principal_id=rm.member_principal_id ORDER BY rolep.name,memberp.name" },
        [pscustomobject]@{ Id='AZ-MASTER-SQL-LOGINS-001'; Scope='MasterOptional'; Purpose='SQL logins with password policy disabled (Standard Check 006)'; Sql="SELECT name AS LoginName, is_disabled AS IsDisabled, is_policy_checked AS IsPolicyChecked, is_expiration_checked AS IsExpirationChecked, create_date AS CreateDate, modify_date AS ModifyDate FROM sys.sql_logins WHERE is_policy_checked=0 ORDER BY name" },
        [pscustomobject]@{ Id='AZ-MASTER-METADATA-PROBE-001'; Scope='MasterOptional'; Purpose='Check effective logical-server security-definition visibility; this does not prove Azure resource or database inventory completeness'; Sql="SELECT HAS_PERMS_BY_NAME(NULL, 'SERVER', 'VIEW ANY SECURITY DEFINITION') AS HasViewAnySecurityDefinition" }
    )
}

function Get-AzureSqlErrorResult {
    param($Exception,[scriptblock]$FailureTranslator)
    if ($FailureTranslator) { return (& $FailureTranslator $Exception) }
    [pscustomobject]@{ Succeeded=$false; ErrorCategory='ConnectionFailed'; SupportCode='AZURE-SQL-ERROR'; UserMessage='Azure SQL operation failed. Sensitive driver and authentication diagnostics were suppressed.'; SanitizedDiagnostics=$null }
}

function Open-AzureSqlDatabaseConnection {
    param([string]$Server,[string]$Database,[scriptblock]$FailureTranslator,[scriptblock]$ConnectionFactory,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password)
    # A serverless database can return 40613 on its first connection while it
    # resumes. Retry only that error, using a new SqlConnection each time.
    $retryDelaysSeconds=@(5,10,15,20)
    for($attempt=0;$attempt -le $retryDelaysSeconds.Count;$attempt++) {
        $connection=$null
        try {
            $connection=New-AzureSqlConnection -Server $Server -Database $Database -AuthMethod $AuthMethod -Username $Username -Password $Password -ConnectionFactory $ConnectionFactory
            $connection.Open()
            return [pscustomobject]@{ Connection=$connection; Failure=$null }
        }
        catch {
            $failure=Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator
            if($null -ne $connection){$connection.Dispose()}
            $sqlNumber=if($failure.SanitizedDiagnostics){$failure.SanitizedDiagnostics.SqlErrorNumber}else{$null}
            if($null -ne $ConnectionFactory -or $sqlNumber -ne 40613 -or $attempt -ge $retryDelaysSeconds.Count){
                return [pscustomobject]@{ Connection=$null; Failure=$failure }
            }
            $delay=$retryDelaysSeconds[$attempt]
            Write-Warning ("Azure SQL database '{0}' is temporarily unavailable (40613). Retrying in {1} seconds, attempt {2} of {3}." -f $Database,$delay,($attempt+2),($retryDelaysSeconds.Count+1))
            Start-Sleep -Seconds $delay
        }
    }
}

function Invoke-AzureSqlReadQuery {
    param([string]$Server,[string]$Database,[string]$QueryId,[string]$Sql,[scriptblock]$FailureTranslator,[scriptblock]$ConnectionFactory,[object]$ExistingConnection,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password)
    $connection=$null; $command=$null; $reader=$null; $failureStage='ConnectionOpen'
    try {
        if ($null -ne $ExistingConnection) { $connection=$ExistingConnection }
        else {
            $connection = New-AzureSqlConnection -Server $Server -Database $Database -AuthMethod $AuthMethod -Username $Username -Password $Password -ConnectionFactory $ConnectionFactory
            $connection.Open()
        }
        $failureStage='ReadOnlyProbe'
        $command=$connection.CreateCommand(); $command.CommandText=$Sql
        $reader=$command.ExecuteReader()
        $rows=New-Object System.Collections.Generic.List[object]
        while ($reader.Read()) {
            $row=[ordered]@{}
            for ($i=0; $i -lt $reader.FieldCount; $i++) { $value=$reader.GetValue($i); $row[$reader.GetName($i)]= $(if ($value -is [DBNull]) {$null} else {$value}) }
            $rows.Add([pscustomobject]$row)
        }
        [pscustomobject]@{ Succeeded=$true; Rows=[object[]]$rows.ToArray(); ErrorCategory=$null; SupportCode=$null; UserMessage=$null }
    }
    catch {
        $failure=Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator
        [pscustomobject]@{ Succeeded=$false; Rows=@(); ErrorCategory=$failure.ErrorCategory; SupportCode=$failure.SupportCode; UserMessage=$failure.UserMessage; FailureStage=$failureStage; SanitizedDiagnostics=$failure.SanitizedDiagnostics }
    }
    finally { if ($null -ne $reader) {$reader.Dispose()}; if ($null -ne $command) {$command.Dispose()}; if ($null -eq $ExistingConnection -and $null -ne $connection) {$connection.Dispose()} }
}

function Test-AzureSqlConnection {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Server,[Parameter(Mandatory=$true)][string]$Database,[Parameter(Mandatory=$true)][scriptblock]$FailureTranslator,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password,[scriptblock]$ConnectionFactory)
    $result=Invoke-AzureSqlReadQuery -Server $Server -Database $Database -QueryId 'AZ-CONNECTION-001' -Sql 'SELECT DB_NAME() AS DatabaseName, ORIGINAL_LOGIN() AS PrincipalName' -FailureTranslator $FailureTranslator -AuthMethod $AuthMethod -Username $Username -Password $Password -ConnectionFactory $ConnectionFactory
    if (-not $result.Succeeded) { return [pscustomobject]@{ Succeeded=$false; ErrorCategory=$result.ErrorCategory; SupportCode=$result.SupportCode; UserMessage=$result.UserMessage; FailureStage=$result.FailureStage; SanitizedDiagnostics=$result.SanitizedDiagnostics } }
    $row=$result.Rows[0]
    [pscustomobject]@{ Succeeded=$true; DatabaseName=[string]$row.DatabaseName; PrincipalName=[string]$row.PrincipalName; Encrypt='Strict'; TrustServerCertificate=$false; FailureStage=$null; SanitizedDiagnostics=$null }
}

function Get-AzureSqlDatabaseInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Server,[Parameter(Mandatory=$true)][scriptblock]$FailureTranslator,[scriptblock]$ConnectionFactory,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password)
    $connection=$null
    try {
        $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database 'master' -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
        if($opened.Failure){return [pscustomobject]@{ Succeeded=$false; Databases=@(); ServerEvidence=@(); ErrorCategory=$opened.Failure.ErrorCategory; SupportCode=$opened.Failure.SupportCode; UserMessage=$opened.Failure.UserMessage; SanitizedDiagnostics=$opened.Failure.SanitizedDiagnostics }}
        $connection=$opened.Connection
        $query=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-MASTER-INVENTORY-001' -Sql 'SELECT name FROM sys.databases WHERE state = 0 ORDER BY name' -FailureTranslator $FailureTranslator -ExistingConnection $connection -AuthMethod $AuthMethod -Username $Username -Password $Password
        if (-not $query.Succeeded) { return [pscustomobject]@{ Succeeded=$false; Databases=@(); ErrorCategory=$query.ErrorCategory; SupportCode=$query.SupportCode; UserMessage=$query.UserMessage; SanitizedDiagnostics=$null } }
        $serverEvidence=New-Object System.Collections.Generic.List[object]
        foreach ($serverQuery in @(Get-AzureSqlQueryMatrix | Where-Object Scope -eq 'MasterOptional')) {
            $serverResult=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId $serverQuery.Id -Sql $serverQuery.Sql -FailureTranslator $FailureTranslator -ExistingConnection $connection -AuthMethod $AuthMethod -Username $Username -Password $Password
            $serverEvidence.Add([pscustomobject]@{ QueryId=$serverQuery.Id; Purpose=$serverQuery.Purpose; Status=$(if ($serverResult.Succeeded) {'Succeeded'} elseif ($serverResult.ErrorCategory -eq 'DatabaseAccessDenied') {'InsufficientPermission'} else {'Failed'}); Rows=$(if ($serverResult.Succeeded) {@($serverResult.Rows)} else {@()}); ErrorCategory=$serverResult.ErrorCategory; SupportCode=$serverResult.SupportCode; UserMessage=$serverResult.UserMessage })
        }
        [pscustomobject]@{ Succeeded=$true; Databases=[string[]]@($query.Rows | ForEach-Object { [string]$_.name }); ServerEvidence=[object[]]$serverEvidence.ToArray(); ErrorCategory=$null; SupportCode=$null; UserMessage=$null; VisibilityNote='sys.databases returns only metadata visible to this identity; the list may be incomplete.'; SanitizedDiagnostics=$null }
    } catch {
        $failure=Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator
        [pscustomobject]@{ Succeeded=$false; Databases=@(); ServerEvidence=@(); ErrorCategory=$failure.ErrorCategory; SupportCode=$failure.SupportCode; UserMessage=$failure.UserMessage; SanitizedDiagnostics=$null }
    } finally { if ($null -ne $connection) {$connection.Dispose()} }
}

function Invoke-AzureSqlEvidenceCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Server,[string]$Database,[switch]$AllVisibleDatabases,[scriptblock]$FailureTranslator,[scriptblock]$ConnectionFactory,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password)
    if (($AllVisibleDatabases -and -not [string]::IsNullOrWhiteSpace($Database)) -or (-not $AllVisibleDatabases -and [string]::IsNullOrWhiteSpace($Database))) {
        throw [ArgumentException]::new('Specify exactly one of Database or AllVisibleDatabases.')
    }
    $started=[datetime]::UtcNow; $scope=if ($AllVisibleDatabases) {'AllVisibleDatabases'} else {'ExplicitDatabase'}
    $inventory=$null; $principal=$null; $targets=@()
    if ($AllVisibleDatabases) {
        $inventory=Get-AzureSqlDatabaseInventory -Server $Server -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
        if ($inventory.Succeeded) { $targets=@($inventory.Databases | Where-Object { $_ -ne 'master' }) }
    } else { $targets=@($Database) }
    $matrix=@(Get-AzureSqlQueryMatrix | Where-Object Scope -eq 'Database')
    $databaseResults=New-Object System.Collections.Generic.List[object]
    foreach ($target in $targets) {
        $databaseStarted=[datetime]::UtcNow; $queryResults=New-Object System.Collections.Generic.List[object]; $databaseConnection=$null
        $probe=$null; $dbPrincipal=$null; $connectionFailure=$null
        $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database $target -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
        $databaseConnection=$opened.Connection
        $connectionFailure=$opened.Failure
        foreach ($query in $matrix) {
            if ($connectionFailure) { $queryResult=[pscustomobject]@{ Succeeded=$false; Rows=@(); ErrorCategory=$connectionFailure.ErrorCategory; SupportCode=$connectionFailure.SupportCode; UserMessage=$connectionFailure.UserMessage } }
            else { $queryResult=Invoke-AzureSqlReadQuery -Server $Server -Database $target -QueryId $query.Id -Sql $query.Sql -FailureTranslator $FailureTranslator -ExistingConnection $databaseConnection }
            $queryRecord=[pscustomobject]@{ QueryId=$query.Id; Purpose=$query.Purpose; Status=$(if ($queryResult.Succeeded) {'Succeeded'} elseif ($queryResult.ErrorCategory -eq 'DatabaseAccessDenied') {'InsufficientPermission'} else {'Failed'}); Rows=$(if ($queryResult.Succeeded) {@($queryResult.Rows)} else {@()}); ErrorCategory=$queryResult.ErrorCategory; SupportCode=$queryResult.SupportCode; UserMessage=$queryResult.UserMessage }
            $queryResults.Add($queryRecord)
            if ($query.Id -eq 'AZ-DB-METADATA-PROBE-001' -and $queryResult.Succeeded -and $queryResult.Rows.Count -gt 0) { $probe=$queryResult.Rows[0] }
            if ($query.Id -eq 'AZ-DB-OWNERSHIP-001' -and $queryResult.Succeeded -and $queryResult.Rows.Count -gt 0) { $dbPrincipal=[string]$queryResult.Rows[0].AuthenticatedPrincipal }
        }
        if ($null -ne $databaseConnection) { $databaseConnection.Dispose() }
        $failedQueries=@($queryResults | Where-Object Status -in @('InsufficientPermission','Failed')).Count
        $firstFailed=@($queryResults | Where-Object Status -in @('InsufficientPermission','Failed') | Select-Object -First 1)
        $status='Collected'
        if ($connectionFailure) { $status=if ($connectionFailure.ErrorCategory -eq 'NetworkAccessDenied') {'NetworkAccessDenied'} elseif ($connectionFailure.ErrorCategory -in @('AuthenticationFailed','DatabaseAccessDenied')) {'AccessDenied'} else {'ConnectionFailed'} }
        elseif ($failedQueries -gt 0) { $status='Partial' }
        $metadataVisible=($null -ne $probe -and [int]$probe.HasViewDefinition -eq 1)
        $visibility=if ($null -eq $probe) {'Unknown; metadata visibility probe did not succeed.'} elseif ($metadataVisible) {'Effective database-scoped VIEW DEFINITION confirmed. This supports complete visibility for the documented database catalog checks only; it does not prove Azure directory, control-plane, or logical-server inventory completeness.'} else {'VIEW DEFINITION was not confirmed. Empty catalog results remain Not Assessed; dbo/db_owner membership is recorded as context and is not used as a substitute visibility assertion.'}
        $principalRow=@($queryResults | Where-Object QueryId -eq 'AZ-DB-OWNERSHIP-001' | ForEach-Object Rows | Select-Object -First 1)
        $evidenceRows=New-Object System.Collections.Generic.List[object]
        foreach ($queryRecord in $queryResults) { foreach ($row in $queryRecord.Rows) { $evidenceRows.Add([pscustomobject]@{ Platform='AzureSQLDatabase'; LogicalServer=$Server; Database=[string]$target; QueryId=$queryRecord.QueryId; Row=$row }) } }
        $databaseResults.Add([pscustomobject]@{ Database=[string]$target; Status=$status; AuthenticatedPrincipal=$dbPrincipal; StartedAt=$databaseStarted; EndedAt=[datetime]::UtcNow; EvidenceQueries=[object[]]$queryResults.ToArray(); EvidenceRows=[object[]]$evidenceRows.ToArray(); MetadataVisibility=$visibility; MetadataVisibilitySufficient=$metadataVisible; ErrorCategory=$(if ($connectionFailure) {$connectionFailure.ErrorCategory} elseif ($firstFailed.Count) {$firstFailed[0].ErrorCategory} else {$null}); SupportCode=$(if ($connectionFailure) {$connectionFailure.SupportCode} elseif ($firstFailed.Count) {$firstFailed[0].SupportCode} else {$null}); UserMessage=$(if ($connectionFailure) {$connectionFailure.UserMessage} elseif ($firstFailed.Count) {$firstFailed[0].UserMessage} else {$null}); EvidenceQueryIds=[string[]]@($matrix.Id) })
    }
    if ($AllVisibleDatabases -and -not $inventory.Succeeded) {
        $databaseResults.Add([pscustomobject]@{ Database=$null; Status='InventoryIncomplete'; AuthenticatedPrincipal=$null; StartedAt=$started; EndedAt=[datetime]::UtcNow; EvidenceQueries=@(); MetadataVisibility='Master inventory unavailable; unseen databases were not assessed.'; ErrorCategory=$inventory.ErrorCategory; SupportCode=$inventory.SupportCode; UserMessage=$inventory.UserMessage; EvidenceQueryIds=@() })
    }
    New-AzureSqlResult -Server $Server -Scope $scope -Principal $principal -DatabaseResults @($databaseResults.ToArray()) -Inventory $inventory -Started $started
}

function Get-AzureSqlDiagnosticBatches {
    param([Parameter(Mandatory=$true)][string]$SqlText)
    $byCheck=@{}
    foreach($batch in @($SqlText -split '(?im)^\s*GO\s*$')) {
        if([string]::IsNullOrWhiteSpace($batch)){continue}
        $ids=New-Object System.Collections.Generic.List[string]
        $matches=[regex]::Matches($batch,"(?i)(?:N)?(?:''|')(?<CheckId>\d{1,3})(?:''|')\s+AS\s+\[(?:Check\s*ID|CheckID)\]")
        foreach($match in $matches) {
            $id=([string]$match.Groups['CheckId'].Value).PadLeft(3,'0')
            if(-not $ids.Contains($id)){$ids.Add($id)}
        }
        # A few legacy checks build the output row dynamically and therefore
        # do not contain a literal `'<id>' AS [Check ID]` in the batch text.
        # Their dedicated @CheckNNN table/variable declarations identify the
        # owning batch without changing or rewriting the original SQL.
        if($ids.Count -eq 0) {
            $fallback=[regex]::Match($batch,'(?i)@Check(?<CheckId>\d{1,3})\b')
            if($fallback.Success){$ids.Add(([string]$fallback.Groups['CheckId'].Value).PadLeft(3,'0'))}
        }
        foreach($id in $ids) {
            if(-not $byCheck.ContainsKey($id)){$byCheck[$id]=New-Object System.Collections.Generic.List[string]}
            $byCheck[$id].Add($batch.Trim())
        }
    }
    $byCheck
}

function Get-AzureSqlCheckProfile {
    param([string]$CheckId)
    $profiles=@{
        '006'=@{Outcome='PASS';Label='Service managed';Message='SQL authentication password policy enforcement is controlled by Azure SQL Database.'}
        '008'=@{Outcome='INFO';Label='Not applicable';Message='Azure SQL Database does not expose the SQL Server sa login model.'}
        '010'=@{Outcome='INFO';Label='Not applicable';Message='Azure SQL Database does not expose SQL Server sysadmin role membership.'}
        '028'=@{Outcome='PASS';Label='Service managed';Message='TRUSTWORTHY is not customer-configurable in Azure SQL Database.'}
        '059'=@{Outcome='INFO';Label='Outside SQL visibility';Message='The effective Azure SQL auditing configuration cannot be determined from the SQL metadata collected by this tool. Verify server-level and database-level auditing policies through the Azure control plane using Azure PowerShell, Azure CLI, REST API, or the Azure portal. Server-level auditing can cover a database even when its database-level policy is disabled.'}
        '072'=@{Outcome='INFO';Label='Not applicable';Message='Azure SQL Database does not expose SQL Server sysadmin membership, so this SQL Server database-owner escalation pattern does not apply.'}
        '078'=@{Outcome='INFO';Label='Not applicable';Message='Azure SQL Database does not use the SQL Server Windows-account database-owner model assessed by this check.'}
        '079'=@{Outcome='INFO';Label='Not applicable';Message='Azure SQL Database does not expose the SQL Server sa login model.'}
        '123'=@{Outcome='PASS';Label='Service managed';Message='AUTO_CLOSE is not customer-configurable in Azure SQL Database.'}
        '155'=@{Outcome='PASS';Label='Service managed';Message='Azure SQL Database does not expose the SQL Server instance-level database-owner SID mapping model used by this check.'}
    }
    if($profiles.ContainsKey($CheckId)){return [pscustomobject]$profiles[$CheckId]}
    return $null
}

function Get-AzureSqlAdministratorObservation {
    param([string]$Server,[scriptblock]$FailureTranslator,$Connection)
    $probe=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-ADMIN-VISIBILITY' -Sql 'SELECT COUNT(*) AS VisibleSessionCount FROM sys.dm_exec_sessions WHERE session_id <= 50;' -FailureTranslator $FailureTranslator -ExistingConnection $Connection
    if(-not $probe.Succeeded -or $probe.Rows.Count -ne 1){return 'Unavailable'}
    if([int]$probe.Rows[0].VisibleSessionCount -gt 11){return 'LikelyAdministrator'}
    return 'NotAdministrator'
}

function Test-AzureSqlPermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Server,[Parameter(Mandatory=$true)][scriptblock]$FailureTranslator,[ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',[string]$Username,[System.Security.SecureString]$Password,[scriptblock]$ConnectionFactory)
    $connection=$null
    try {
        $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database 'master' -FailureTranslator $FailureTranslator -AuthMethod $AuthMethod -Username $Username -Password $Password -ConnectionFactory $ConnectionFactory
        if($opened.Failure){return $opened.Failure}
        $connection=$opened.Connection
        $metadata=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-PERMISSION-IDENTITY' -Sql "SELECT ORIGINAL_LOGIN() AS ExecutionLogin, CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS ProductVersion" -FailureTranslator $FailureTranslator -ExistingConnection $connection
        if(-not $metadata.Succeeded){return $metadata}
        $permissions=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-SERVER-PERMISSIONS' -Sql "SELECT * FROM sys.fn_my_permissions(NULL, 'SERVER');" -FailureTranslator $FailureTranslator -ExistingConnection $connection
        if(-not $permissions.Succeeded){return $permissions}
        $databasePermissions=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-DATABASE-PERMISSIONS' -Sql "SELECT * FROM sys.fn_my_permissions(NULL, 'DATABASE');" -FailureTranslator $FailureTranslator -ExistingConnection $connection
        if(-not $databasePermissions.Succeeded){return $databasePermissions}
        $rows=@(foreach($name in @('VIEW SERVER SECURITY STATE','VIEW SERVER PERFORMANCE STATE','CONNECT ANY DATABASE')){
            [pscustomobject]@{RoleOrPermission=$name;CheckStatus=$(if(@($permissions.Rows | Where-Object permission_name -eq $name).Count){'Yes'}else{'No'})}
        })
        $rows += [pscustomobject]@{RoleOrPermission='VIEW SECURITY DEFINITION (master)';CheckStatus=$(if(@($databasePermissions.Rows | Where-Object permission_name -eq 'VIEW SECURITY DEFINITION').Count){'Yes'}else{'No'})}
        $administratorObservation=Get-AzureSqlAdministratorObservation -Server $Server -FailureTranslator $FailureTranslator -Connection $connection
        $adminTitle=if($AuthMethod -eq 'EntraInteractive'){'Microsoft Entra administrator'}else{'Server admin'}
        $administratorMessage=switch($administratorObservation){
            'LikelyAdministrator' {"Likely the $adminTitle, based on indirect observation."}
            'NotAdministrator' {"Indirect observation indicates that the current identity is not the $adminTitle."}
            default {'Administrator visibility probe unavailable.'}
        }
        [pscustomobject]@{Succeeded=$true;ExecutionLogin=[string]$metadata.Rows[0].ExecutionLogin;SqlServerVersion=('Azure SQL Database ({0})' -f $metadata.Rows[0].ProductVersion);ProductVersion=[string]$metadata.Rows[0].ProductVersion;Rows=$rows;HasInsufficientAccess=(@($rows | Where-Object CheckStatus -ne 'Yes').Count -gt 0);AdministratorObservation=$administratorObservation;Notes=($administratorMessage+' Azure SQL Database does not provide metadata to determine this with certainty. Use the Azure control plane to verify administrator status.')}
    }
    catch {Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator}
    finally {if($null -ne $connection){$connection.Dispose()}}
}

function Get-AzureSqlUnsupportedChecks {
    [ordered]@{
        '802'='Contained availability groups are a SQL Server engine feature and are not exposed for Azure SQL Database.'
        '806'='SQL Server sp_configure/reconfigure pending-change state is not exposed as an Azure SQL Database instance setting.'
        '030'='The SQL Server instance-wide cross-database ownership chaining option is not exposed for Azure SQL Database.'
        '031'='The database-level cross-database ownership chaining setting is not supported in Azure SQL Database.'
        '034'='xp_cmdshell is not available in Azure SQL Database.'
        '036'='Ad Hoc Distributed Queries is a SQL Server instance option and is not available in Azure SQL Database.'
        '038'='OLE Automation procedures are not available in Azure SQL Database.'
        '011'='Azure SQL Database does not expose the SQL Server custom server-role permission graph evaluated by this check.'
        '026'='The SQL Server instance-level permissions granted to logins are not exposed in Azure SQL Database. This check is grouped under Account dependencies and orphaned accounts.'
        '027'='Azure SQL Database does not expose the SQL Server custom server-role model. This check is grouped under Account dependencies and orphaned accounts.'
        '046'='This check uses sp_validatelogins to validate Windows Active Directory logins, which are not Azure SQL Database logins.'
        '129'='The original orphaned-user query relies on SQL Server login mappings and availability-group metadata; contained Azure SQL Database users do not require a matching server login.'
        '050'='The SQL Server instance error-log count is not exposed; Azure SQL Database error-log retention is service-managed.'
        '069'='The SQL Server login-failure error-log setting is not exposed; Azure SQL Database login auditing requires service-side evidence.'
    }
}

function Get-AzureSqlServerRoleMembershipQuery {
    @'
;WITH LoginPrincipals AS
(
    SELECT
        principal_id,
        name COLLATE DATABASE_DEFAULT AS name,
        type COLLATE DATABASE_DEFAULT AS type,
        type_desc COLLATE DATABASE_DEFAULT AS type_desc,
        create_date,
        modify_date,
        is_disabled
    FROM sys.sql_logins
    WHERE type = 'S'

    UNION ALL

    SELECT
        principal_id,
        name COLLATE DATABASE_DEFAULT AS name,
        type COLLATE DATABASE_DEFAULT AS type,
        type_desc COLLATE DATABASE_DEFAULT AS type_desc,
        create_date,
        modify_date,
        is_disabled
    FROM sys.server_principals
    WHERE type = 'E'
)
SELECT
    '015' AS [Check ID],
    roles.name AS ServerRoleName,
    members.name AS MemberName,
    CASE members.type WHEN 'S' THEN N'SQL Login' WHEN 'E' THEN N'Entra ID Login' END AS LoginType,
    (
        SELECT
            CASE members.type WHEN 'S' THEN N'SQL Login' WHEN 'E' THEN N'Entra ID Login' END AS MemberType,
            members.create_date,
            members.modify_date,
            members.is_disabled
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.server_role_members AS rm
INNER JOIN sys.server_principals AS roles
    ON rm.role_principal_id = roles.principal_id
INNER JOIN LoginPrincipals AS members
    ON rm.member_principal_id = members.principal_id
WHERE roles.name IN
(
    N'##MS_DatabaseManager##',
    N'##MS_LoginManager##',
    N'##MS_SecurityDefinitionReader##',
    N'##MS_ServerSecurityStateReader##'
)
ORDER BY roles.name, members.name;
'@
}

function Get-AzureSqlEmptyDatabaseRolesQuery {
    @'
SELECT
    '113' AS [Check ID],
    DB_NAME() AS DatabaseName,
    roles.name AS DatabaseRoleName,
    roles.principal_id AS PrincipalId,
    (
        SELECT
            DB_NAME() AS DatabaseName,
            roles.create_date,
            roles.owning_principal_id,
            owners.name
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.database_principals AS roles
LEFT JOIN sys.database_role_members AS members
    ON roles.principal_id = members.role_principal_id
LEFT JOIN sys.database_principals AS owners
    ON roles.owning_principal_id = owners.principal_id
WHERE roles.type = 'R'
  AND members.member_principal_id IS NULL
  AND roles.is_fixed_role = 0
  AND roles.name <> N'public'
ORDER BY roles.name;
'@
}

function Get-AzureSqlDatabaseOwnerMembersQuery {
    @'
SELECT
    '130' AS [Check ID],
    DB_NAME() AS DatabaseName,
    member.name AS MemberName,
    member.type_desc AS Principal_Type,
    (
        SELECT
            member.principal_id,
            member.authentication_type_desc AS AuthType,
            member.create_date,
            member.modify_date
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo
FROM sys.database_role_members AS database_role_members
INNER JOIN sys.database_principals AS database_role
    ON database_role_members.role_principal_id = database_role.principal_id
INNER JOIN sys.database_principals AS member
    ON database_role_members.member_principal_id = member.principal_id
WHERE database_role.name = N'db_owner'
  AND member.name <> N'dbo'
ORDER BY member.name;
'@
}

function Get-AzureSqlAuthenticationModeQuery {
    @'
SELECT
    '002' AS [Check ID],

    CASE
        WHEN SERVERPROPERTY('EngineEdition') = 5 -- Azure SQL Database
        THEN
            CASE SERVERPROPERTY('IsExternalAuthenticationOnly')
                WHEN 1 THEN 'Entra-only Authentication'
                WHEN 0 THEN 'SQL Authentication enabled'
                ELSE 'Unknown'
            END
        ELSE
            CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                WHEN 1 THEN 'Windows Authentication'
                WHEN 0 THEN 'Windows and SQL Server Authentication (Mixed Mode)'
                ELSE 'Unknown'
            END
    END AS AuthenticationMode,

    CASE
        WHEN SERVERPROPERTY('EngineEdition') = 5 -- Azure SQL Database
            THEN SERVERPROPERTY('IsExternalAuthenticationOnly')
        ELSE
            SERVERPROPERTY('IsIntegratedSecurityOnly')
    END AS AuthenticationModeValue,

    (
        SELECT
            SERVERPROPERTY('IsIntegratedSecurityOnly') AS IsIntegratedSecurityOnly,
            SERVERPROPERTY('IsExternalAuthenticationOnly') AS IsExternalAuthenticationOnly,
            SERVERPROPERTY('IsExternalGovernanceEnabled') AS IsExternalGovernanceEnabled,
            (
                SELECT
                    client_id,
                    identity_type,
                    tenant_id,
                    is_primary
                FROM sys.dm_server_managed_identities
                WHERE tenant_id IS NOT NULL
                FOR XML PATH('ManagedIdentity'), TYPE
            ) AS ManagedIdentities
        FOR XML PATH('AdditionalInfo'), TYPE
    ) AS AdditionalInfo;
'@
}

function Get-AzureSqlSystemOverviewQuery {
    param([bool]$IncludeAdministratorCounts=$false)
    $query=@'
DECLARE @EngineEdition int=TRY_CONVERT(int,SERVERPROPERTY('EngineEdition'));
DECLARE @ProductVersion nvarchar(128)=CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion'));
DECLARE @ProductMajorVersion int=TRY_CONVERT(int,PARSENAME(@ProductVersion,4));
DECLARE @VisibleDatabaseCount int;
DECLARE @DatabaseCompatibilityLevel int;
DECLARE @DatabaseState nvarchar(60);
DECLARE @DatabaseCollation nvarchar(128);
DECLARE @CatalogDatabaseId int;
DECLARE @CurrentDatabase sysname=DB_NAME();
DECLARE @ConnectionCount nvarchar(260);
DECLARE @LoginCount nvarchar(260);
DECLARE @IncludeAdministratorCounts bit=__ADMIN_COUNTS__;
SELECT @VisibleDatabaseCount=COUNT(*) FROM sys.databases;
SELECT @CatalogDatabaseId=database_id,@DatabaseCompatibilityLevel=compatibility_level,
       @DatabaseState=state_desc,@DatabaseCollation=collation_name
FROM sys.databases WHERE name=@CurrentDatabase;
IF @IncludeAdministratorCounts=1
BEGIN
BEGIN TRY
    SELECT @ConnectionCount=CONVERT(nvarchar(30),COUNT(*))+N' observed eligible connections'
    FROM sys.dm_exec_connections
    WHERE protocol_type <> 'Database Mirroring' AND net_transport <> 'Shared memory';
END TRY
BEGIN CATCH
    SET @ConnectionCount=N'Unavailable - connection visibility query failed. SQL error '+CONVERT(nvarchar(20),ERROR_NUMBER())+N'.';
END CATCH;
BEGIN TRY
    SELECT @LoginCount=CONVERT(nvarchar(260),COUNT(*))
    FROM (
        SELECT principal_id FROM sys.sql_logins
        UNION
        SELECT principal_id FROM sys.server_principals WHERE type IN ('E','X')
    ) AS VisibleLogins;
END TRY
BEGIN CATCH
    SET @LoginCount=N'Unavailable - login inventory query failed. SQL error '+CONVERT(nvarchar(20),ERROR_NUMBER())+N'.';
END CATCH;
END;
SELECT '800' AS [Check ID],Item,Value
FROM (VALUES
    (1,N'Product Major Version',COALESCE(CONVERT(nvarchar(260),@ProductMajorVersion),N'Unavailable - ProductVersion did not return a major version.')),
    (2,N'SQL Server Version',N'Azure SQL Database (service-updated; build numbers are not SQL Server release numbers)'),
    (3,N'Edition',COALESCE(CONVERT(nvarchar(260),SERVERPROPERTY('Edition')),N'Unavailable - Edition property returned NULL.')),
    (4,N'Product Level',COALESCE(CONVERT(nvarchar(260),SERVERPROPERTY('ProductLevel')),N'Unavailable - ProductLevel property returned NULL.')),
    (6,N'Version Number',COALESCE(@ProductVersion,N'Unavailable - ProductVersion property returned NULL.')),
    (8,N'Resource Last Update DateTime',COALESCE(CONVERT(nvarchar(260),SERVERPROPERTY('ResourceLastUpdateDateTime')),N'Unavailable - resource update time was not returned by SQL metadata.' )),
    (9,N'Resource Version',COALESCE(CONVERT(nvarchar(260),SERVERPROPERTY('ResourceVersion')),N'Unavailable - ResourceVersion property returned NULL.')),
    (10,N'Engine Edition',CASE WHEN @EngineEdition=5 THEN N'Azure SQL Database' ELSE COALESCE(N'Unknown (EngineEdition='+CONVERT(nvarchar(20),@EngineEdition)+N')',N'Unknown') END),
    (11,N'AWS RDS detected',N'Not applicable - this target is Azure SQL Database.'),
    (21,N'Number Databases Visible to Identity',CONVERT(nvarchar(260),@VisibleDatabaseCount)+N' (sys.databases metadata visible to this identity; inventory may be incomplete)'),
    (22,N'Number Logins',@LoginCount),
    (23,N'Current Active Connections',@ConnectionCount),
    (24,N'Current Database',COALESCE(CONVERT(nvarchar(260),@CurrentDatabase),N'Unknown')),
    (25,N'Database ID',COALESCE(CONVERT(nvarchar(260),@CatalogDatabaseId),N'Unavailable - database catalog row was not visible.')),
    (26,N'Database Compatibility Level',COALESCE(CONVERT(nvarchar(260),@DatabaseCompatibilityLevel),N'Unavailable - compatibility level was not visible.' )),
    (27,N'Database State',COALESCE(@DatabaseState,N'Unavailable - database state was not visible.' )),
    (28,N'Database Collation',COALESCE(@DatabaseCollation,N'Unavailable - database collation was not returned.'))
) AS SystemOverview(SortOrder,Item,Value)
WHERE @IncludeAdministratorCounts=1 OR SortOrder NOT IN (22,23)
ORDER BY SortOrder;
'@
    return $query.Replace('__ADMIN_COUNTS__',$(if($IncludeAdministratorCounts){'1'}else{'0'}))
}

function Invoke-AzureSqlDiagnosticBatch {
    param([Parameter(Mandatory=$true)][object]$Connection,[Parameter(Mandatory=$true)][string]$Sql,[scriptblock]$FailureTranslator)
    $command=$null;$reader=$null
    try {
        $command=$Connection.CreateCommand();$command.CommandText=$Sql;$command.CommandTimeout=120
        $reader=$command.ExecuteReader();$rows=New-Object System.Collections.Generic.List[object]
        do {
            if($reader.FieldCount -gt 0) {
                while($reader.Read()) {
                    $row=[ordered]@{}
                    for($i=0;$i -lt $reader.FieldCount;$i++) {$value=$reader.GetValue($i);$row[$reader.GetName($i)]=if($value -is [DBNull]){$null}else{$value}}
                    $rows.Add([pscustomobject]$row)
                }
            }
        } while($reader.NextResult())
        [pscustomobject]@{Succeeded=$true;Rows=[object[]]$rows.ToArray();ErrorCategory=$null;SupportCode=$null;UserMessage=$null;SqlErrorNumber=$null}
    } catch {
        $failure=Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator
        $sqlNumber=$null
        if($failure.SanitizedDiagnostics -and $null -ne $failure.SanitizedDiagnostics.SqlErrorNumber){$sqlNumber=$failure.SanitizedDiagnostics.SqlErrorNumber}
        [pscustomobject]@{Succeeded=$false;Rows=@();ErrorCategory=$failure.ErrorCategory;SupportCode=$failure.SupportCode;UserMessage=$failure.UserMessage;SqlErrorNumber=$sqlNumber}
    } finally {if($null -ne $reader){$reader.Dispose()};if($null -ne $command){$command.Dispose()}}
}

function Get-AzureSqlDiagnosticFailureExplanation {
    param([string]$ErrorCategory,[string]$SupportCode,[object]$SqlErrorNumber,[string]$Stage)
    $detail=switch($ErrorCategory) {
        'OptionalModuleMissing' {'Entra authentication requires the Microsoft Az.Accounts module, version 5.3.4 or later. See README.md for the installation command.';break}
        'AuthenticationWindowRequired' {'Entra interactive sign-in could not obtain a parent window. Open a fresh interactive PowerShell window and run the updated Azure package.';break}
        'AuthenticationFailed' {'Azure SQL rejected the selected authentication method or credentials.';break}
        'NetworkAccessDenied' {'The server could not be reached from this network or the client is not allowed by the server network rules.';break}
        'DatabaseAccessDenied' {'The authenticated identity could not open the requested database or lacks permission for this check.';break}
        default {if($Stage -eq 'ConnectionOpen'){'Azure SQL did not allow a connection to this database.'}else{'Azure SQL could not execute this original SQL Server check batch; the object, permission, or syntax may not be supported in this Azure SQL Database context.'}}
    }
    if($null -ne $SqlErrorNumber){$detail+=' SQL error number: {0}.' -f $SqlErrorNumber}
    if(-not [string]::IsNullOrWhiteSpace($SupportCode)){$detail+=' Support code: {0}.' -f $SupportCode}
    $detail
}

function Invoke-AzureSqlCompatibilityAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Server,
        [string]$Database,
        [switch]$AllVisibleDatabases,
        [Parameter(Mandatory=$true)][string]$OriginalSql,
        [Parameter(Mandatory=$true)][object[]]$CheckCatalog,
        [string[]]$SkipCheckIds=@(),
        [Parameter(Mandatory=$true)][scriptblock]$FailureTranslator,
        [ValidateSet('EntraInteractive','SQL')][string]$AuthMethod='EntraInteractive',
        [string]$Username,
        [System.Security.SecureString]$Password,
        [scriptblock]$ConnectionFactory
    )
    if(($AllVisibleDatabases -and -not [string]::IsNullOrWhiteSpace($Database)) -or (-not $AllVisibleDatabases -and [string]::IsNullOrWhiteSpace($Database))){throw [ArgumentException]::new('Specify exactly one of Database or AllVisibleDatabases.')}
    $started=[datetime]::UtcNow;$scope=if($AllVisibleDatabases){'AllVisibleDatabases'}else{'ExplicitDatabase'}
    $batchMap=Get-AzureSqlDiagnosticBatches -SqlText $OriginalSql
    # These original IDs have Azure-specific queries. The standard
    # embedded SQL stays unchanged and is still used by the SQL Server path.
    $batchMap['002']=New-Object System.Collections.Generic.List[string]
    $batchMap['002'].Add((Get-AzureSqlAuthenticationModeQuery).Trim())
    $batchMap['015']=New-Object System.Collections.Generic.List[string]
    $batchMap['015'].Add((Get-AzureSqlServerRoleMembershipQuery).Trim())
    $batchMap['113']=New-Object System.Collections.Generic.List[string]
    $batchMap['113'].Add((Get-AzureSqlEmptyDatabaseRolesQuery).Trim())
    $batchMap['130']=New-Object System.Collections.Generic.List[string]
    $batchMap['130'].Add((Get-AzureSqlDatabaseOwnerMembersQuery).Trim())
    $batchMap['800']=New-Object System.Collections.Generic.List[string]
    $batchMap['800'].Add((Get-AzureSqlSystemOverviewQuery).Trim())
    $unsupportedChecks=Get-AzureSqlUnsupportedChecks
    $skipLookup=@{};foreach($id in $SkipCheckIds){$skipLookup[([string]$id).PadLeft(3,'0')]=$true}
    $requestedSkipCheckIds=[string[]]@($skipLookup.Keys)
    $inventoryStatus='NotRequested';$inventoryError=$null;$targets=@();$noVisibleDatabases=$false
    if($AllVisibleDatabases) {
        $inventoryStatus='Failed'
        $master=$null
        try {
            $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database 'master' -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
            if($opened.Failure){$inventoryError=$opened.Failure}
            else {
                $master=$opened.Connection
                $inventory=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-COMPAT-INVENTORY' -Sql 'SELECT name FROM sys.databases WHERE state=0 ORDER BY name' -FailureTranslator $FailureTranslator -ExistingConnection $master -AuthMethod $AuthMethod -Username $Username -Password $Password
                if($inventory.Succeeded) {$targets=@($inventory.Rows|ForEach-Object{[string]$_.name}|Where-Object{$_ -ne 'master'});$inventoryStatus='Collected';if($targets.Count -eq 0){$targets=@($null);$noVisibleDatabases=$true}}
                else {$inventoryError=$inventory}
            }
        } catch {$failure=Get-AzureSqlErrorResult -Exception $_ -FailureTranslator $FailureTranslator;$inventoryError=$failure;$inventoryStatus='Failed'} finally {if($null -ne $master){$master.Dispose()}}
    } else {$targets=@($Database)}
    $databaseRuns=New-Object System.Collections.Generic.List[object]
    $masterChecks=@()
    $authenticatedPrincipal=$null
    $administratorObservation='Unavailable'
    $masterSectionIds=@('0','6','12','13')
    if($AllVisibleDatabases -and $inventoryStatus -ne 'Collected'){$targets=@($null)}
    $executionTargets=New-Object System.Collections.Generic.List[object]
    foreach($target in $targets){$executionTargets.Add([pscustomobject]@{Database=$target;MasterOnly=$false})}
    $executionTargets.Add([pscustomobject]@{Database='master';MasterOnly=$true})
    foreach($executionTarget in $executionTargets) {
        $target=$executionTarget.Database;$masterOnly=[bool]$executionTarget.MasterOnly
        $connection=$null;$connectionFailure=$null;$databaseName=if($null -eq $target){$null}else{[string]$target}
        if($null -eq $target -and $inventoryError -and -not $masterOnly){$connectionFailure=$inventoryError}
        elseif($databaseName) {
            $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database $databaseName -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
            $connection=$opened.Connection
            $connectionFailure=$opened.Failure
        }
        if($masterOnly -and $null -ne $connection){
            $identityResult=Invoke-AzureSqlReadQuery -Server $Server -Database 'master' -QueryId 'AZ-ASSESSMENT-IDENTITY' -Sql 'SELECT ORIGINAL_LOGIN() AS ExecutionLogin;' -FailureTranslator $FailureTranslator -ExistingConnection $connection
            if($identityResult.Succeeded -and $identityResult.Rows.Count -eq 1){$authenticatedPrincipal=[string]$identityResult.Rows[0].ExecutionLogin}
            $administratorObservation=Get-AzureSqlAdministratorObservation -Server $Server -FailureTranslator $FailureTranslator -Connection $connection
        }
        # These checks cannot distinguish incomplete visibility from a clean result.
        # Fail closed if the master visibility probe is negative or unavailable.
        if($masterOnly -and $administratorObservation -ne 'LikelyAdministrator'){
            foreach($administratorCheckId in @('003','004','015')){$skipLookup[$administratorCheckId]=$true}
        }
        $checks=New-Object System.Collections.Generic.List[object]
        foreach($check in $CheckCatalog) {
            $id=([string]$check.'Check ID').PadLeft(3,'0');$name=[string]$check.Section;$sectionId=[string]$check.SectionID
            $checkName='Check {0}' -f $id
            # System Overview is collected once against master after the other checks.
            if($id -eq '800' -or $unsupportedChecks.Contains($id)){continue}
            $masterScoped=($id -eq '015' -or ($sectionId -in $masterSectionIds -and $id -ne '129'))
            if($masterOnly -ne $masterScoped){continue}
            if($skipLookup.ContainsKey($id)) {
                $checks.Add([pscustomobject]@{CheckId=$id;Database=$databaseName;SectionID=$sectionId;Section=$name;Status='Skipped';Rows=@();ErrorCategory=$null;SupportCode=$null;SqlErrorNumber=$null;Explanation='Skipped';BatchCount=0});continue
            }
            $profile=Get-AzureSqlCheckProfile -CheckId $id
            if($null -ne $profile){
                $checks.Add([pscustomobject]@{CheckId=$id;Database=$databaseName;SectionID=$sectionId;Section=$name;Status='Platform defined';Rows=@();FixedOutcome=$profile.Outcome;AzureLabel=$profile.Label;ErrorCategory=$null;SupportCode=$null;SqlErrorNumber=$null;Explanation=$profile.Message;BatchCount=0})
                continue
            }
            if($noVisibleDatabases -and -not $masterOnly) {
                $checks.Add([pscustomobject]@{CheckId=$id;Database=$null;SectionID=$sectionId;Section=$name;Status='Not Run';Rows=@();ErrorCategory=$null;SupportCode=$null;SqlErrorNumber=$null;Explanation='The master inventory query succeeded but listed no visible user databases, so this original check was not run.';BatchCount=$(if($batchMap.ContainsKey($id)){@($batchMap[$id]).Count}else{0})});continue
            }
            if(-not $batchMap.ContainsKey($id)) {
                $checks.Add([pscustomobject]@{CheckId=$id;Database=$databaseName;SectionID=$sectionId;Section=$name;Status='Not Located';Rows=@();ErrorCategory=$null;SupportCode=$null;SqlErrorNumber=$null;Explanation='No original SQL batch carrying this check ID was found in the embedded Get-SqlSafe SQL source.';BatchCount=0});continue
            }
            if($connectionFailure) {
                $number=$null;if($connectionFailure.SanitizedDiagnostics){$number=$connectionFailure.SanitizedDiagnostics.SqlErrorNumber}
                $category=[string]$connectionFailure.ErrorCategory;$support=[string]$connectionFailure.SupportCode
                $explanation=Get-AzureSqlDiagnosticFailureExplanation -ErrorCategory $category -SupportCode $support -SqlErrorNumber $number -Stage 'ConnectionOpen'
                $checks.Add([pscustomobject]@{CheckId=$id;Database=$databaseName;SectionID=$sectionId;Section=$name;Status=$(if($null -eq $target -and $AllVisibleDatabases){'Not Run'}else{'Connection Failed'});Rows=@();ErrorCategory=$category;SupportCode=$support;SqlErrorNumber=$number;Explanation=$(if($null -eq $target -and $AllVisibleDatabases){'The all-visible database inventory failed, so this check was not run. '+$explanation}else{$explanation});BatchCount=@($batchMap[$id]).Count});continue
            }
            $allRows=New-Object System.Collections.Generic.List[object];$failed=$false;$lastFailure=$null
            foreach($sqlBatch in $batchMap[$id]) {$batchResult=Invoke-AzureSqlDiagnosticBatch -Connection $connection -Sql $sqlBatch -FailureTranslator $FailureTranslator;if($batchResult.Succeeded){foreach($row in $batchResult.Rows){$allRows.Add($row)}}else{$failed=$true;$lastFailure=$batchResult}}
            if($failed) {$explanation=Get-AzureSqlDiagnosticFailureExplanation -ErrorCategory $lastFailure.ErrorCategory -SupportCode $lastFailure.SupportCode -SqlErrorNumber $lastFailure.SqlErrorNumber -Stage 'QueryExecution';$status='Execution Failed'} elseif($allRows.Count -eq 0){$explanation='The check query completed and returned no matching rows. The original rule evaluates this result.';$status='No Rows'} else {$explanation='The original check query completed and returned rows.';$status='Executed'}
            $checks.Add([pscustomobject]@{CheckId=$id;Database=$databaseName;SectionID=$sectionId;Section=$name;Status=$status;Rows=[object[]]$allRows.ToArray();ErrorCategory=$(if($lastFailure){$lastFailure.ErrorCategory}else{$null});SupportCode=$(if($lastFailure){$lastFailure.SupportCode}else{$null});SqlErrorNumber=$(if($lastFailure){$lastFailure.SqlErrorNumber}else{$null});Explanation=$explanation;BatchCount=@($batchMap[$id]).Count})
        }
        if($null -ne $connection){$connection.Dispose()}
        if($masterOnly){$masterChecks=[object[]]$checks.ToArray()}
        else{$databaseRuns.Add([pscustomobject]@{Database=$databaseName;Checks=[object[]]$checks.ToArray();Status=$(if($noVisibleDatabases){'NoVisibleDatabases'}elseif($connectionFailure){'ConnectionFailed'}else{'Executed'})})}
    }
    $systemOverview=$null
    if($skipLookup.ContainsKey('800')){
        $systemOverview=[pscustomobject]@{CheckId='800';Database='master';SectionID='0';Section='Information';Status='Skipped';Rows=@();ErrorCategory=$null;SupportCode=$null;SqlErrorNumber=$null;Explanation='Skipped';BatchCount=0}
    }
    else{
        $overviewConnection=$null
        try {
            $opened=Open-AzureSqlDatabaseConnection -Server $Server -Database 'master' -FailureTranslator $FailureTranslator -ConnectionFactory $ConnectionFactory -AuthMethod $AuthMethod -Username $Username -Password $Password
            if($opened.Failure){
                $failure=$opened.Failure
                $number=if($failure.SanitizedDiagnostics){$failure.SanitizedDiagnostics.SqlErrorNumber}else{$null}
                $explanation=Get-AzureSqlDiagnosticFailureExplanation -ErrorCategory $failure.ErrorCategory -SupportCode $failure.SupportCode -SqlErrorNumber $number -Stage 'ConnectionOpen'
                $systemOverview=[pscustomobject]@{CheckId='800';Database='master';SectionID='0';Section='Information';Status='Connection Failed';Rows=@();ErrorCategory=$failure.ErrorCategory;SupportCode=$failure.SupportCode;SqlErrorNumber=$number;Explanation=$explanation;BatchCount=1}
            }
            else {
                $overviewConnection=$opened.Connection
                $batchResult=Invoke-AzureSqlDiagnosticBatch -Connection $overviewConnection -Sql (Get-AzureSqlSystemOverviewQuery -IncludeAdministratorCounts ($administratorObservation -eq 'LikelyAdministrator')) -FailureTranslator $FailureTranslator
                if($batchResult.Succeeded){
                    $overviewStatus=if(@($batchResult.Rows).Count){'Executed'}else{'No Rows'}
                    $overviewExplanation=if($overviewStatus -eq 'No Rows'){'System Overview completed against master but returned no rows.'}else{'System Overview was collected once against master.'}
                }
                else {
                    $overviewStatus='Execution Failed'
                    $overviewExplanation=Get-AzureSqlDiagnosticFailureExplanation -ErrorCategory $batchResult.ErrorCategory -SupportCode $batchResult.SupportCode -SqlErrorNumber $batchResult.SqlErrorNumber -Stage 'QueryExecution'
                }
                $systemOverview=[pscustomobject]@{CheckId='800';Database='master';SectionID='0';Section='Information';Status=$overviewStatus;Rows=$(if($batchResult.Succeeded){[object[]]@($batchResult.Rows)}else{@()});ErrorCategory=$batchResult.ErrorCategory;SupportCode=$batchResult.SupportCode;SqlErrorNumber=$batchResult.SqlErrorNumber;Explanation=$overviewExplanation;BatchCount=1}
            }
        }
        finally {if($null -ne $overviewConnection){$overviewConnection.Dispose()}}
    }
    [pscustomobject]@{Platform='AzureSQLDatabase';LogicalServer=$Server;RequestedScope=$scope;AuthMethod=$AuthMethod;AuthenticatedPrincipal=$authenticatedPrincipal;AdministratorObservation=$administratorObservation;StartedAt=$started;EndedAt=[datetime]::UtcNow;InventoryStatus=$inventoryStatus;InventoryError=$inventoryError;DatabaseRuns=[object[]]$databaseRuns.ToArray();MasterChecks=$masterChecks;SystemOverview=$systemOverview;CheckCount=($CheckCatalog.Count-$unsupportedChecks.Count);SkippedCheckIds=[string[]]@($skipLookup.Keys);RequestedSkipCheckIds=$requestedSkipCheckIds;DiagnosticOnly=$false;Succeeded=($databaseRuns.Count -gt 0 -or @($masterChecks | Where-Object Status -in @('Executed','No Rows')).Count -gt 0)}
}

function Get-AzureSqlRuleCatalog {
    [pscustomobject[]]@(
        [pscustomobject]@{ RuleId='AZ-ID-DB-OWNER-001'; StandardCheckIds=@('130'); Title='Assigned database owner-role membership'; Scope='Database'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-DB-ROLE-MEMBERSHIPS-001','AZ-DB-METADATA-PROBE-001'); Applicability='Each selected database'; Recommendation='Review direct db_owner assignments; remove accounts that do not require full database control and prefer narrower roles.'; References=@('https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-helpdbfixedrole-transact-sql?view=sql-server-ver17') },
        [pscustomobject]@{ RuleId='AZ-ID-DB-ADMIN-ROLES-001'; StandardCheckIds=@(); Title='Sensitive database administrator role membership'; Scope='Database'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-DB-ROLE-MEMBERSHIPS-001','AZ-DB-METADATA-PROBE-001'); Applicability='Each selected database'; Recommendation='Review db_securityadmin, db_accessadmin, and db_ddladmin memberships; remove unused access and prefer narrower rights.'; References=@('https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-helpdbfixedrole-transact-sql?view=sql-server-ver17') },
        [pscustomobject]@{ RuleId='AZ-ID-DB-POWERFUL-GRANTS-001'; StandardCheckIds=@(); Title='Explicit powerful database permissions'; Scope='Database'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-DB-PERMISSIONS-001','AZ-DB-PRINCIPALS-001','AZ-DB-METADATA-PROBE-001'); Applicability='Each selected database'; Recommendation='Remove unnecessary CONTROL, ALTER ANY USER, ALTER ANY ROLE, or IMPERSONATE grants; prefer narrow grants.'; References=@('https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-database-principal-permissions-transact-sql?view=sql-server-ver17','https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-permissions-transact-sql?view=sql-server-ver17') },
        [pscustomobject]@{ RuleId='AZ-ID-DB-PUBLIC-POWERFUL-GRANTS-001'; StandardCheckIds=@(); Title='Powerful permissions granted to PUBLIC'; Scope='Database'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-DB-PERMISSIONS-001','AZ-DB-METADATA-PROBE-001'); Applicability='Each selected database'; Recommendation='Revoke high-impact grants from PUBLIC and grant them only to intended principals.'; References=@('https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-database-principal-permissions-transact-sql?view=sql-server-ver17','https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-permissions-transact-sql?view=sql-server-ver17') },
        [pscustomobject]@{ RuleId='113'; StandardCheckIds=@('113'); Title='Custom database roles without members'; Scope='Database'; Severity='Observe'; Weight=1; EvidencePrerequisites=@('AZ-DB-EMPTY-CUSTOM-ROLES-001','AZ-DB-METADATA-PROBE-001'); Applicability='Each selected database'; Recommendation='Review empty custom roles and remove those that are no longer required.'; References=@() },
        [pscustomobject]@{ RuleId='006'; StandardCheckIds=@('006'); Title='SQL logins without password policy enforcement'; Scope='LogicalServer'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-MASTER-SQL-LOGINS-001','AZ-MASTER-METADATA-PROBE-001'); Applicability='All-visible scope with successful master evidence'; Recommendation='Enable password policy enforcement for SQL logins where SQL authentication remains approved; review exceptions.'; References=@('https://learn.microsoft.com/en-us/sql/relational-databases/security/password-policy') },
        [pscustomobject]@{ RuleId='AZ-ID-SERVER-DATABASE-ADMIN-001'; StandardCheckIds=@(); Title='Azure SQL logical-server database and login administration roles'; Scope='LogicalServer'; Severity='High'; Weight=3; EvidencePrerequisites=@('AZ-MASTER-SERVER-PRINCIPALS-001','AZ-MASTER-SERVER-ROLES-001','AZ-MASTER-METADATA-PROBE-001'); Applicability='All-visible scope with master evidence'; Recommendation='Limit ##MS_DatabaseManager## and ##MS_LoginManager## membership to approved logical-server operators.'; References=@('https://learn.microsoft.com/en-us/azure/azure-sql/database/security-server-roles?view=azuresql') },
        [pscustomobject]@{ RuleId='AZ-ID-SERVER-STATE-MANAGER-001'; StandardCheckIds=@(); Title='Azure SQL logical-server state manager role'; Scope='LogicalServer'; Severity='Medium'; Weight=2; EvidencePrerequisites=@('AZ-MASTER-SERVER-PRINCIPALS-001','AZ-MASTER-SERVER-ROLES-001','AZ-MASTER-METADATA-PROBE-001'); Applicability='All-visible scope with master evidence'; Recommendation='Limit ##MS_ServerStateManager## membership to approved operators because it includes server-state alteration and broad state-reading capabilities.'; References=@('https://learn.microsoft.com/en-us/azure/azure-sql/database/security-server-roles?view=azuresql') }
    )
}

function Get-AzureStandardRuleMapping {
    [pscustomobject[]]@(
        [pscustomobject]@{ CheckId='002'; CheckName='Authentication Mode'; StandardSeverity='OBSERVE'; Mapping='Deferred'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL server authentication configuration, including Entra-only mode, is configured and validated through Azure service settings. A database-engine connection cannot prove the server-level authentication mode.' },
        [pscustomobject]@{ CheckId='003'; CheckName='SQL Authentication usage'; StandardSeverity='WARNING'; Mapping='Deferred'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='The Standard result is a SQL Server instance-wide live-session percentage. Azure SQL Database DMV visibility and workload sampling do not provide a defensible equivalent for overall usage.' },
        [pscustomobject]@{ CheckId='004'; CheckName='NTLM Authentication usage'; StandardSeverity='OBSERVE/WARNING/FAIL'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database client authentication is not Windows NTLM authentication.' },
        [pscustomobject]@{ CheckId='006'; CheckName='SQL Logins without password policy enforcement'; StandardSeverity='FAIL'; Mapping='Adapted'; AzureRuleIds=@('006'); Scope='LogicalServer/master'; Reason='The same SQL login policy property is available through Azure SQL Database master sys.sql_logins. Empty results are Pass only with VIEW ANY SECURITY DEFINITION confirmed; explicit database runs do not request master and show Not Assessed.' },
        [pscustomobject]@{ CheckId='008'; CheckName='SA Login Name'; StandardSeverity='OBSERVE'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database does not provide the SQL Server built-in sa login.' },
        [pscustomobject]@{ CheckId='010'; CheckName='Sysadmin-members individual accounts'; StandardSeverity='OBSERVE'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database has no sysadmin fixed server role. Azure logical-server roles are not equivalent to sysadmin and remain reported under Azure-specific IDs.' },
        [pscustomobject]@{ CheckId='011'; CheckName='Server role membership with direct Elevation-of-Privilege Risk'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='This rule evaluates SQL Server custom server-role permission paths to sysadmin. Azure SQL Database does not expose that custom server-role model.' },
        [pscustomobject]@{ CheckId='015'; CheckName='Powerful server role membership individual accounts'; StandardSeverity='OBSERVE'; Mapping='Deferred'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='The Standard rule distinguishes individual accounts from groups and assesses SQL Server roles. Azure fixed roles have different semantics; a faithful individual-account-only adaptation is not yet implemented.' },
        [pscustomobject]@{ CheckId='026'; CheckName='Server permissions granted to Logins'; StandardSeverity='WARNING'; Mapping='Deferred'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='The Standard result covers SQL Server server securable grants. Azure SQL Database exposes a different permission surface; current server-role membership evidence is not equivalent to all server grants.' },
        [pscustomobject]@{ CheckId='027'; CheckName='Custom server roles without members'; StandardSeverity='OBSERVE'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database provides fixed logical-server roles rather than SQL Server custom server roles.' },
        [pscustomobject]@{ CheckId='028'; CheckName='Databases with TRUSTWORTHY property set'; StandardSeverity='FAIL'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Database'; Reason='The TRUSTWORTHY database property is not supported as an Azure SQL Database security control.' },
        [pscustomobject]@{ CheckId='030'; CheckName='Instance-wide cross-database ownership chaining enabled'; StandardSeverity='FAIL'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='The SQL Server instance-wide cross-database ownership chaining option is not exposed for Azure SQL Database.' },
        [pscustomobject]@{ CheckId='031'; CheckName='Databases with cross database ownership setting active'; StandardSeverity='FAIL'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Database'; Reason='The database-level cross-database ownership chaining setting is not supported in Azure SQL Database.' },
        [pscustomobject]@{ CheckId='034'; CheckName='XP_cmdshell setting'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='xp_cmdshell is not available in Azure SQL Database.' },
        [pscustomobject]@{ CheckId='036'; CheckName='Ad Hoc distributed queries setting'; StandardSeverity='FAIL'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='The SQL Server Ad Hoc Distributed Queries server option is not exposed in Azure SQL Database.' },
        [pscustomobject]@{ CheckId='038'; CheckName='OLE Automation Procedures setting'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='OLE Automation procedures are not available in Azure SQL Database.' },
        [pscustomobject]@{ CheckId='046'; CheckName='Orphaned Windows Logins'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database does not use Windows logins. Resolving stale Entra users requires directory evidence not supplied by T-SQL.' },
        [pscustomobject]@{ CheckId='050'; CheckName='Number of Error Logs kept'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Service'; Reason='Azure SQL Database error-log retention is service-managed and is not the SQL Server instance error-log count.' },
        [pscustomobject]@{ CheckId='059'; CheckName='Security Auditing minimal setup'; StandardSeverity='FAIL'; Mapping='Deferred'; AzureRuleIds=@(); Scope='Service/control plane'; Reason='Azure auditing configuration and destinations are service/control-plane settings. This engine assessment does not query or claim them.' },
        [pscustomobject]@{ CheckId='069'; CheckName='Basic Login-Failure logging status'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Service'; Reason='The Standard check tests SQL Server error-log configuration; Azure SQL Database does not expose that engine-owned error log setting.' },
        [pscustomobject]@{ CheckId='072'; CheckName='Database Owner sysadmin'; StandardSeverity='OBSERVE'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Database/logical server'; Reason='Azure SQL Database has no sysadmin role; Azure service administrators and dbmanager behavior are not equivalent to a SQL Server database owner mapped to sysadmin.' },
        [pscustomobject]@{ CheckId='078'; CheckName='Database Owner Windows Account'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Database'; Reason='Windows accounts are not Azure SQL Database principals.' },
        [pscustomobject]@{ CheckId='079'; CheckName='SA Login State'; StandardSeverity='INFO'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='LogicalServer'; Reason='Azure SQL Database has no SQL Server built-in sa login.' },
        [pscustomobject]@{ CheckId='113'; CheckName='Custom database roles without members'; StandardSeverity='OBSERVE'; Mapping='Adapted'; AzureRuleIds=@('113'); Scope='Database'; Reason='The same custom-role-with-zero-members meaning is collected from the selected database catalogs. A Finding or Pass requires VIEW DEFINITION; otherwise the result is Not Assessed.' },
        [pscustomobject]@{ CheckId='123'; CheckName='Databases with AUTO_CLOSE setting on'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Database'; Reason='Microsoft documents AUTO_CLOSE as unavailable on SQL Database; no T-SQL result is scored for Azure SQL Database.' },
        [pscustomobject]@{ CheckId='129'; CheckName='Orphaned Database Users'; StandardSeverity='WARNING'; Mapping='Deferred'; AzureRuleIds=@(); Scope='Database'; Reason='The original SQL Server query relies on server-login mappings and availability-group metadata. Contained Azure SQL Database users need no matching server login; an Azure-specific check would require separate logic.' },
        [pscustomobject]@{ CheckId='130'; CheckName='Db_owner database role members'; StandardSeverity='OBSERVE'; Mapping='Adapted'; AzureRuleIds=@('AZ-ID-DB-OWNER-001'); Scope='Database'; Reason='Direct non-dbo db_owner assignments remain findings; dbo is retained as owner context and excluded from assigned-account findings. Empty results require VIEW DEFINITION.' },
        [pscustomobject]@{ CheckId='155'; CheckName='Database Owner not valid'; StandardSeverity='WARNING'; Mapping='Deferred'; AzureRuleIds=@(); Scope='Database/logical server'; Reason='A reliable owner-to-logical-server-principal validity check needs master security-definition visibility and service semantics not guaranteed in an explicit-database run.' },
        [pscustomobject]@{ CheckId='800'; CheckName='System Overview'; StandardSeverity='INFO'; Mapping='Deferred'; AzureRuleIds=@(); Scope='Database/logical server'; Reason='The Standard informational row includes SQL Server instance facts that do not have a like-for-like Azure SQL Database engine interpretation; an Azure-specific information panel is deferred.' },
        [pscustomobject]@{ CheckId='802'; CheckName='Contained Availability Groups'; StandardSeverity='INFO'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Service'; Reason='Contained Availability Groups are a SQL Server engine feature, not an Azure SQL Database tenant configuration.' },
        [pscustomobject]@{ CheckId='806'; CheckName='Outstanding configuration changes'; StandardSeverity='WARNING'; Mapping='Not Applicable'; AzureRuleIds=@(); Scope='Service'; Reason='Azure SQL Database does not expose SQL Server instance sp_configure/reconfigure pending-state semantics.' }
    )
}

function Get-AzureSqlRuleOutcome {
    param([object]$Rule,[string]$Database,[string]$Status,[string]$Reason,[object[]]$Matches,[string[]]$EvidenceQueryIds,[object[]]$ContextEvidence=@())
    [pscustomobject]@{ RuleId=$Rule.RuleId; StandardCheckIds=[string[]]@($Rule.StandardCheckIds); Title=$Rule.Title; Scope=$Rule.Scope; Database=$Database; Status=$Status; Severity=$Rule.Severity; Weight=$Rule.Weight; Reason=$Reason; Findings=[object[]]@($Matches); ContextEvidence=[object[]]@($ContextEvidence); EvidenceQueryIds=[string[]]@($EvidenceQueryIds); Recommendation=$Rule.Recommendation; References=[string[]]@($Rule.References) }
}

function Invoke-AzureSqlRuleEvaluation {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$CollectionResult)
    $catalog=@(Get-AzureSqlRuleCatalog); $outcomes=New-Object System.Collections.Generic.List[object]
    $dbRules=@($catalog | Where-Object Scope -eq 'Database')
    foreach ($databaseResult in @($CollectionResult.Databases | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Database) })) {
        $queryMap=@{}; foreach ($query in $databaseResult.EvidenceQueries) { $queryMap[[string]$query.QueryId]=$query }
        $roleRows=@(); $permissionRows=@(); $principalRows=@()
        if ($queryMap.ContainsKey('AZ-DB-ROLE-MEMBERSHIPS-001')) { $roleRows=@($queryMap['AZ-DB-ROLE-MEMBERSHIPS-001'].Rows) }
        $emptyRoleQuery=$queryMap['AZ-DB-EMPTY-CUSTOM-ROLES-001']
        $emptyRoleRows=@(); if ($emptyRoleQuery -and $emptyRoleQuery.Status -eq 'Succeeded') {$emptyRoleRows=@($emptyRoleQuery.Rows)}
        if ($queryMap.ContainsKey('AZ-DB-PERMISSIONS-001')) { $permissionRows=@($queryMap['AZ-DB-PERMISSIONS-001'].Rows) }
        if ($queryMap.ContainsKey('AZ-DB-PRINCIPALS-001')) { $principalRows=@($queryMap['AZ-DB-PRINCIPALS-001'].Rows) }
        $metadataQuery=$queryMap['AZ-DB-METADATA-PROBE-001']
        $metadataProbe=if ($metadataQuery -and $metadataQuery.Status -eq 'Succeeded' -and @($metadataQuery.Rows).Count -gt 0) {$metadataQuery.Rows[0]} else {$null}
        $visibilitySufficient=($null -ne $metadataProbe -and [int]$metadataProbe.HasViewDefinition -eq 1)
        $knownRoleMembers=@{}
        foreach ($roleRow in $roleRows) { if ($roleRow.RoleName) { $memberKey=([string]$roleRow.MemberName).ToLowerInvariant(); if (-not $knownRoleMembers.ContainsKey($memberKey)) {$knownRoleMembers[$memberKey]=New-Object System.Collections.Generic.List[string]}; $knownRoleMembers[$memberKey].Add([string]$roleRow.RoleName) } }
        $ownerMembers=@(@($roleRows | Where-Object { [string]$_.RoleName -ieq 'db_owner' }) | ForEach-Object { [string]$_.MemberName })
        $adminMembers=@(@($roleRows | Where-Object { [string]$_.RoleName -iin @('db_owner','db_securityadmin','db_accessadmin','db_ddladmin') }) | ForEach-Object { [string]$_.MemberName })
        $roleQuery=$queryMap['AZ-DB-ROLE-MEMBERSHIPS-001']
        $dboRows=@($roleRows | Where-Object { [string]$_.RoleName -ieq 'db_owner' -and [string]$_.MemberName -ieq 'dbo' })
        $dboContext=@($dboRows | ForEach-Object { [pscustomobject]@{ Principal=[string]$_.MemberName; Role=[string]$_.RoleName; Interpretation='Special dbo owner context; retained as evidence and excluded from assigned-account findings'; SourceQueryId='AZ-DB-ROLE-MEMBERSHIPS-001' } })
        $dbOwnerMatch=@($roleRows | Where-Object { [string]$_.RoleName -ieq 'db_owner' -and [string]$_.MemberName -ine 'dbo' } | ForEach-Object { [pscustomobject]@{ Principal=[string]$_.MemberName; Role=[string]$_.RoleName; MemberType=[string]$_.MemberType; SourceQueryId='AZ-DB-ROLE-MEMBERSHIPS-001' } })
        $adminMatch=@($roleRows | Where-Object { [string]$_.RoleName -iin @('db_securityadmin','db_accessadmin','db_ddladmin') -and $ownerMembers -notcontains [string]$_.MemberName } | ForEach-Object { [pscustomobject]@{ Principal=[string]$_.MemberName; Role=[string]$_.RoleName; MemberType=[string]$_.MemberType; SourceQueryId='AZ-DB-ROLE-MEMBERSHIPS-001' } })
        $permissionsEvidenceReady=($queryMap.ContainsKey('AZ-DB-PERMISSIONS-001') -and $queryMap['AZ-DB-PERMISSIONS-001'].Status -eq 'Succeeded')
        $roleEvidenceReady=($queryMap.ContainsKey('AZ-DB-ROLE-MEMBERSHIPS-001') -and $roleQuery.Status -eq 'Succeeded')
        $principalEvidenceReady=($queryMap.ContainsKey('AZ-DB-PRINCIPALS-001') -and $queryMap['AZ-DB-PRINCIPALS-001'].Status -eq 'Succeeded')
        $commonRoleIds=@('AZ-DB-ROLE-MEMBERSHIPS-001')
        foreach ($rule in @($dbRules | Where-Object RuleId -in @('AZ-ID-DB-OWNER-001','AZ-ID-DB-ADMIN-ROLES-001'))) {
            if ($rule.RuleId -eq 'AZ-ID-DB-OWNER-001') {$ruleMatches=@($dbOwnerMatch)} else {$ruleMatches=@($adminMatch)}
            $ready=$roleEvidenceReady
            $status=if ($ruleMatches.Count -gt 0) {'Finding'} elseif (-not $ready -or -not $visibilitySufficient) {'Not Assessed'} else {'Pass'}
            $reason=if ($ruleMatches.Count -gt 0) {'One or more non-dbo role memberships were directly observed.'} elseif (-not $ready) {'Required role-membership query did not succeed.'} elseif (-not $visibilitySufficient) {'An empty result cannot be Pass because effective database-scoped VIEW DEFINITION was not confirmed.'} elseif ($rule.RuleId -eq 'AZ-ID-DB-OWNER-001' -and $dboContext.Count -gt 0) {'Only special dbo owner context was observed; dbo is retained as context and is not treated as a separately assigned account.'} else {'Required query succeeded with effective VIEW DEFINITION and no matching memberships were observed.'}
            $context=if ($rule.RuleId -eq 'AZ-ID-DB-OWNER-001') {$dboContext} else {@()}
            $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $rule -Database $databaseResult.Database -Status $status -Reason $reason -Matches $ruleMatches -EvidenceQueryIds $commonRoleIds -ContextEvidence $context))
        }
        $emptyRoleReady=($null -ne $emptyRoleQuery -and $emptyRoleQuery.Status -eq 'Succeeded')
        $emptyRoleStatus=if (-not $emptyRoleReady -or -not $visibilitySufficient) {'Not Assessed'} elseif ($emptyRoleRows.Count -gt 0) {'Finding'} else {'Pass'}
        $emptyRoleReason=if (-not $emptyRoleReady) {'Required custom-role and role-membership query did not succeed.'} elseif (-not $visibilitySufficient) {'Custom-role emptiness cannot be established without effective database-scoped VIEW DEFINITION.'} elseif ($emptyRoleRows.Count -gt 0) {'One or more custom database roles with no visible members were observed.'} else {'No empty custom database roles were observed with effective VIEW DEFINITION.'}
        $emptyRoleFindings=@($emptyRoleRows | ForEach-Object { [pscustomobject]@{ Role=[string]$_.RoleName; PrincipalId=$_.PrincipalId; Owner=[string]$_.OwnerName; SourceQueryId='AZ-DB-EMPTY-CUSTOM-ROLES-001' } })
        $emptyRoleRule=@($dbRules | Where-Object RuleId -eq '113')[0]
        $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $emptyRoleRule -Database $databaseResult.Database -Status $emptyRoleStatus -Reason $emptyRoleReason -Matches $emptyRoleFindings -EvidenceQueryIds @('AZ-DB-EMPTY-CUSTOM-ROLES-001','AZ-DB-METADATA-PROBE-001')))
        $powerfulPerms=@(); $publicPerms=@()
        foreach ($permission in $permissionRows) {
            $state=[string]$permission.state_desc; $permissionName=[string]$permission.permission_name; $class=[string]$permission.class_desc; $grantee=[string]$permission.GranteeName
            if ($state -notin @('GRANT','GRANT_WITH_GRANT_OPTION')) { continue }
            $isPublic=($grantee -ieq 'public')
            $qualifies=($class -eq 'DATABASE' -and $permissionName -in @('CONTROL','ALTER ANY USER','ALTER ANY ROLE')) -or ($class -eq 'DATABASE_PRINCIPAL' -and $permissionName -eq 'IMPERSONATE')
            if (-not $qualifies -or $grantee -ieq 'dbo') { continue }
            $targetName=$null
            if ($class -eq 'DATABASE_PRINCIPAL') { $target=@($principalRows | Where-Object { [int]$_.principal_id -eq [int]$permission.major_id } | Select-Object -First 1); if ($target.Count -gt 0) {$targetName=[string]$target[0].name} }
            $match=[pscustomobject]@{ Principal=$grantee; PrincipalType=[string]$permission.GranteeType; Permission=$permissionName; State=$state; Scope=$class; Target=$targetName; SourceQueryId='AZ-DB-PERMISSIONS-001'; TargetSourceQueryId=$(if ($class -eq 'DATABASE_PRINCIPAL') {'AZ-DB-PRINCIPALS-001'} else {$null}) }
            if ($isPublic) { $publicPerms += $match; continue }
            $memberRoles=@(); if ($knownRoleMembers.ContainsKey($grantee.ToLowerInvariant())) {$memberRoles=@($knownRoleMembers[$grantee.ToLowerInvariant()].ToArray())}
            $coveredByRole=($memberRoles -contains 'db_owner' -and $permissionName -eq 'CONTROL') -or (($memberRoles -contains 'db_owner' -or $memberRoles -contains 'db_securityadmin') -and $permissionName -eq 'ALTER ANY ROLE') -or (($memberRoles -contains 'db_owner' -or $memberRoles -contains 'db_accessadmin') -and $permissionName -eq 'ALTER ANY USER')
            if (-not $coveredByRole) { $powerfulPerms += $match }
        }
        foreach ($rule in @($dbRules | Where-Object RuleId -in @('AZ-ID-DB-POWERFUL-GRANTS-001','AZ-ID-DB-PUBLIC-POWERFUL-GRANTS-001'))) {
            if ($rule.RuleId -eq 'AZ-ID-DB-POWERFUL-GRANTS-001') {$ruleMatches=@($powerfulPerms)} else {$ruleMatches=@($publicPerms)}
            $ready=$permissionsEvidenceReady -and ($rule.RuleId -ne 'AZ-ID-DB-POWERFUL-GRANTS-001' -or $principalEvidenceReady)
            $requiredIds=if ($rule.RuleId -eq 'AZ-ID-DB-POWERFUL-GRANTS-001') {@('AZ-DB-PERMISSIONS-001','AZ-DB-PRINCIPALS-001')} else {@('AZ-DB-PERMISSIONS-001')}
            $status=if ($ruleMatches.Count -gt 0) {'Finding'} elseif (-not $ready -or -not $visibilitySufficient) {'Not Assessed'} else {'Pass'}
            $reason=if ($ruleMatches.Count -gt 0) {'One or more exact-scope, high-impact GRANT rows were directly observed.'} elseif (-not $ready) {'One or more required permission/principal queries did not succeed.'} elseif (-not $visibilitySufficient) {'An empty result is not a Pass because complete metadata visibility was not established.'} else {'Required queries succeeded with sufficient visibility and no matching grants were observed.'}
            $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $rule -Database $databaseResult.Database -Status $status -Reason $reason -Matches $ruleMatches -EvidenceQueryIds $requiredIds))
        }
    }
    $serverRules=@($catalog | Where-Object Scope -eq 'LogicalServer')
    if ($CollectionResult.RequestedScope -ne 'AllVisibleDatabases') {
        foreach ($serverRule in $serverRules) {
            $status=if ($serverRule.RuleId -eq '006') {'Not Assessed'} else {'Not Applicable'}
            $reason=if ($serverRule.RuleId -eq '006') {'The adapted SQL login policy check is applicable at logical-server scope, but master is deliberately not opened during an explicit-database assessment.'} else {'Master-scoped logical-server role evidence was not requested for this explicit database target.'}
            $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $serverRule -Database $null -Status $status -Reason $reason -Matches @() -EvidenceQueryIds @()))
        }
    } else {
        $serverRows=@($CollectionResult.Inventory.ServerEvidence); $required=@('AZ-MASTER-SERVER-PRINCIPALS-001','AZ-MASTER-SERVER-ROLES-001'); $serverMap=@{}; foreach ($r in $serverRows) {$serverMap[[string]$r.QueryId]=$r}
        $masterProbeQuery=$serverMap['AZ-MASTER-METADATA-PROBE-001']
        $masterProbe=if ($masterProbeQuery -and $masterProbeQuery.Status -eq 'Succeeded' -and @($masterProbeQuery.Rows).Count -gt 0) {$masterProbeQuery.Rows[0]} else {$null}
        $masterVisibility=($null -ne $masterProbe -and [int]$masterProbe.HasViewAnySecurityDefinition -eq 1)
        $observedServerRoles=@($serverRows | Where-Object { $_.QueryId -eq 'AZ-MASTER-SERVER-ROLES-001' -and $_.Status -eq 'Succeeded' } | ForEach-Object { $_.Rows } | Where-Object { [string]$_.RoleName -in @('##MS_DatabaseManager##','##MS_LoginManager##','##MS_ServerStateManager##') } | ForEach-Object { [pscustomobject]@{ Principal=[string]$_.MemberName; Role=[string]$_.RoleName; MemberType=[string]$_.MemberType; SourceQueryId='AZ-MASTER-SERVER-ROLES-001' } })
        $ready=(@($required | Where-Object { -not $serverMap.ContainsKey($_) -or $serverMap[$_].Status -ne 'Succeeded' }).Count -eq 0)
        foreach ($serverRule in $serverRules) {
            if ($serverRule.RuleId -eq '006') {
                $loginQuery=$serverMap['AZ-MASTER-SQL-LOGINS-001']
                $loginRows=@(); if ($loginQuery -and $loginQuery.Status -eq 'Succeeded') {$loginRows=@($loginQuery.Rows)}
                $loginMatches=@($loginRows | ForEach-Object { [pscustomobject]@{ Principal=[string]$_.LoginName; IsPolicyChecked=$_.IsPolicyChecked; IsExpirationChecked=$_.IsExpirationChecked; SourceQueryId='AZ-MASTER-SQL-LOGINS-001' } })
                $loginReady=($null -ne $loginQuery -and $loginQuery.Status -eq 'Succeeded')
                $loginStatus=if ($loginMatches.Count -gt 0) {'Finding'} elseif (-not $loginReady -or -not $masterVisibility) {'Not Assessed'} else {'Pass'}
                $loginReason=if ($loginMatches.Count -gt 0) {'SQL logins with is_policy_checked = 0 were directly observed.'} elseif (-not $loginReady) {'The sys.sql_logins evidence query did not succeed.'} elseif (-not $masterVisibility) {'An empty sys.sql_logins result cannot be Pass because VIEW ANY SECURITY DEFINITION was not confirmed.'} else {'No SQL login without password policy enforcement was observed with VIEW ANY SECURITY DEFINITION confirmed.'}
                $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $serverRule -Database $null -Status $loginStatus -Reason $loginReason -Matches $loginMatches -EvidenceQueryIds @('AZ-MASTER-SQL-LOGINS-001','AZ-MASTER-METADATA-PROBE-001')))
                continue
            }
            $roleNames=if ($serverRule.RuleId -eq 'AZ-ID-SERVER-STATE-MANAGER-001') {@('##MS_ServerStateManager##')} else {@('##MS_DatabaseManager##','##MS_LoginManager##')}
            $serverMatches=@($observedServerRoles | Where-Object Role -in $roleNames)
            $status=if ($serverMatches.Count -gt 0) {'Finding'} elseif (-not $ready -or -not $masterVisibility) {'Not Assessed'} else {'Pass'}
            $reason=if ($serverMatches.Count -gt 0) {'One or more matching Azure SQL fixed server-role memberships were directly observed.'} elseif (-not $ready) {'Master inventory or a required server-principal/role query did not succeed.'} elseif (-not $masterVisibility) {'No matching role was visible, but VIEW ANY SECURITY DEFINITION was not confirmed for complete logical-server security catalog visibility.'} else {'Required master evidence succeeded with VIEW ANY SECURITY DEFINITION confirmed and no matching roles were observed.'}
            $outcomes.Add((Get-AzureSqlRuleOutcome -Rule $serverRule -Database $null -Status $status -Reason $reason -Matches $serverMatches -EvidenceQueryIds ($required + 'AZ-MASTER-METADATA-PROBE-001')))
        }
    }
    $resultRows=[object[]]$outcomes.ToArray(); $assessed=@($resultRows | Where-Object Status -in @('Pass','Finding')); $applicable=@($resultRows | Where-Object Status -ne 'Not Applicable'); $weight=0; $findingWeight=0; $applicableWeight=0; $notAssessedWeight=0; $notApplicableWeight=0
    foreach ($ruleResult in $resultRows) { $ruleWeight=[int]$ruleResult.Weight; if ($ruleResult.Status -ne 'Not Applicable') {$applicableWeight += $ruleWeight}; if ($ruleResult.Status -eq 'Not Assessed') {$notAssessedWeight += $ruleWeight}; if ($ruleResult.Status -eq 'Not Applicable') {$notApplicableWeight += $ruleWeight} }
    foreach ($assessedRule in $assessed) { $weight += [int]$assessedRule.Weight; if ($assessedRule.Status -eq 'Finding') {$findingWeight += [int]$assessedRule.Weight} }
    $score=if ($weight -gt 0) {[Math]::Round((($weight-$findingWeight)/$weight)*100,1)} else {$null}
    $mapping=@(Get-AzureStandardRuleMapping)
    [pscustomobject]@{ RuleCatalog=$catalog; StandardMapping=$mapping; RuleResults=$resultRows; Findings=[object[]]@($resultRows | Where-Object Status -eq 'Finding'); Summary=[pscustomobject]@{ Finding=@($resultRows | Where-Object Status -eq 'Finding').Count; Pass=@($resultRows | Where-Object Status -eq 'Pass').Count; NotApplicable=@($resultRows | Where-Object Status -eq 'Not Applicable').Count; NotAssessed=@($resultRows | Where-Object Status -eq 'Not Assessed').Count; AssessedInstances=$assessed.Count; ApplicableInstances=$applicable.Count; AssessedWeight=$weight; ApplicableWeight=$applicableWeight; NotAssessedWeight=$notAssessedWeight; NotApplicableWeight=$notApplicableWeight; FindingWeight=$findingWeight; Score=$score; ScoreLabel=$(if ($null -eq $score) {'Not scored: no supported rule instances had sufficient evidence and visibility.'} else {'Weighted subset score; applies only to the assessed Azure rule instances shown here, not the full Standard catalog or server security.'}) } }
}

function ConvertTo-AzureHtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-AzureSafeFileToken {
    param([Parameter(Mandatory=$true)][string]$Value)
    $safe=[regex]::Replace($Value,'[^A-Za-z0-9_-]','_').Trim().TrimEnd('.')
    $safe=[regex]::Replace($safe,'\.{2,}','_').Trim('.','_')
    if ([string]::IsNullOrWhiteSpace($safe)) {$safe='database'}
    if ($safe -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {$safe='_'+$safe}
    if ($safe.Length -gt 48) {$safe=$safe.Substring(0,48)}
    $sha=[System.Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').Substring(0,10).ToLowerInvariant() } finally { $sha.Dispose() }
    '{0}-{1}' -f $safe,$hash
}

function New-AzureSqlAssessmentHtml {
    param([Parameter(Mandatory=$true)]$Collection,[Parameter(Mandatory=$true)]$Evaluation,[object]$OnlyDatabase,[hashtable]$ReportLinks=@{})
    $dbResults=@($Collection.Databases | Where-Object { $_.Database -and (-not $OnlyDatabase -or $_.Database -ceq $OnlyDatabase) })
    $findings=@($Evaluation.Findings | Where-Object { if ($OnlyDatabase) { $_.Database -ceq $OnlyDatabase } else { $true } })
    $sections=New-Object System.Collections.Generic.List[string]
    $scopeLabel=if ($OnlyDatabase) {'Individual database report (subset): {0}' -f $OnlyDatabase} else {$Collection.RequestedScope}
    $scopeText=ConvertTo-AzureHtmlText $scopeLabel
    $localRequested=if ($OnlyDatabase) {1} else {$Collection.Coverage.Requested}
    $localCollected=if ($OnlyDatabase) {@($dbResults | Where-Object Status -eq 'Collected').Count} else {$Collection.Coverage.Collected}
    $logicalServer=ConvertTo-AzureHtmlText $Collection.LogicalServer
    $principal=ConvertTo-AzureHtmlText $Collection.AuthenticatedPrincipal
    $visibleUserDatabases=@($Collection.Inventory.Databases | Where-Object { [string]$_ -ne 'master' })
    $visibleCountText=if ($Collection.Inventory.Status -eq 'Collected') { '{0} visible user databases (list may be incomplete; master is inventory-only)' -f $visibleUserDatabases.Count } elseif ($Collection.Inventory.Status -eq 'Failed') {'Unavailable; inventory failed'} else {'Not requested for explicit database scope'}
    $visibleNamesText=if ($Collection.Inventory.Status -eq 'Collected') { (@($visibleUserDatabases | ForEach-Object { ConvertTo-AzureHtmlText $_ }) -join ', ') } elseif ($Collection.Inventory.Status -eq 'Failed') {'Unavailable; master inventory failed.'} else {'Not requested for explicit database scope.'}
    $links=''
    foreach ($db in $dbResults) { if ($ReportLinks.ContainsKey([string]$db.Database)) { $label=ConvertTo-AzureHtmlText $db.Database; $dbReportPath=[string]$ReportLinks[[string]$db.Database]; $hrefPath=(Join-Path (Split-Path -Leaf (Split-Path -Parent $dbReportPath)) ([System.IO.Path]::GetFileName($dbReportPath))).Replace('\','/'); $href=ConvertTo-AzureHtmlText $hrefPath; $links += "<li><a href='$href'>$label</a></li>" } }
    $ruleCounts=@($Evaluation.RuleResults | Where-Object { if ($OnlyDatabase) { $_.Database -ceq $OnlyDatabase } else { $true } })
    $localFinding=@($ruleCounts | Where-Object Status -eq 'Finding').Count; $localPass=@($ruleCounts | Where-Object Status -eq 'Pass').Count; $localNotApplicable=@($ruleCounts | Where-Object Status -eq 'Not Applicable').Count; $localNotAssessed=@($ruleCounts | Where-Object Status -eq 'Not Assessed').Count
    $localAssessed=@($ruleCounts | Where-Object Status -in @('Pass','Finding')); $localWeight=0; $localFindingWeight=0; $localApplicableWeight=0; $localNotAssessedWeight=0; $localNotApplicableWeight=0
    foreach($ruleResult in $ruleCounts) { $ruleWeight=[int]$ruleResult.Weight; if($ruleResult.Status -ne 'Not Applicable'){$localApplicableWeight += $ruleWeight}; if($ruleResult.Status -eq 'Not Assessed'){$localNotAssessedWeight += $ruleWeight}; if($ruleResult.Status -eq 'Not Applicable'){$localNotApplicableWeight += $ruleWeight} }
    foreach($assessedRule in $localAssessed) {$localWeight += [int]$assessedRule.Weight; if($assessedRule.Status -eq 'Finding'){$localFindingWeight += [int]$assessedRule.Weight}}; $localScore=if ($localWeight -gt 0) {[Math]::Round((($localWeight-$localFindingWeight)/$localWeight)*100,1)} else {$null}
    $scoreCell=if ($null -eq $localScore) {'Not scored'} else {('{0}%' -f $localScore)}
    $mappingCounts=@{}; foreach($mappingRow in $Evaluation.StandardMapping) { $key=[string]$mappingRow.Mapping; if(-not $mappingCounts.ContainsKey($key)){$mappingCounts[$key]=0}; $mappingCounts[$key]++ }
    $mappingRows=New-Object System.Collections.Generic.List[string]
    foreach($mappingRow in $Evaluation.StandardMapping) {
        $mappingStatus=ConvertTo-AzureHtmlText $mappingRow.Mapping
        $mappingRuleIds=ConvertTo-AzureHtmlText ($mappingRow.AzureRuleIds -join ', ')
        $mappingRows.Add("<tr><td>$(ConvertTo-AzureHtmlText $mappingRow.CheckId)</td><td>$(ConvertTo-AzureHtmlText $mappingRow.CheckName)</td><td>$mappingStatus</td><td>$mappingRuleIds</td><td>$(ConvertTo-AzureHtmlText $mappingRow.Reason)</td></tr>")
    }
    $mappingSummary=('Standard catalog mapping: {0} adapted, {1} not applicable, {2} deferred, {3} reused as-is.' -f @($Evaluation.StandardMapping | Where-Object Mapping -eq 'Adapted').Count,@($Evaluation.StandardMapping | Where-Object Mapping -eq 'Not Applicable').Count,@($Evaluation.StandardMapping | Where-Object Mapping -eq 'Deferred').Count,@($Evaluation.StandardMapping | Where-Object Mapping -eq 'Reused as-is').Count)
    $head=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Azure SQL Database Engine Security Assessment</title><style>
body{font-family:Segoe UI,Arial,sans-serif;color:#1f2933;margin:24px;background:#f4f7f6}main{max-width:1180px;margin:auto}.card{background:white;border:1px solid #d8dee4;border-radius:8px;padding:18px;margin:14px 0}h1,h2,h3{color:#17324d}table{border-collapse:collapse;width:100%;margin:10px 0}th,td{border:1px solid #d8dee4;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3f7}.badge{font-weight:600}.finding{color:#9b1c1c}.pass{color:#176b3a}.gap{color:#8a5a00}.muted{color:#52606d}.evidence{background:#f8fafb;padding:8px;white-space:pre-wrap;overflow-wrap:anywhere}.notice{border-left:4px solid #c27c0e;background:#fff8e7;padding:12px}a{color:#075a9c}</style></head><body><main>
<h1>Azure SQL Database Engine Security Assessment</h1>
<p><strong>Scope:</strong> database-engine identity and privilege evidence only. This report does not assess Azure firewall/network configuration, private endpoints, auditing, Defender, TDE/CMK, backups, or other Azure control-plane settings.</p>
<div class="notice"><strong>Partial engine assessment.</strong> Catalog rows may be hidden by SQL metadata visibility, and all-visible database inventory may be incomplete. A score applies only to the rule instances with sufficient evidence listed in this report; it is not a full Standard catalog score or a complete Azure security assessment. Azure control-plane settings are outside this report.</div>
<section class="card"><h2>Run and coverage</h2><table><tr><th>Logical server</th><td>$logicalServer</td></tr><tr><th>Requested scope</th><td>$scopeText</td></tr><tr><th>Authenticated identity</th><td>$principal</td></tr><tr><th>Started / ended (UTC)</th><td>$(ConvertTo-AzureHtmlText $Collection.StartedAt) / $(ConvertTo-AzureHtmlText $Collection.EndedAt)</td></tr><tr><th>Databases requested / visible / collected</th><td>$localRequested / $(ConvertTo-AzureHtmlText $visibleCountText) / $localCollected</td></tr><tr><th>Visible database names</th><td>$visibleNamesText</td></tr><tr><th>Inventory</th><td>$(ConvertTo-AzureHtmlText $Collection.Inventory.Status) - $(ConvertTo-AzureHtmlText $Collection.Inventory.VisibilityNote)</td></tr><tr><th>Coverage summary</th><td>$(ConvertTo-AzureHtmlText $Collection.Coverage.Summary)</td></tr><tr><th>Rule outcomes</th><td>Findings $localFinding; Pass $localPass; Not Applicable $localNotApplicable; Not Assessed $localNotAssessed</td></tr><tr><th>Weighted subset score</th><td>$scoreCell - assessed weight $localWeight of $localApplicableWeight applicable weight; $localNotAssessedWeight not-assessed weight and $localNotApplicableWeight not-applicable weight are excluded from score.</td></tr><tr><th>Standard catalog mapping</th><td>$(ConvertTo-AzureHtmlText $mappingSummary)</td></tr></table>
$(if ($Collection.Inventory.ErrorCategory) { '<p class="gap">Master inventory error: {0} ({1}) - {2}</p>' -f (ConvertTo-AzureHtmlText $Collection.Inventory.ErrorCategory),(ConvertTo-AzureHtmlText $Collection.Inventory.SupportCode),(ConvertTo-AzureHtmlText $Collection.Inventory.UserMessage) })
$(if ($links) { "<h3>Per-database reports</h3><ul>$links</ul>" })</section>
<section class="card"><h2>Standard catalog mapping</h2><p>The mapping describes how the Standard check catalog relates to this Azure SQL Database engine assessment. “Deferred” means this report does not claim an equivalent result. “Not Applicable” identifies SQL Server features absent from this service or an inapplicable engine scope. See the versioned mapping document distributed with this package for preserved Standard severity, evidence contracts, references, and detailed rationale.</p><table><tr><th>Standard ID</th><th>Standard check</th><th>Azure mapping</th><th>Azure rule ID</th><th>Rationale</th></tr>$($mappingRows -join "`n")</table></section>
"@
    $sections.Add($head)
    foreach ($db in $dbResults) {
        $dbName=ConvertTo-AzureHtmlText $db.Database
        $dbOutcomes=@($ruleCounts | Where-Object Database -ceq $db.Database)
        $ruleRows=New-Object System.Collections.Generic.List[string]
        foreach ($outcome in $dbOutcomes) {
            $css=if ($outcome.Status -eq 'Finding') {'finding'} elseif ($outcome.Status -eq 'Pass') {'pass'} else {'gap'}
            $referenceLinks=New-Object System.Collections.Generic.List[string]
            foreach ($reference in $outcome.References) { $safeReference=ConvertTo-AzureHtmlText $reference; $referenceLinks.Add("<a href='$safeReference' rel='noreferrer'>$safeReference</a>") }
            $ruleRows.Add("<tr><td>$(ConvertTo-AzureHtmlText $outcome.RuleId)</td><td>$(ConvertTo-AzureHtmlText $outcome.Title)</td><td>$(ConvertTo-AzureHtmlText $outcome.Scope)</td><td>$(ConvertTo-AzureHtmlText $outcome.Severity)</td><td class='$css'>$(ConvertTo-AzureHtmlText $outcome.Status)</td><td>$(ConvertTo-AzureHtmlText $outcome.Reason)</td><td>$(ConvertTo-AzureHtmlText ($outcome.EvidenceQueryIds -join ', '))</td><td>$(ConvertTo-AzureHtmlText $outcome.Recommendation)</td><td>$($referenceLinks -join '<br>')</td></tr>")
            foreach ($finding in $outcome.Findings) {
                $fields=New-Object System.Collections.Generic.List[string]
                foreach ($prop in $finding.PSObject.Properties) { $fields.Add((' {0}: {1}' -f [string]$prop.Name,[string]$prop.Value)) }
                $ruleRows.Add("<tr><td colspan='9'><strong>Observed match</strong><div class='evidence'>$(ConvertTo-AzureHtmlText ($fields -join ';'))</div></td></tr>")
            }
            foreach ($context in $outcome.ContextEvidence) {
                $fields=New-Object System.Collections.Generic.List[string]
                foreach ($prop in $context.PSObject.Properties) { $fields.Add((' {0}: {1}' -f [string]$prop.Name,[string]$prop.Value)) }
                $ruleRows.Add("<tr><td colspan='9'><strong>Context evidence (not a finding)</strong><div class='evidence'>$(ConvertTo-AzureHtmlText ($fields -join ';'))</div></td></tr>")
            }
        }
        $queryRows=New-Object System.Collections.Generic.List[string]
        foreach ($q in $db.EvidenceQueries) {
            $css=if ($q.Status -eq 'Succeeded') {'pass'} else {'gap'}
            $queryRows.Add("<tr><td>$(ConvertTo-AzureHtmlText $q.QueryId)</td><td class='$css'>$(ConvertTo-AzureHtmlText $q.Status)</td><td>$(@($q.Rows).Count)</td><td>$(ConvertTo-AzureHtmlText $q.ErrorCategory) $(ConvertTo-AzureHtmlText $q.SupportCode) $(ConvertTo-AzureHtmlText $q.UserMessage)</td></tr>")
            if (@($q.Rows).Count -gt 0) { $serialized=ConvertTo-Json -InputObject @($q.Rows) -Depth 6; $queryRows.Add("<tr><td colspan='4'><details><summary>Evidence rows: $(ConvertTo-AzureHtmlText $q.QueryId)</summary><div class='evidence'>$(ConvertTo-AzureHtmlText $serialized)</div></details></td></tr>") }
        }
        $section=@"
<section class="card"><h2>Database: $dbName</h2><p><strong>Status:</strong> <span class="$(if ($db.Status -eq 'Collected') {'pass'} else {'gap'})">$(ConvertTo-AzureHtmlText $db.Status)</span></p><p><strong>Principal:</strong> $(ConvertTo-AzureHtmlText $db.AuthenticatedPrincipal)</p><p><strong>Metadata visibility:</strong> $(ConvertTo-AzureHtmlText $db.MetadataVisibility)</p><p><strong>Evidence time (UTC):</strong> $(ConvertTo-AzureHtmlText $db.StartedAt) - $(ConvertTo-AzureHtmlText $db.EndedAt)</p>
$(if ($db.ErrorCategory) { '<p class="gap">{0} ({1}) - {2}</p>' -f (ConvertTo-AzureHtmlText $db.ErrorCategory),(ConvertTo-AzureHtmlText $db.SupportCode),(ConvertTo-AzureHtmlText $db.UserMessage) })
<h3>Rule outcomes</h3><table><tr><th>Rule ID</th><th>Rule</th><th>Scope</th><th>Severity</th><th>Outcome</th><th>Evaluation</th><th>Evidence query IDs</th><th>Recommendation</th><th>References</th></tr>$($ruleRows -join "`n")</table>
<h3>Evidence queries</h3><table><tr><th>Query ID</th><th>Status</th><th>Rows</th><th>Sanitized diagnostic</th></tr>$($queryRows -join "`n")</table></section>
"@
        $sections.Add($section)
    }
    if ($OnlyDatabase) {$serverOutcomes=@()} else {$serverOutcomes=@($ruleCounts | Where-Object Scope -eq 'LogicalServer')}
    if ($serverOutcomes.Count -gt 0) {
        $serverRows=New-Object System.Collections.Generic.List[string]
        foreach ($outcome in $serverOutcomes) {
            $serverRows.Add("<tr><td>$(ConvertTo-AzureHtmlText $outcome.RuleId)</td><td>$(ConvertTo-AzureHtmlText $outcome.Scope)</td><td>$(ConvertTo-AzureHtmlText $outcome.Status)</td><td>$(ConvertTo-AzureHtmlText $outcome.Reason)</td><td>$(ConvertTo-AzureHtmlText ($outcome.EvidenceQueryIds -join ', '))</td></tr>")
            foreach ($match in $outcome.Findings) {$serverRows.Add("<tr><td colspan='5'><div class='evidence'>$(ConvertTo-AzureHtmlText (($match.PSObject.Properties | ForEach-Object { '{0}: {1}' -f $_.Name,$_.Value }) -join '; '))</div></td></tr>")}
        }
        $masterQueries=@($Collection.Inventory.ServerEvidence)
        $masterRows=New-Object System.Collections.Generic.List[string]
        foreach ($q in $masterQueries) {$masterRows.Add("<tr><td>$(ConvertTo-AzureHtmlText $q.QueryId)</td><td>$(ConvertTo-AzureHtmlText $q.Status)</td><td>$(@($q.Rows).Count)</td><td>$(ConvertTo-AzureHtmlText $q.ErrorCategory) $(ConvertTo-AzureHtmlText $q.SupportCode) $(ConvertTo-AzureHtmlText $q.UserMessage)</td></tr>"); if (@($q.Rows).Count -gt 0) {$masterRows.Add("<tr><td colspan='4'><div class='evidence'>$(ConvertTo-AzureHtmlText (ConvertTo-Json -InputObject @($q.Rows) -Depth 6))</div></td></tr>")}}
        $sections.Add("<section class='card'><h2>Logical-server scope</h2><p>Master-scoped checks are separate from database checks. An explicit database run marks them Not Applicable. Their evidence may itself have limited metadata visibility.</p><table><tr><th>Rule</th><th>Scope</th><th>Outcome</th><th>Evaluation</th><th>Evidence query IDs</th></tr>$($serverRows -join "`n")</table><h3>Master evidence</h3><table><tr><th>Query ID</th><th>Status</th><th>Rows</th><th>Sanitized diagnostic</th></tr>$($masterRows -join "`n")</table></section>")
    }
    $sections.Add('</main></body></html>')
    $sections -join "`n"
}

function New-AzureSqlAssessmentReports {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$CollectionResult,[Parameter(Mandatory=$true)][string]$ResultsFolder,[switch]$CreateIndividualReports,[string]$Timestamp=(Get-Date -Format 'yyyyMMdd_HHmmss'))
    $hasEvidence=@($CollectionResult.Databases | Where-Object { $_.Database -and @($_.EvidenceQueries | Where-Object Status -eq 'Succeeded').Count -gt 0 }).Count -gt 0
    if (-not $hasEvidence) { return [pscustomobject]@{ Published=$false; ReportPath=$null; IndividualReports=@(); Evaluation=$null; UserMessage='No Azure database evidence was successfully collected. No security report was written.' } }
    $evaluation=Invoke-AzureSqlRuleEvaluation -CollectionResult $CollectionResult
    $serverToken=ConvertTo-AzureSafeFileToken -Value $CollectionResult.LogicalServer
    if (-not (Test-Path -LiteralPath $ResultsFolder -PathType Container)) { New-Item -ItemType Directory -Path $ResultsFolder -Force | Out-Null }
    $reportPath=Join-Path $ResultsFolder ("{0}_AzureSQL_Engine_Assessment_{1}.html" -f $serverToken,$Timestamp)
    $individual=@(); $links=@{}
    if ($CreateIndividualReports) {
        $individualFolder=Join-Path $ResultsFolder ("{0}_AzureSQL_Database_Reports_{1}" -f $serverToken,$Timestamp)
        New-Item -ItemType Directory -Path $individualFolder -Force | Out-Null
        foreach ($db in @($CollectionResult.Databases | Where-Object { $_.Database -and @($_.EvidenceQueries | Where-Object Status -eq 'Succeeded').Count -gt 0 })) {
            $dbToken=ConvertTo-AzureSafeFileToken -Value ([string]$db.Database)
            $dbPath=Join-Path $individualFolder ("{0}_{1}_AzureSQL_Engine_Assessment_{2}.html" -f $serverToken,$dbToken,$Timestamp)
            $links[[string]$db.Database]=$dbPath
            $dbHtml=New-AzureSqlAssessmentHtml -Collection $CollectionResult -Evaluation $evaluation -OnlyDatabase ([string]$db.Database)
            [System.IO.File]::WriteAllText($dbPath,$dbHtml,(New-Object System.Text.UTF8Encoding($false)))
            $individual += $dbPath
        }
    }
    $html=New-AzureSqlAssessmentHtml -Collection $CollectionResult -Evaluation $evaluation -ReportLinks $links
    [System.IO.File]::WriteAllText($reportPath,$html,(New-Object System.Text.UTF8Encoding($false)))
    [pscustomobject]@{ Published=$true; ReportPath=$reportPath; IndividualReports=[string[]]$individual; Evaluation=$evaluation; UserMessage=('Azure SQL Database engine assessment report written: {0}' -f $reportPath) }
}

Export-ModuleMember -Function Test-AzureSqlConnection, Test-AzureSqlPermissions, Get-AzureSqlCheckProfile, Get-AzureSqlDatabaseInventory, Invoke-AzureSqlEvidenceCollection, Invoke-AzureSqlCompatibilityAssessment, Get-AzureSqlQueryMatrix, Get-AzureSqlRuleCatalog, Get-AzureStandardRuleMapping, Invoke-AzureSqlRuleEvaluation, New-AzureSqlAssessmentReports, ConvertTo-AzureSafeFileToken
