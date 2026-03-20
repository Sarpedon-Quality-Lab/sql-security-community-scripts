<#
.SYNOPSIS
    SQL Server Security Assessment Collector - Community Edition

.DESCRIPTION
    Logic & Engine by Andreas Wolter (MCSM). 
    This script orchestrates the collection of security metadata and 
    generates the High-Level Security Indicators HTML report.

.PARAMETER SqlInstance
    The SQL Server instance(s) to be assessed.

.NOTES
    Version:  2026.1
    Author:   Andreas Wolter (Sarpedon Quality Lab)
    License:  Sarpedon Community License
    Website:  https://www.SarpedonQualityLab.US/resources

    DISCLAIMER:
    This tool is provided "as is" for informational purposes only. It identifies 
    high-level indicators of risk and does not constitute a comprehensive security 
    audit, legal advice, or a guarantee of security. The author and Sarpedon 
    Quality Lab LLC assume no liability for any inaccuracies, system impacts, 
    or security incidents occurring after its use. Use at your own risk.

.EXAMPLE
    .\Get-SqlSecurityIndicators.ps1 -SqlInstance "SQLPROD01"
#>

# --- Dependency Check: Invoke-Sqlcmd ---
if (-not (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue)) {

    $msg = @"
The required PowerShell cmdlet 'Invoke-Sqlcmd' is not available on this system.

This tool depends on the SqlServer PowerShell module.

To install it, run the following command in PowerShell:

Install-Module SqlServer -Scope CurrentUser

If your environment restricts internet access, please contact your administrator.

Execution has been stopped.
"@

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show($msg, "Missing Dependency", 'OK', 'Error') | Out-Null
    } catch {
        Write-Error $msg
    }

    return
}
# --- End Dependency Check ---


$Debug                  = 'false'

# --- CONFIGURATION ---
$ScriptRoot                = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReleaseVersion            = '2026.1'
$AuthMethod                = 'Windows'
$Username                  = ''
$Password                  = ''
$EncryptOption             = 'Optional'
$TrustCert                 = $false

$SqlServer                 = $null
$Database                  = 'master'
$SqlFilePath               = Join-Path $ScriptRoot 'SqlSafe_202601.sql'

$ResultsFolder             = Join-Path $ScriptRoot 'Results'
if (-not (Test-Path $ResultsFolder)) {
    New-Item -ItemType Directory -Path $ResultsFolder | Out-Null
}

# --- FUNCTIONS ---
function Show-UiMessage {
    param(
        [string]$Message,
        [string]$Title = 'SQL Security Assessment',
        [ValidateSet('Info','Warning','Error')]
        [string]$Kind = 'Info'
    )

    $image = switch ($Kind) {
        'Warning' { [System.Windows.MessageBoxImage]::Warning }
        'Error'   { [System.Windows.MessageBoxImage]::Error }
        default   { [System.Windows.MessageBoxImage]::Information }
    }

    [System.Windows.MessageBox]::Show(
        $Message,
        $Title,
        [System.Windows.MessageBoxButton]::OK,
        $image
    ) | Out-Null
}

function Get-DialogInput {
    param($ServerInput, $WinAuth, $UsernameInput, $PasswordInput, $EncryptOption, $TrustCert)

    [pscustomobject]@{
        SqlServer     = $ServerInput.Text.Trim()
        AuthMethod    = if ($WinAuth.IsChecked) { 'Windows' } else { 'SQL' }
        Username      = $UsernameInput.Text.Trim()
        Password      = $PasswordInput.Password
        EncryptOption = if ($EncryptOption.SelectedItem) { [string]$EncryptOption.SelectedItem.Tag } else { 'Optional' }
        TrustCert     = [bool]$TrustCert.IsChecked
    }
}

function Validate-DialogInput {
    param(
        [Parameter(Mandatory)]$InputObject,
        [switch]$ForConnect
    )

    if ([string]::IsNullOrWhiteSpace($InputObject.SqlServer)) {
        return 'Please enter a SQL Server name or instance.'
    }

    if ($InputObject.AuthMethod -eq 'SQL') {
        if ([string]::IsNullOrWhiteSpace($InputObject.Username)) {
            return 'Please enter a username for SQL Server Authentication.'
        }

        if ($ForConnect -and [string]::IsNullOrWhiteSpace($InputObject.Password)) {
            return 'Please enter a password for SQL Server Authentication.'
        }
    }

    return $null
}

function Build-TestConnectionString {
    param(
        [Parameter(Mandatory)]$InputObject
    )

    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $InputObject.SqlServer
    $builder['Initial Catalog'] = 'master'
    $builder['Connect Timeout'] = 5
    $builder['Application Name'] = 'SQL Security Assessment - Test Connection'

    switch ($InputObject.EncryptOption) {
        'Mandatory' { $builder['Encrypt'] = $true }
        default     { $builder['Encrypt'] = $false }
    }

    $builder['TrustServerCertificate'] = $InputObject.TrustCert

    if ($InputObject.AuthMethod -eq 'Windows') {
        $builder['Integrated Security'] = $true
    }
    else {
        $builder['User ID'] = $InputObject.Username
        $builder['Password'] = $InputObject.Password
    }

    $builder.ConnectionString
}

function Test-SqlConnection {
    param(
        [Parameter(Mandatory)]$InputObject
    )

    if ($InputObject.EncryptOption -eq 'Strict') {
        throw 'Strict encryption is not testable with this dialog''s built-in System.Data.SqlClient probe. It requires a newer SQL client driver and is intended for SQL Server 2022 / Azure SQL.'
    }

    $connectionString = Build-TestConnectionString -InputObject $InputObject
    $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString

    try {
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandText = @"
SELECT
    CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS ProductVersion,
    CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)) AS ProductLevel,
    CAST(SERVERPROPERTY('Edition') AS nvarchar(256)) AS Edition
"@
        $reader = $command.ExecuteReader()
        $row = $null
        if ($reader.Read()) {
            $row = [pscustomobject]@{
                ProductVersion = [string]$reader['ProductVersion']
                ProductLevel   = [string]$reader['ProductLevel']
                Edition        = [string]$reader['Edition']
            }
        }
        $reader.Close()
        return $row
    }
    finally {
        if ($connection.State -ne [System.Data.ConnectionState]::Closed) {
            $connection.Close()
        }
        $connection.Dispose()
    }
}

function Format-ServerName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }

    $segments = $Name.Split('\')
    $segments = foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment)) { $segment }
        else { $segment.Substring(0,1).ToUpper() + $segment.Substring(1) }
    }
    [string]::Join('\', $segments)
}

function Normalize-RecText {
    param([string]$Text)

    if ($null -eq $Text) { return '' }

    $Text = [string]$Text

    $badEnDash1 = ([string][char]0x00C3) + [char]0x00A2 + [char]0x00E2 + [char]0x201A + [char]0x00AC + [char]0x00E2 + [char]0x20AC + [char]0x0153
    $badEmDash1 = ([string][char]0x00C3) + [char]0x00A2 + [char]0x00E2 + [char]0x201A + [char]0x00AC + [char]0x00E2 + [char]0x20AC + [char]0x009D
    $badEnDash2 = ([string][char]0x00E2) + [char]0x20AC + [char]0x201C
    $badEmDash2 = ([string][char]0x00E2) + [char]0x20AC + [char]0x201D
    $goodEnDash = [string][char]0x2013
    $goodEmDash = [string][char]0x2014

    $Text = $Text.Replace($badEnDash1, $goodEnDash)
    $Text = $Text.Replace($badEmDash1, $goodEmDash)
    $Text = $Text.Replace($badEnDash2, $goodEnDash)
    $Text = $Text.Replace($badEmDash2, $goodEmDash)

    return $Text.Trim()
}

function Protect-HeaderValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }

    $text = [string]$Value

    # Never allow likely credentials to appear in report header fields
    if ($text -eq [string]$Password) { return '[redacted]' }
    if ($text -eq [string]$Username -and -not [string]::IsNullOrWhiteSpace($text)) { return '[redacted]' }

    # Defensive redaction for common key/value accidental leaks
    $text = $text -replace '(?i)\b(password|pwd)\s*=\s*[^;,\s]+', '$1=[redacted]'
    $text = $text -replace '(?i)\b(user\s*id|uid|username)\s*=\s*[^;,\s]+', '$1=[redacted]'

    return $text
}

function Normalize-CheckId {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $number = 0
    if ([int]::TryParse($text.Trim(), [ref]$number)) {
        return ('{0:D3}' -f $number)
    }

    return $text.Trim()
}

function Get-RowCheckId {
    param([object]$Row)
    if ($null -eq $Row) { return $null }
    if ($Row.PSObject.Properties['Check ID']) { return Normalize-CheckId $Row.'Check ID' }
    if ($Row.PSObject.Properties['ID']) { return Normalize-CheckId $Row.ID }
    return $null
}

function Get-RowCheckName {
    param([object]$Row)
    if ($null -eq $Row) { return '' }
    if ($Row.PSObject.Properties['Check Name']) { return [string]$Row.'Check Name' }
    if ($Row.PSObject.Properties['Name']) { return [string]$Row.Name }
    return ''
}

function Test-IsInformationalOnlyCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckId
    )

    $number = 0
    if ([int]::TryParse($CheckId, [ref]$number)) {
        return ($number -ge 800 -and $number -le 899)
    }

    return $false
}

function Get-ExecutiveData {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    return @($Items | Where-Object { -not (Test-IsInformationalOnlyCheck -CheckId ([string]$_.CheckId)) })
}

function Normalize-LevelOfEffort {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return 'Unspecified' }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return 'Unspecified' }

    switch -Regex ($text.ToUpperInvariant()) {
        '^LOW$' { return 'Low' }
        '^MEDIUM$' { return 'Medium' }
        '^HIGH$' { return 'High' }
        '^UNSPECIFIED$' { return 'Unspecified' }
        default { return 'Unspecified' }
    }
}

function Get-NumericValueFromColumn {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)]
        [string]$ColumnName
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return $null }
    if ([string]::IsNullOrWhiteSpace($ColumnName)) { return $null }

    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        if (-not $row.PSObject.Properties[$ColumnName]) { continue }

        $raw = $row.$ColumnName
        if ($null -eq $raw) { continue }

        $num = 0.0
        if ([double]::TryParse([string]$raw, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$num)) {
            return $num
        }
        if ([double]::TryParse([string]$raw, [ref]$num)) {
            return $num
        }
    }

    return $null
}

function Get-FirstNumericValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    foreach ($row in $Rows) {
        $props = @($row.PSObject.Properties | Select-Object -Skip 2)
        foreach ($prop in $props) {
            if ($null -eq $prop.Value) { continue }

            $parsed = 0.0
            $text = [string]$prop.Value
            if ([double]::TryParse($text, [ref]$parsed)) {
                return $parsed
            }
        }
    }

    return $null
}

function Get-SqlDefinedChecks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SqlText
    )

    $results = @()
    $seen = @{}
    $order = 0

    $commentPattern = "(?im)^\s*--\s*Check\s*:\s*(?<CheckId>\d{1,3})\s+(?<CheckName>.+?)\.sql\s*$"
    $commentMatches = [System.Text.RegularExpressions.Regex]::Matches($SqlText, $commentPattern)

    foreach ($match in $commentMatches) {
        $order++
        $checkId = Normalize-CheckId $match.Groups['CheckId'].Value
        if ($null -eq $checkId) { continue }
        if ($seen.ContainsKey($checkId)) { continue }

        $checkName = [string]$match.Groups['CheckName'].Value
        $seen[$checkId] = $true

        $results += [PSCustomObject]@{
            CheckId   = $checkId
            CheckName = $checkName.Trim()
            SqlOrder  = $order
        }
    }

    if ($results.Count -gt 0) {
        return @($results)
    }

    $selectPattern = "(?is)(?:N)?'(?<CheckId>\d{1,3})'\s+AS\s+\[(?:Check\s*ID|CheckID)\]\s*,\s*(?:N)?'(?<CheckName>(?:''|[^'])*)'\s+AS\s+\[(?:Check\s*Name|CheckName)\]"
    $selectMatches = [System.Text.RegularExpressions.Regex]::Matches($SqlText, $selectPattern)

    foreach ($match in $selectMatches) {
        $order++
        $checkId = Normalize-CheckId $match.Groups['CheckId'].Value
        if ($null -eq $checkId) { continue }
        if ($seen.ContainsKey($checkId)) { continue }

        $checkName = $match.Groups['CheckName'].Value -replace "''", "'"
        $seen[$checkId] = $true

        $results += [PSCustomObject]@{
            CheckId   = $checkId
            CheckName = [string]$checkName
            SqlOrder  = $order
        }
    }

    return @($results)
}

function Get-OutcomeBadgeHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Outcome
    )

    return "<span class='badge outcome-$Outcome'>$Outcome</span>"
}

function Get-ChecksProgressHtml {
    param(
        [int]$Passed,
        [int]$Total
    )

    $percent = 0
    if ($Total -gt 0) {
        $percent = [math]::Round(($Passed / $Total) * 100)
    }

    return @"
<div class='checks-progress' title='$Passed of $Total checks passed'>
    <div class='checks-progress-track'>
        <div class='checks-progress-fill' style='width: $($percent)%;'></div>
    </div>
    <div class='checks-progress-text'>$Passed / $Total</div>
</div>
"@
}

function Convert-DataRowsToHtmlTable {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return "<div class='empty-detail'>No detail rows returned for this check.</div>"
    }

    $excludeColumns = @(
        'Check ID', 'Check Name', 'ID', 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors'
    )

    $detailColumnNames = @(
        $Rows[0].PSObject.Properties |
        Where-Object { $_.Name -notin $excludeColumns } |
        Select-Object -ExpandProperty Name
    )

    if ($detailColumnNames.Count -eq 0) {
        return "<div class='empty-detail'>No detail columns returned.</div>"
    }

    function Test-IsEmptyAdditionalInfoValue {
        param([AllowNull()][object]$Value)

        if ($null -eq $Value) { return $true }

        $text = ([string]$Value).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { return $true }

        $normalized = $text.ToLowerInvariant()
        if ($normalized -in @(
            '{}',
            '<additionalinfo />',
            '<additionalinfo/>',
            '&lt;additionalinfo /&gt;',
            '&lt;additionalinfo/&gt;'
        )) { return $true }

        return $false
    }

    $headerCells = foreach ($columnName in $detailColumnNames) {
        $safeName = [System.Net.WebUtility]::HtmlEncode([string]$columnName)
        "<th>$safeName</th>"
    }

    $bodyRows = foreach ($row in $Rows) {
        $cells = foreach ($columnName in $detailColumnNames) {
            $value = $row.$columnName

            if ([string]$columnName -eq 'AdditionalInfo') {
                if (Test-IsEmptyAdditionalInfoValue $value) {
                    "<td class='additional-info-cell'></td>"
                    continue
                }

                $safeXml = [System.Net.WebUtility]::HtmlEncode([string]$value)
                "<td class='additional-info-cell'><details class='xml-expand'><summary>Show XML</summary><div class='xml-content'>$safeXml</div></details></td>"
                continue
            }

            if ($null -eq $value) {
                $textValue = ''
            }
            elseif ($value -is [byte[]]) {
                $bytes = $value
                while ($bytes.Length -gt 0 -and $bytes[-1] -eq 0) {
                    $bytes = $bytes[0..($bytes.Length - 2)]
                }

                if ($bytes.Length -eq 0) {
                    $textValue = ''
                }
                else {
                    $textValue = '0x' + (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
                }
            }
            else {
                $textValue = [string]$value
            }

            $safeValue = [System.Net.WebUtility]::HtmlEncode($textValue)
            "<td>$safeValue</td>"
        }

        "<tr>$($cells -join '')</tr>"
    }

    return @"
<table class='detail-table'>
    <thead>
        <tr>
            $($headerCells -join '')
        </tr>
    </thead>
    <tbody>
        $($bodyRows -join "`r`n")
    </tbody>
</table>
"@
}

function Get-RecommendationLookup {
    param()
    return $RecommendationLookup
}

function Get-RecommendationCellHtml {
    param(
        [string]$Outcome,
        [string]$CheckId,
        [hashtable]$RecommendationLookup
    )

    if ($Outcome -eq 'PASS' -or $Outcome -eq 'INFO') {
        return "<span class='recommendation-muted'>&mdash;</span>"
    }

    if ($RecommendationLookup.ContainsKey($CheckId)) {
        $text = [string]$RecommendationLookup[$CheckId].Recommendation
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $safeText = [System.Net.WebUtility]::HtmlEncode($text) -replace "(`r`n|`r|`n)", "<br />"
            return "<div class='recommendation-main'>$safeText</div>"
        }
    }

    return "<div class='recommendation-main recommendation-missing'>MISSING</div>"
}

function Get-LevelOfEffortValue {
    param(
        [string]$Outcome,
        [string]$CheckId,
        [hashtable]$RecommendationLookup
    )

    if ($Outcome -eq 'PASS' -or $Outcome -eq 'INFO') {
        return 'Unspecified'
    }

    if ($RecommendationLookup.ContainsKey($CheckId)) {
        return (Normalize-LevelOfEffort $RecommendationLookup[$CheckId].LevelOfEffort)
    }

    return 'Unspecified'
}

function Get-RecommendationPanelHtml {
    param(
        [string]$Outcome,
        [string]$CheckId,
        [hashtable]$RecommendationLookup
    )

    if ($Outcome -eq 'PASS' -or $Outcome -eq 'INFO') {
        return ""
    }

    $text = 'MISSING'
        $referenceTitle = ''
    $referenceUrl = ''
    $referenceTitle2 = ''
    $referenceUrl2 = ''

    if ($RecommendationLookup.ContainsKey($CheckId)) {
        $candidateText = [string]$RecommendationLookup[$CheckId].Recommendation
        if (-not [string]::IsNullOrWhiteSpace($candidateText)) {
            $text = $candidateText
        }
        $referenceTitle = Normalize-RecText ([string]$RecommendationLookup[$CheckId].ReferenceTitle)
        $referenceUrl = [string]$RecommendationLookup[$CheckId].ReferenceUrl
        $referenceTitle2 = Normalize-RecText ([string]$RecommendationLookup[$CheckId].ReferenceTitle2)
        $referenceUrl2 = [string]$RecommendationLookup[$CheckId].ReferenceUrl2
    }

    $safeText = [System.Net.WebUtility]::HtmlEncode($text) -replace "(`r`n|`r|`n)", "<br />"
    
    $referenceHtmlBlocks = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($referenceUrl)) {
        $safeUrl = [System.Net.WebUtility]::HtmlEncode($referenceUrl)
        if (-not [string]::IsNullOrWhiteSpace($referenceTitle)) {
            if ($referenceTitle -match '^\s*ReferenceTitle\s*=\s*(.+)$') { $referenceTitle = $matches[1].Trim() }
            $safeLinkText = [System.Net.WebUtility]::HtmlEncode($referenceTitle)
        }
        else {
            $safeLinkText = $safeUrl
        }

        $referenceHtmlBlocks.Add("<div class='recommendation-reference'><strong>Reference:</strong> <a href='$safeUrl' target='_blank' rel='noopener noreferrer'>$safeLinkText</a></div>") | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($referenceUrl2)) {
        $safeUrl2 = [System.Net.WebUtility]::HtmlEncode($referenceUrl2)
        if (-not [string]::IsNullOrWhiteSpace($referenceTitle2)) {
            if ($referenceTitle2 -match '^\s*ReferenceTitle2\s*=\s*(.+)$') { $referenceTitle2 = $matches[1].Trim() }
            $safeLinkText2 = [System.Net.WebUtility]::HtmlEncode($referenceTitle2)
        }
        else {
            $safeLinkText2 = $safeUrl2
        }

        $referenceHtmlBlocks.Add("<div class='recommendation-reference'><strong>Reference:</strong> <a href='$safeUrl2' target='_blank' rel='noopener noreferrer'>$safeLinkText2</a></div>") | Out-Null
    }

    $referencesHtml = $referenceHtmlBlocks -join "`r`n"

    return @"
<div class='recommendation-panel outcome-$Outcome'>
    <div class='recommendation-title'>Recommendation</div>
    <div class='recommendation-body'>$safeText</div>
    $referencesHtml
</div>
"@
}

function Get-ExecutiveSummaryHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $defaultIntro = @"
<div class='executive-summary-block'>
    <h2>Executive Summary</h2>
    <p>Add your management summary here.</p>
    <div class='executive-priority-list'>
        <h3>Priority Findings</h3>
        <!--PRIORITY_FINDINGS-->
    </div>
</div>
"@

    if (Test-Path $Path) {
        try {
            return Get-Content -Path $Path -Raw -ErrorAction Stop
        }
        catch {
            return '<div class="executive-summary-block"><p>Executive summary file could not be read.</p></div>'
        }
    }

    return $defaultIntro
}

function Get-ChartHtml {
    param(
        [int]$Passes,
        [int]$Observes,
        [int]$Warns,
        [int]$Fails,
        [int]$InfoCount,
        [int]$ActionableTotal,
        [int]$OverallTotal)

    $outcomeTotal = [Math]::Max(1, ($Passes + $Observes + $Warns + $Fails))
    $passPct = [Math]::Round(($Passes / $outcomeTotal) * 100, 0)
    $observePct = [Math]::Round(($Observes / $outcomeTotal) * 100, 0)
    $warningPct = [Math]::Round(($Warns / $outcomeTotal) * 100, 0)
    $failPct = [Math]::Max(0, 100 - $passPct - $observePct - $warningPct)

    $mainChartHtml = @"
<div class='chart-card chart-card-primary'>
    <div class='chart-title'>Outcome Distribution</div>
    <div class='distribution-bar' aria-label='Outcome Distribution'>
        <div class='distribution-segment distribution-pass' style='width: $($passPct)%;'></div>
        <div class='distribution-segment distribution-observe' style='width: $($observePct)%;'></div>
        <div class='distribution-segment distribution-warning' style='width: $($warningPct)%;'></div>
        <div class='distribution-segment distribution-fail' style='width: $($failPct)%;'></div>
    </div>
    <div class='chart-legend'>
        <div><span class='legend-swatch distribution-pass'></span>Pass: $Passes ($($passPct)%)</div>
        <div><span class='legend-swatch distribution-observe'></span>Observe: $Observes ($($observePct)%)</div>
        <div><span class='legend-swatch distribution-warning'></span>Warning: $Warns ($($warningPct)%)</div>
        <div><span class='legend-swatch distribution-fail'></span>Fail: $Fails ($($failPct)%)</div>
    </div>
</div>
"@

    return $mainChartHtml
}

function Get-CheckOutcome {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [hashtable]$RecommendationLookup
    )

    if (Test-IsInformationalOnlyCheck -CheckId $CheckId) { return 'INFO' }

    if (-not $Rules.Contains($CheckId)) {
        return 'INFO'
    }

    $rule = $Rules[$CheckId]
    $method = [string]$rule.Method
    $configuredSeverity = 'FAIL'

    if ($rule.ContainsKey('Severity') -and -not [string]::IsNullOrWhiteSpace([string]$rule.Severity)) {
        $configuredSeverity = ([string]$rule.Severity).ToUpperInvariant()
    }

    switch ($method) {
        'static' {
            return $configuredSeverity
        }

        'rows_exist' {
            if ($Rows.Count -gt 0) { return $configuredSeverity }
            return 'PASS'
        }

        'threshold_max' {
            $value = Get-NumericValueFromColumn -Rows $Rows -ColumnName ([string]$rule.Column)
            $limit = $null
            if ($rule.ContainsKey('Limit')) { $limit = [double]$rule.Limit }
            elseif ($rule.ContainsKey('Value')) { $limit = [double]$rule.Value }

            if ($null -ne $value -and $null -ne $limit -and $value -gt $limit) {
                return $configuredSeverity
            }
            return 'PASS'
        }

        'threshold_min' {
            $value = Get-NumericValueFromColumn -Rows $Rows -ColumnName ([string]$rule.Column)
            $limit = $null
            if ($rule.ContainsKey('Limit')) { $limit = [double]$rule.Limit }
            elseif ($rule.ContainsKey('Value')) { $limit = [double]$rule.Value }

            if ($null -eq $value) { return $configuredSeverity }
            if ($null -ne $limit -and $value -lt $limit) { return $configuredSeverity }
            return 'PASS'
        }

        'column_equals' {
            $columnName = [string]$rule.Column
            $expectedValue = [string]$rule.ExpectedValue

            foreach ($row in $Rows) {
                if ($row.PSObject.Properties.Name -contains $columnName) {
                    $actualValue = [string]$row.$columnName
                    if ($actualValue -eq $expectedValue) {
                        return $configuredSeverity
                    }
                }
            }

            return 'PASS'
        }

        'row_count_equals' {
            $expectedCount = 0
            if ($rule.ContainsKey('Count')) {
                $expectedCount = [int]$rule.Count
            }

            if ($Rows.Count -eq $expectedCount) {
                return $configuredSeverity
            }
            return 'PASS'
        }

        'threshold_band_min' {
            $value = Get-FirstNumericValue -Rows $Rows
            if ($null -eq $value) { return 'PASS' }

            $bands = @($rule.Bands | Sort-Object { [double]$_.Limit })
            foreach ($band in $bands) {
                $limit = [double]$band.Limit
                if ($value -lt $limit) {
                    return ([string]$band.Severity).ToUpperInvariant()
                }
            }

            return 'PASS'
        }

        default {
            return 'INFO'
        }
    }
}

function Get-ActionableChecks {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    return @($Items | Where-Object { $_.Outcome -ne 'INFO' })
}

function Get-SectionSeverity {
    <#
    .SYNOPSIS
        Calculates an aggregated section severity for executive reporting.

    .DESCRIPTION
        INFO findings are excluded from the calculation.

        Base weights:
            PASS    = 0
            OBSERVE = 1
            WARNING = 2
            FAIL    = 3

        Override rules:
            - If any FAIL exists, the minimum returned section severity is WARNING.
            - If two or more FAIL findings exist, the section severity is FAIL.
            - If three or more WARNING findings exist, the section severity is WARNING.

        Otherwise, the highest remaining weighted outcome is returned.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    $actionable = @($Items | Where-Object { $_.Outcome -ne 'INFO' })
    if ($actionable.Count -eq 0) {
        if ($Items.Count -gt 0) { return 'INFO' }
        return 'PASS'
    }

    $weightMap = @{
        PASS    = 0
        OBSERVE = 1
        WARNING = 2
        FAIL    = 3
    }

    $failCount = @($actionable | Where-Object { $_.Outcome -eq 'FAIL' }).Count
    $warningCount = @($actionable | Where-Object { $_.Outcome -eq 'WARNING' }).Count

    if ($failCount -ge 2) { return 'FAIL' }
    if ($failCount -ge 1) { return 'WARNING' }
    if ($warningCount -ge 3) { return 'WARNING' }

    $maxWeight = -1
    $result = 'PASS'
    foreach ($item in $actionable) {
        $outcome = [string]$item.Outcome
        if (-not $weightMap.ContainsKey($outcome)) { continue }
        $weight = [int]$weightMap[$outcome]
        if ($weight -gt $maxWeight) {
            $maxWeight = $weight
            $result = $outcome
        }
    }

    return $result
}

function Invoke-AssessmentSqlcmd {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        [Parameter(Mandatory = $true)]
        [string]$Database,
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows','SQL')]
        [string]$AuthMethod,
        [string]$Username,
        [string]$Password,
        [ValidateSet('Optional','Mandatory','Strict')]
        [string]$EncryptOption = 'Optional',
        [bool]$TrustCert = $false
    )

    $invokeSqlcmd = Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue
    if (-not $invokeSqlcmd) {
        throw "The required PowerShell cmdlet 'Invoke-Sqlcmd' is not available on this system."
    }

    $availableParams = $invokeSqlcmd.Parameters.Keys
    $splat = @{
        ServerInstance = $ServerInstance
        Database       = $Database
        InputFile      = $InputFile
        ErrorAction    = 'Stop'
    }

    if ($AuthMethod -eq 'SQL') {
        $splat['Username'] = $Username
        $splat['Password'] = $Password
    }

    if ($availableParams -contains 'Encrypt') {
        $splat['Encrypt'] = $EncryptOption
    }
    elseif ($availableParams -contains 'EncryptConnection') {
        switch ($EncryptOption) {
            'Mandatory' { $splat['EncryptConnection'] = $true }
            'Strict' {
                throw "The installed SqlServer PowerShell module does not support Encryption='Strict'. Please use a newer SqlServer module version that supports the -Encrypt parameter."
            }
        }
    }

    if ($TrustCert) {
        if ($availableParams -contains 'TrustServerCertificate') {
            $splat['TrustServerCertificate'] = $true
        }
        else {
            throw "The installed SqlServer PowerShell module does not support the Trust Server Certificate option. Please install a newer SqlServer module or use a trusted SQL Server certificate."
        }
    }

    Invoke-Sqlcmd @splat
}

# --- EMBEDDED DATA (integrated) ---
$AllowedCheckIds = @(
    '802'
    '806'
    '002'
    '003'
    '004'
    '028'
    '031'
    '034'
    '036'
    '038'
    '050'
    '072'
    '078'
    '123'
    '129'
    '155'
    '015'
    '026'
    '027'
    '008'
    '010'
    '079'
    '113'
    '046'
    '059'
    '069'
)
$AllowedCheckIdLookup = @{}
foreach ($id in $AllowedCheckIds) { $AllowedCheckIdLookup[$id] = $true }

$Catalog = @(
    [pscustomobject]@{ 'Check ID' = '002'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '003'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '004'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '008'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '010'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '015'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '026'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '027'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '028'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '031'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '034'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '036'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '038'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '046'; SectionID = '13'; Section = 'Account dependencies and orphaned accounts' },
    [pscustomobject]@{ 'Check ID' = '050'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '059'; SectionID = '15'; Section = 'Basic Security Audit Configuration Review' },
    [pscustomobject]@{ 'Check ID' = '069'; SectionID = '15'; Section = 'Basic Security Audit Configuration Review' },
    [pscustomobject]@{ 'Check ID' = '072'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '078'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '079'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '113'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '123'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '129'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '155'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '802'; SectionID = '0'; Section = 'Information' },
    [pscustomobject]@{ 'Check ID' = '806'; SectionID = '0'; Section = 'Information' }
)

$Rules = [ordered]@{
    '002' = @{ Method = 'column_equals'; Column = 'Result2'; ExpectedValue = 0; Severity = 'OBSERVE' } # Authentication mode
    '003' = @{ Method = 'threshold_max'; Column = 'Result2'; Limit = 10; Severity = 'FAIL' } # SQL Authentication usage
    '004' = @{ Method = 'threshold_max'; Column = 'Result2'; Limit = 10; Severity = 'FAIL' } # NTLM Authentication usage
    '008' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # SA Login Name
    '010' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Sysadmin-members individual accounts
    '015' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Powerful server role membership
    '026' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Server permissions granted to Logins
    '027' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Custom server roles without members
    '028' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Databases with Trustworthy property set
    '031' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # cross db ownership chaining setting
    '034' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # XP_cmdshell setting
    '036' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Ad hoc distributed queries setting
    '038' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # OLE Automation Procedures setting
    '046' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Orphaned Windows Logins
    '050' = @{ Method = 'threshold_min'; Column = 'Number'; Limit = 30; Severity = 'WARNING' } # Number of ErrorLogs kept
    '059' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Security Auditing minimal setup
    '079' = @{ Method = 'static'; Severity = 'INFO' } # SA Login State
    '113' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Custom database roles without members
    '123' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # DBs with AUTO_CLOSE setting on
	'129' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Orphaned Database Users
    '802' = @{ Method = 'static'; Severity = 'INFO' } # Contained AGs present
    '806' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # outstanding configuration changes
}

$RecommendationLookup = @{
    '802' = [pscustomobject]@{ CheckName = 'Contained AGs present'; Recommendation = @'
If contained availability groups are present, review the security and operational implications carefully, including identity handling to ensure that the Contained Availability Group is monitored and secured at the same level as the host.
'@.Trim(); ReferenceTitle = 'Why you should use SQL Server contained availability groups to save time – and why consultants may not tell you about them'; ReferenceUrl = 'https://andreas-wolter.com/en/2504_sqlserver_contained_availability_groups/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '806' = [pscustomobject]@{ CheckName = 'outstanding configuration changes'; Recommendation = @'
There are outstanding configuration changes pending. This means that some settings will only take effect after a server restart or after executing the RECONFIGURE statement. Ensure that you understand which settings will change and validate their impact before they are applied.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '002' = [pscustomobject]@{ CheckName = 'Authentication mode'; Recommendation = @'
SQL Authentication increases the attack surface because credentials must be stored, transmitted, and managed separately from the operating system. Whenever possible, prefer Windows Authentication, which integrates with Active Directory and supports centralized identity management, password policies, and stronger authentication mechanisms. If applications currently require SQL Authentication, work with the application vendor to enable support for Windows Authentication or modern identity solutions. Where SQL logins must remain in use, enforce strong password policies, disable unused accounts, and regularly monitor login activity.
'@.Trim(); ReferenceTitle = 'Choose an authentication mode'; ReferenceUrl = 'https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '003' = [pscustomobject]@{ CheckName = 'SQL Authentication usage'; Recommendation = @'
SQL Authentication increases the attack surface because credentials must be stored, transmitted, and managed separately from the operating system. Whenever possible, prefer Windows Authentication, which integrates with Active Directory and supports centralized identity management, password policies, and stronger authentication mechanisms. If applications currently require SQL Authentication, work with the application vendor to enable support for Windows Authentication or modern identity solutions. Where SQL logins must remain in use, enforce strong password policies, disable unused accounts, and regularly monitor login activity.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '004' = [pscustomobject]@{ CheckName = 'NTLM Authentication usage'; Recommendation = @'
More than 10% of observed connections are still using NTLM. NTLM is on a deprecation path and provides weaker security compared to modern alternatives such as Kerberos. Reduce and phase out NTLM wherever possible by identifying affected clients and migrating them to Kerberos-based authentication.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '028' = [pscustomobject]@{ CheckName = 'Databases with Trustworthy property set'; Recommendation = @'
The assessment identified databases with the TRUSTWORTHY property set to ON. This setting represents a significant security risk and is commonly classified as a high-severity finding. When a database is marked as TRUSTWORTHY, SQL Server implicitly trusts its contents, which can enable privilege escalation and unauthorized access to server-level resources. Determine the technical reason for this configuration and evaluate safer alternatives, such as module signing (code signing), to achieve the same functionality without relying on TRUSTWORTHY.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = 'TRUSTWORTHY database property'; ReferenceUrl2 = 'https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17' }
    '031' = [pscustomobject]@{ CheckName = 'cross db ownership chaining setting'; Recommendation = @'
The server-level cross-database ownership chaining setting is enabled. This configuration affects all databases on the instance and should be avoided, as it weakens isolation boundaries and enables privilege escalation with relatively little effort. If cross-database access is required, use the database-level setting only for specific databases that explicitly require it, and ensure the configuration is tightly controlled and well documented.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '034' = [pscustomobject]@{ CheckName = 'XP_cmdshell setting'; Recommendation = @'
xp_cmdshell can be abused for command execution and lateral movement and should only be enabled temporarily when absolutely necessary. Disable it by default and document any approved exception with compensating controls.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '036' = [pscustomobject]@{ CheckName = 'Ad hoc distributed queries setting'; Recommendation = @'
The Ad Hoc Distributed Queries setting allows users to access external data sources directly using functions such as OPENROWSET and OPENDATASOURCE. This increases the attack surface by enabling arbitrary connections to external systems, which can lead to unauthorized data access, data exfiltration, or execution of unintended queries—especially when combined with elevated permissions. Disable Ad Hoc Distributed Queries unless there is a clear and documented technical requirement. Where external data access is necessary, prefer controlled mechanisms such as linked servers with explicitly defined security contexts. Due to the increased risk, consider isolating databases that require this setting on a dedicated SQL Server instance.he Ad Hoc Distributed Queries setting allows users to access external data sources directly using functions such as OPENROWSET and OPENDATASOURCE, significantly increasing the attack surface. It enables arbitrary connections to external or untrusted systems, facilitates data exfiltration, and may allow privilege escalation or code execution through vulnerable OLE DB providers under the SQL Server service account. In the event of compromise, it can also be used as a pivot point to access other systems on the network. Where external access is needed, prefer controlled mechanisms such as linked servers with defined security contexts. Disable this setting unless there is a clear and documented technical requirement. Due to the increased risk, consider isolating databases that require this setting on a dedicated SQL Server instance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '038' = [pscustomobject]@{ CheckName = 'OLE Automation Procedures setting'; Recommendation = @'
The OLE Automation Procedures setting allows Transact-SQL code to instantiate COM objects and interact with external Windows components. Enabling this feature represents a significant security risk, as it can be used by an attacker with database access to execute arbitrary commands, modify the registry, or read and write files—effectively bypassing standard SQL Server security boundaries and enabling privilege escalation under the SQL Server service account. Disable OLE Automation Procedures unless there is a strict and documented requirement. Where external interaction is needed, prefer safer alternatives such as SQL Server Agent jobs, CLR integration with strict permission sets, or application-layer logic outside the database. Ensure any required functionality is implemented using controlled, auditable mechanisms rather than direct OS-level access from within SQL Server.
'@.Trim(); ReferenceTitle = 'OLE Automation stored procedures (Transact-SQL)'; ReferenceUrl = 'https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/ole-automation-stored-procedures-transact-sql?view=sql-server-ver17'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '050' = [pscustomobject]@{ CheckName = 'Number of ErrorLogs kept'; Recommendation = @'
Fewer than 30 SQL Server error logs are being retained. Increase the setting to 90 to improve the available history for security investigations, troubleshooting, and forensic review. In practice, there is no downside for having one ErrorLog per day with 90 days history.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '072' = [pscustomobject]@{ CheckName = 'Database Owner sysadmin'; Recommendation = @'
ome databases are owned by logins with sysadmin privileges. This can be abused by users with elevated permissions within the database to escalate privileges to the server level and should therefore be avoided. Use a dedicated, low-privileged login as the database owner instead. If using sa as a consistently available owner, ensure the associated risks are fully understood—especially in combination with settings such as TRUSTWORTHY or features that execute code as the database owner.
'@.Trim(); ReferenceTitle = 'SQL Server Database Ownership: survey results & recommendations'; ReferenceUrl = 'https://andreas-wolter.com/en/sql-server-database-ownership-survey-results-recommendations/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '078' = [pscustomobject]@{ CheckName = 'Database Owner Windows account'; Recommendation = @'
Some databases are owned by Windows accounts. This can cause issues after restores to different servers or if the associated login is removed, and it often indicates weaknesses in database deployment processes. Ensure that all databases are owned by a consistently available account on every server.
'@.Trim(); ReferenceTitle = 'SQL Server Database Ownership: survey results & recommendations'; ReferenceUrl = 'https://andreas-wolter.com/en/sql-server-database-ownership-survey-results-recommendations/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '123' = [pscustomobject]@{ CheckName = 'DBs with AUTO_CLOSE setting on'; Recommendation = @'
The assessment identified databases with AUTO_CLOSE enabled. This setting can negatively impact performance by causing frequent resource initialization and may contribute to instability or enable denial-of-service scenarios. It should not be used on server systems and is only appropriate for limited use cases such as single-user or desktop environments.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '129' = [pscustomobject]@{ CheckName = 'Orphaned Database Users'; Recommendation = @'
The assessment identified orphaned database users without a corresponding login. Review and remove or remap these users to reduce administrative overhead and prevent confusion or unintended permission issues. Orphaned users can also introduce risks such as privilege takeover and non-repudiation by misusing their identities.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '155' = [pscustomobject]@{ CheckName = 'Database Owner not valid'; Recommendation = @'
Some databases do no have a valid owner-match between master and th database itself. This can happen Some databases do not have a valid owner mapping between the metadata in master and the user database. This can occur after a restore when the original owner login does not exist on the target system, or when the owner login has been removed. Such mismatches can lead to unexpected behavior or code execution issues. Ensure that every database has a valid and existing owner. The owner can be set in SSMS under Database - Properties - Files, or by using the ALTER AUTHORIZATION statement.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '015' = [pscustomobject]@{ CheckName = 'Powerful server role membership'; Recommendation = @'
Individual user accounts were found assigned to powerful server roles. Avoid assigning such privileges directly to personal accounts. Instead, use centrally managed Windows groups to reduce the risk of orphaned logins and improve access governance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '026' = [pscustomobject]@{ CheckName = 'Server permissions granted to Logins'; Recommendation = @'
The assessment identified individual accounts with server-level permissions. Avoid assigning such permissions directly to personal accounts. Instead, use centrally managed Windows groups to improve governance, simplify access control, and reduce the risk of orphaned logins.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '027' = [pscustomobject]@{ CheckName = 'Custom server roles without members'; Recommendation = @'
The assessment identified custom server roles without any members. Review these roles and remove those that are no longer required to reduce clutter and maintain a clear and manageable security model.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '008' = [pscustomobject]@{ CheckName = 'SA Login Name'; Recommendation = @'
Review the protection strategy for the built-in sa account carefully. Prioritize auditing both successful and failed logon attempts to detect misuse or attack activity early. Ensure all login attempts are logged, regularly reviewed, and integrated with centralized monitoring or alerting. Restrict direct use of sa to exceptional, well-justified cases and tightly control password exposure.
'@.Trim(); ReferenceTitle = 'To rename or not, that is the question – how to protect SQL Server’s built-in sysadmin account sa'; ReferenceUrl = 'https://andreas-wolter.com/en/202512_renaming-sql-servers-sa-account/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '010' = [pscustomobject]@{ CheckName = 'Sysadmin-members individual accounts'; Recommendation = @'
The assessment identified individual user accounts with sysadmin membership. Limit sysadmin privileges to tightly controlled administrative Windows groups managed in Active Directory, rather than assigning them directly to individual accounts.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '079' = [pscustomobject]@{ CheckName = 'SA Login State'; Recommendation = @'
Disabling the sa account is not a universal best practice and should not be relied upon as a primary security control, as it can lead to unexpected issues during patching or due to script and application dependencies. Instead, ensure that auditing of failed login attempts—especially targeting sa—is properly configured and regularly reviewed to detect brute-force and unauthorized access attempts.
'@.Trim(); ReferenceTitle = 'To rename or not, that is the question – how to protect SQL Server’s built-in sysadmin account sa'; ReferenceUrl = 'https://andreas-wolter.com/en/202512_renaming-sql-servers-sa-account/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '113' = [pscustomobject]@{ CheckName = 'Custom database roles without members'; Recommendation = @'
The assessment found custom database roles without members. Review whether these roles are still needed and remove obsolete roles to keep the permission model understandable and clutter-free.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '046' = [pscustomobject]@{ CheckName = 'Orphaned Windows Logins'; Recommendation = @'
The assessment found orphaned Windows logins that no longer exist in Active Directory. Review and remove them to reduce stale access paths and simplify access governance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '059' = [pscustomobject]@{ CheckName = 'Security Auditing minimal setup'; Recommendation = @'
Security auditing is insufficiently configured. At a minimum, monitor failed login attempts, permission changes, role membership changes, and other security-relevant activities. Refer to established guidance for a comprehensive set of audit actions to ensure adequate visibility into security events.
'@.Trim(); ReferenceTitle = 'Recommendation for Security Auditing for databases – with example for Microsoft SQL Server'; ReferenceUrl = 'https://andreas-wolter.com/en/202507_recommended_security_auditing_databases_sql_server/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '069' = [pscustomobject]@{ CheckName = ''; Recommendation = @'

'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
}

$EmbeddedDetailsTemplateHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQL Server Security Assessment Community Edition</title>
<style>
body{font-family:Segoe UI, Arial, sans-serif;background:#f4f7f6;margin:40px;color:#333;}
.page{max-width:1200px;margin:0 auto;min-height:calc(100vh - 80px);display:flex;flex-direction:column;}

.report-header{margin-bottom:20px;padding:0;}
.title-block{display:flex;flex-direction:column;gap:4px;}
h1{margin:0;color:#2c3e50;font-size:2rem;line-height:1.1;}
.header-subtitle{font-size:.98rem;color:#6b7280;font-weight:500;}

.exec-header-box{display:flex;flex-direction:column;gap:14px;margin-bottom:20px;}
.meta-strip{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:10px;margin:0;width:100%}
.meta-box{background:#f8f9fb;border:1px solid #e7eaee;border-radius:10px;padding:10px 12px;min-width:0}
.meta-title{font-size:11px;text-transform:uppercase;color:#667085;margin-bottom:4px}
.meta-value{font-size:14px;font-weight:600;color:#1f2937;word-break:break-word;overflow-wrap:anywhere}

.visuals-panel,.controls,.detail-section{background:white;box-shadow:0 2px 5px rgba(0,0,0,0.1);}
.visuals-panel{margin-bottom:20px;padding:16px;page-break-inside:avoid;break-inside:avoid;}
.visuals-title{font-size:1rem;font-weight:700;color:#2c3e50;margin:0 0 14px 0;}

.chart-row{display:flex;align-items:flex-end;gap:14px;min-height:250px;}
.chart-bars{display:flex;align-items:flex-end;gap:18px;flex:1;min-height:220px;padding:10px 6px 0 6px;border-bottom:1px solid #d9e2ea;}
.chart-bar-wrap{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:8px;min-width:90px;flex:1;}
.chart-track{position:relative;width:100%;max-width:100px;height:160px;background:#eef2f6;border-radius:14px 14px 0 0;overflow:hidden;display:flex;align-items:flex-end;}
.chart-bar{position:relative;width:100%;min-height:8px;border-radius:14px 14px 0 0;}
.chart-bar-pct-inside{position:absolute;left:50%;top:8px;transform:translateX(-50%);font-size:.82rem;font-weight:700;line-height:1;color:#fff;white-space:nowrap;pointer-events:none;text-shadow:0 1px 1px rgba(0,0,0,.25);}
.chart-bar-pct-inside.dark-text{color:#212529;text-shadow:none;}
.chart-label{font-size:.85rem;color:#5b6b79;font-weight:700;text-align:center;letter-spacing:.02em;}
.chart-bar.outcome-PASS{background:#28a745;}
.chart-bar.outcome-OBSERVE{background:#0ea5e9;}
.chart-bar.outcome-WARNING{background:#ffc107;}
.chart-bar.outcome-FAIL{background:#dc3545;}

.controls{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:20px;padding:16px;}
.controls-left,.controls-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.controls-label{font-weight:600;color:#2c3e50;margin-right:2px;}
button{font:inherit;padding:10px 12px;border:1px solid #ccd3d9;border-radius:6px;background:#fff;cursor:pointer;}
button.disabled-btn{background:#e2e5e8;color:#777;border-color:#e2e5e8;cursor:not-allowed;}
.filter-btn{font-weight:600;}
.filter-btn.active{background:#2c3e50;color:#fff;border-color:#2c3e50;}

.detail-section{padding:18px;margin-bottom:20px;}
.compact-summary-table{width:100%;border-collapse:collapse;cursor:pointer;}
.compact-summary-table td{padding:10px;border:1px solid #ddd;background:#34495e;color:white;font-weight:bold;}
.summary-check-id{width:120px;white-space:nowrap;}
.summary-check-outcome{width:140px;text-align:center;}
.summary-check-name{position:relative;padding-right:40px !important;}
.summary-check-name::after{content:"\25BC";position:absolute;right:12px;top:50%;transform:translateY(-50%);}
.detail-section.open .summary-check-name::after{content:"\25B2";}
.detail-content{display:none;margin-top:15px;}
.detail-section.open .detail-content{display:block;}
.detail-table{border-collapse:collapse;width:100%;}
.detail-table th{background:#34495e;color:white;padding:8px;border:1px solid #ddd;text-align:left;}
.detail-table td{padding:8px;border:1px solid #ddd;}

.xml-expand summary{cursor:pointer;font-weight:600;color:#2c3e50;}
.xml-content{margin:8px 0 0 0;padding:10px;background:#f8f9fb;border:1px solid #e7eaee;border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;font-family:Consolas, Monaco, monospace;font-size:.85rem;}
.additional-info-cell{min-width:280px;}

.badge{padding:4px 8px;border-radius:4px;color:white;font-weight:bold;}
.outcome-PASS,.section-dot.outcome-PASS{background:#28a745;}
.outcome-OBSERVE,.section-dot.outcome-OBSERVE{background:#0ea5e9;}
.outcome-FAIL,.section-dot.outcome-FAIL{background:#dc3545;}
.outcome-WARNING,.section-dot.outcome-WARNING{background:#ffc107;color:#212529;}
.outcome-INFO,.section-dot.outcome-INFO{background:#17a2b8;}
.section-heading{margin:28px 0 10px;color:#2c3e50;border-bottom:2px solid #d9e2ea;padding-bottom:6px;}
.recommendation-panel{margin-top:14px;padding:14px 16px;background:#fafbfd;border-left:5px solid #ccd3d9;}
.recommendation-panel.outcome-FAIL{border-left-color:#dc3545;}
.recommendation-panel.outcome-WARNING{border-left-color:#ffc107;}
.recommendation-panel.outcome-INFO{border-left-color:#17a2b8;}
.recommendation-title{font-weight:700;color:#2c3e50;margin-bottom:6px;}
.recommendation-body{margin-bottom:6px;}
.empty-detail{color:#5b6b79;}
.hidden-by-filter{display:none !important;}

.report-footer{margin-top:auto;padding:14px 0 2px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;line-height:1.35;}
.report-footer-inner{display:grid;grid-template-columns:1fr auto 1fr;align-items:end;gap:14px;}
.footer-left,.footer-center,.footer-right{white-space:nowrap;}
.footer-center{text-align:center;}
.footer-right{text-align:right;}
.footer-logo{height:32px;vertical-align:middle;margin-right:8px;opacity:.75;}
.footer-muted{display:block;}

@media print {
    body{background:#fff;margin:20px 24px;}
    .page{min-height:auto;}
    .visuals-panel,.controls,.detail-section,.meta-box{box-shadow:none;}
    .visuals-panel{page-break-inside:avoid;break-inside:avoid;}
    .chart-bar,.chart-track,.footer-logo{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .report-footer{position:fixed;bottom:0;left:0;right:0;padding:10px 24px 2px;background:#fff;}
}

@media (max-width: 900px){
    .meta-strip{grid-template-columns:1fr 1fr;}
    .report-footer-inner{grid-template-columns:1fr;gap:6px;}
    .footer-left,.footer-center,.footer-right{text-align:left;white-space:normal;}
}
@media (max-width: 720px){
    .controls{flex-direction:column;align-items:stretch;}
    .controls-left,.controls-right{width:100%;}
    .chart-bars{gap:10px;}
    .chart-bar-wrap{min-width:64px;}
}
</style>
</head>
<body>
<div class="page">
<div class='report-header'>
    <div class='title-block'>
        <h1>SQL Server Security Assessment</h1>
        <div class='header-subtitle'>Scope: High-Level Security Indicators (Community Edition) | Release: {RELEASE_VERSION}</div>
    </div>
</div>

<div class='exec-header-box'>
    <div class='meta-strip'>
        <div class='meta-box'><div class='meta-title'>Core Security Controls</div><div class='meta-value'>{CHECK_COUNT}</div></div>
        <div class='meta-box'><div class='meta-title'>Sections Analyzed</div><div class='meta-value'>{SECTION_COUNT}</div></div>
        <div class='meta-box'><div class='meta-title'>Report Date</div><div class='meta-value'>{REPORT_DATE}</div></div>
        <div class='meta-box'><div class='meta-title'>Target Server</div><div class='meta-value'>{TARGET_SERVER}</div></div>
    </div>
</div>

<div class="visuals-panel">
    <div class="visuals-title">Outcome Distribution</div>
    <div class="chart-row">
        <div class="chart-bars">
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-PASS" id="bar-pass" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-pass-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">PASS (<span id="bar-pass-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-OBSERVE" id="bar-observe" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-observe-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">OBSERVE (<span id="bar-observe-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-WARNING" id="bar-warning" style="height:0%;">
                        <div class="chart-bar-pct-inside dark-text" id="bar-warning-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">WARNING (<span id="bar-warning-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-FAIL" id="bar-fail" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-fail-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">FAIL (<span id="bar-fail-value">0</span>)</div>
            </div>
        </div>
    </div>
</div>

<div class="controls detail-controls">
    <div class="controls-left">
        <div class="controls-label">Filter results by Outcome</div>
        <button class="filter-btn active" type="button" data-filter="ALL">All</button>
        <button class="filter-btn" type="button" data-filter="PASS">PASS</button>
        <button class="filter-btn" type="button" data-filter="OBSERVE">OBSERVE</button>
        <button class="filter-btn" type="button" data-filter="WARNING">WARNING</button>
        <button class="filter-btn" type="button" data-filter="FAIL">FAIL</button>
        <button class="filter-btn" type="button" data-filter="INFO">INFO</button>
    </div>
    <div class="controls-right">
        <button id="expandAll" type="button">Expand All</button>
        <button id="collapseAll" type="button" class="disabled-btn" disabled>Collapse All</button>
    </div>
</div>

<!--DETAIL_BODY-->

<div class="report-footer">
    <div class="report-footer-inner">
        <div class="footer-left">
            <img class="footer-logo" src="data:image/png;base64,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" alt="logo" />
            &#169; 2026 Sarpedon Quality Lab
            <span class="footer-muted">Community Edition</span>
        </div>
        <div class="footer-center">
            Logic &amp; Engine by <a href="https://www.andreas-wolter.com" target="_blank" rel="noopener noreferrer">Andreas Wolter</a> (MCSM)
            <span class="footer-muted">Version {RELEASE_VERSION}</span>
        </div>
        <div class="footer-right">
            Documentation &amp; Resources:
            <span class="footer-muted"><a href="https://www.SarpedonQualityLab.US/resources" target="_blank" rel="noopener noreferrer">SarpedonQualityLab.US/resources</a></span>
        </div>
    </div>
</div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function(){
const sections = Array.from(document.querySelectorAll('.detail-section'));
const filterButtons = Array.from(document.querySelectorAll('.filter-btn'));
const expandBtn = document.getElementById('expandAll');
const collapseBtn = document.getElementById('collapseAll');
let activeOutcome = 'ALL';

function setExpanded(section, val){ if(!section) return; if(val) section.classList.add('open'); else section.classList.remove('open'); }
function getOutcome(section){ const badge = section.querySelector('.summary-check-outcome .badge'); return badge ? badge.textContent.trim().toUpperCase() : ''; }
function visibleSections(){ return sections.filter(s => !s.classList.contains('hidden-by-filter')); }

function updateButtons(){
    const visible = visibleSections();
    const anyVisibleOpen = visible.some(s => s.classList.contains('open'));
    if (expandBtn) {
        expandBtn.disabled = visible.length === 0 || anyVisibleOpen;
        expandBtn.classList.toggle('disabled-btn', expandBtn.disabled);
    }
    if (collapseBtn) {
        collapseBtn.disabled = visible.length === 0 || !anyVisibleOpen;
        collapseBtn.classList.toggle('disabled-btn', collapseBtn.disabled);
    }
}

function pct(count, total){
    if (!total) return '0%';
    return Math.round((count / total) * 100) + '%';
}

function setText(id, value){
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setBar(id, count, maxCount){
    const el = document.getElementById(id);
    if (!el) return;
    const height = maxCount > 0 ? Math.max(8, Math.round((count / maxCount) * 100)) : 0;
    el.style.height = (count > 0 ? height : 0) + '%';
}

function updateVisuals(){
    const order = ['PASS','OBSERVE','WARNING','FAIL'];
    const counts = {PASS:0, OBSERVE:0, WARNING:0, FAIL:0};
    sections.forEach(section => {
        const outcome = getOutcome(section);
        if (counts.hasOwnProperty(outcome)) counts[outcome] += 1;
    });
    const total = order.reduce((a, k) => a + counts[k], 0);
    const maxCount = Math.max(0, ...order.map(k => counts[k]));

    setText('bar-pass-value', counts.PASS);
    setText('bar-observe-value', counts.OBSERVE);
    setText('bar-warning-value', counts.WARNING);
    setText('bar-fail-value', counts.FAIL);

    setText('bar-pass-pct', pct(counts.PASS, total));
    setText('bar-observe-pct', pct(counts.OBSERVE, total));
    setText('bar-warning-pct', pct(counts.WARNING, total));
    setText('bar-fail-pct', pct(counts.FAIL, total));

    setBar('bar-pass', counts.PASS, maxCount);
    setBar('bar-observe', counts.OBSERVE, maxCount);
    setBar('bar-warning', counts.WARNING, maxCount);
    setBar('bar-fail', counts.FAIL, maxCount);
}

function applyFilters(){
    sections.forEach(section => {
        const oc = getOutcome(section);
        const show = activeOutcome === 'ALL' || oc === activeOutcome;
        section.classList.toggle('hidden-by-filter', !show);
    });
    updateButtons();
}

sections.forEach(section => {
    const summary = section.querySelector('.compact-summary-table');
    if (summary) {
        summary.addEventListener('click', function(){
            section.classList.toggle('open');
            updateButtons();
        });
    }
});

filterButtons.forEach(btn => {
    btn.addEventListener('click', function(){
        activeOutcome = (btn.getAttribute('data-filter') || 'ALL').toUpperCase();
        filterButtons.forEach(b => b.classList.toggle('active', b === btn));
        applyFilters();
    });
});

if (expandBtn) {
    expandBtn.addEventListener('click', function(){
        visibleSections().forEach(section => setExpanded(section, true));
        updateButtons();
    });
}

if (collapseBtn) {
    collapseBtn.addEventListener('click', function(){
        sections.forEach(section => setExpanded(section, false));
        updateButtons();
    });
}

updateVisuals();
applyFilters();
updateButtons();
});
</script>
</body>
</html>

'@

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Data

# --- EARLY SQL FILE VALIDATION ---
$ExpectedSqlFileName = 'SqlSafe_202601.sql'
$ExpectedSqlHash = '273918b1d86395be3bae0c100832bbe34f309bdec84f7c59e9c30af775656f8f'

if ([System.IO.Path]::GetFileName($SqlFilePath) -ne $ExpectedSqlFileName) {
    [System.Windows.MessageBox]::Show(
        "Unexpected SQL file name detected. Only the original SqlSafe_202601.sql file is permitted. Execution has been stopped.",
        "SQL Security Assessment",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
    return
}

try {
    $ActualSqlHash = (Get-FileHash -Path $SqlFilePath -Algorithm SHA256 -ErrorAction Stop).Hash
}
catch {
    [System.Windows.MessageBox]::Show(
        ("Failed to validate the SQL script file.`n`n{0}" -f $_.Exception.Message),
        "SQL Security Assessment",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
    return
}

if ($ActualSqlHash -ne $ExpectedSqlHash) {
    [System.Windows.MessageBox]::Show(
        "The SQL script SqlSafe_202601.sql has been modified or replaced. Execution has been stopped. For security reasons, only the original, unmodified version of the security check script may be used.",
        "SQL Security Assessment",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
    return
}

# --- EXECUTION ---
# --- EMBEDDED DATA (integrated) ---
$AllowedCheckIds = @(
    '802'
    '806'
    '002'
    '003'
    '004'
    '028'
    '031'
    '034'
    '036'
    '038'
    '050'
    '072'
    '078'
    '123'
    '129'
    '155'
    '015'
    '026'
    '027'
    '008'
    '010'
    '079'
    '113'
    '046'
    '059'
    '069'
)
$AllowedCheckIdLookup = @{}
foreach ($id in $AllowedCheckIds) { $AllowedCheckIdLookup[$id] = $true }

$Catalog = @(
    [pscustomobject]@{ 'Check ID' = '002'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '003'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '004'; SectionID = '6'; Section = 'Communication Security' },
    [pscustomobject]@{ 'Check ID' = '008'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '010'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '015'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '026'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '027'; SectionID = '10'; Section = 'Server Privileges Analysis for EoP Risks' },
    [pscustomobject]@{ 'Check ID' = '028'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '031'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '034'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '036'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '038'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '046'; SectionID = '13'; Section = 'Account dependencies and orphaned accounts' },
    [pscustomobject]@{ 'Check ID' = '050'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '059'; SectionID = '15'; Section = 'Basic Security Audit Configuration Review' },
    [pscustomobject]@{ 'Check ID' = '069'; SectionID = '15'; Section = 'Basic Security Audit Configuration Review' },
    [pscustomobject]@{ 'Check ID' = '072'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '078'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '079'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '113'; SectionID = '12'; Section = 'SQL Server and Database Accounts security' },
    [pscustomobject]@{ 'Check ID' = '123'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '129'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '155'; SectionID = '7'; Section = 'SQL Server Configuration Security' },
    [pscustomobject]@{ 'Check ID' = '802'; SectionID = '0'; Section = 'Information' },
    [pscustomobject]@{ 'Check ID' = '806'; SectionID = '0'; Section = 'Information' }
)

$Rules = [ordered]@{
    '002' = @{ Method = 'column_equals'; Column = 'Result2'; ExpectedValue = 0; Severity = 'OBSERVE' } # Authentication mode
    '003' = @{ Method = 'threshold_max'; Column = 'Result2'; Limit = 10; Severity = 'FAIL' } # SQL Authentication usage
    '004' = @{ Method = 'threshold_max'; Column = 'Result2'; Limit = 10; Severity = 'FAIL' } # NTLM Authentication usage
    '008' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # SA Login Name
    '010' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Sysadmin-members individual accounts
    '015' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Powerful server role membership
    '026' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Server permissions granted to Logins
    '027' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Custom server roles without members
    '028' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Databases with Trustworthy property set
    '031' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # cross db ownership chaining setting
    '034' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # XP_cmdshell setting
    '036' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Ad hoc distributed queries setting
    '038' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # OLE Automation Procedures setting
    '046' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Orphaned Windows Logins
    '050' = @{ Method = 'threshold_min'; Column = 'Number'; Limit = 30; Severity = 'WARNING' } # Number of ErrorLogs kept
    '059' = @{ Method = 'rows_exist'; Severity = 'FAIL' } # Security Auditing minimal setup
    '079' = @{ Method = 'static'; Severity = 'INFO' } # SA Login State
    '113' = @{ Method = 'rows_exist'; Severity = 'OBSERVE' } # Custom database roles without members
    '123' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # DBs with AUTO_CLOSE setting on
	'129' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # Orphaned Database Users
    '802' = @{ Method = 'static'; Severity = 'INFO' } # Contained AGs present
    '806' = @{ Method = 'rows_exist'; Severity = 'WARNING' } # outstanding configuration changes
}

$RecommendationLookup = @{
    '802' = [pscustomobject]@{ CheckName = 'Contained AGs present'; Recommendation = @'
If contained availability groups are present, review the security and operational implications carefully, including identity handling to ensure that the Contained Availability Group is monitored and secured at the same level as the host.
'@.Trim(); ReferenceTitle = 'Why you should use SQL Server contained availability groups to save time – and why consultants may not tell you about them'; ReferenceUrl = 'https://andreas-wolter.com/en/2504_sqlserver_contained_availability_groups/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '806' = [pscustomobject]@{ CheckName = 'outstanding configuration changes'; Recommendation = @'
There are outstanding configuration changes pending. This means that some settings will only take effect after a server restart or after executing the RECONFIGURE statement. Ensure that you understand which settings will change and validate their impact before they are applied.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '002' = [pscustomobject]@{ CheckName = 'Authentication mode'; Recommendation = @'
SQL Authentication increases the attack surface because credentials must be stored, transmitted, and managed separately from the operating system. Whenever possible, prefer Windows Authentication, which integrates with Active Directory and supports centralized identity management, password policies, and stronger authentication mechanisms. If applications currently require SQL Authentication, work with the application vendor to enable support for Windows Authentication or modern identity solutions. Where SQL logins must remain in use, enforce strong password policies, disable unused accounts, and regularly monitor login activity.
'@.Trim(); ReferenceTitle = 'Choose an authentication mode'; ReferenceUrl = 'https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '003' = [pscustomobject]@{ CheckName = 'SQL Authentication usage'; Recommendation = @'
SQL Authentication increases the attack surface because credentials must be stored, transmitted, and managed separately from the operating system. Whenever possible, prefer Windows Authentication, which integrates with Active Directory and supports centralized identity management, password policies, and stronger authentication mechanisms. If applications currently require SQL Authentication, work with the application vendor to enable support for Windows Authentication or modern identity solutions. Where SQL logins must remain in use, enforce strong password policies, disable unused accounts, and regularly monitor login activity.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '004' = [pscustomobject]@{ CheckName = 'NTLM Authentication usage'; Recommendation = @'
More than 10% of observed connections are still using NTLM. NTLM is on a deprecation path and provides weaker security compared to modern alternatives such as Kerberos. Reduce and phase out NTLM wherever possible by identifying affected clients and migrating them to Kerberos-based authentication.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '028' = [pscustomobject]@{ CheckName = 'Databases with Trustworthy property set'; Recommendation = @'
The assessment identified databases with the TRUSTWORTHY property set to ON. This setting represents a significant security risk and is commonly classified as a high-severity finding. When a database is marked as TRUSTWORTHY, SQL Server implicitly trusts its contents, which can enable privilege escalation and unauthorized access to server-level resources. Determine the technical reason for this configuration and evaluate safer alternatives, such as module signing (code signing), to achieve the same functionality without relying on TRUSTWORTHY.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = 'TRUSTWORTHY database property'; ReferenceUrl2 = 'https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17' }
    '031' = [pscustomobject]@{ CheckName = 'cross db ownership chaining setting'; Recommendation = @'
The server-level cross-database ownership chaining setting is enabled. This configuration affects all databases on the instance and should be avoided, as it weakens isolation boundaries and enables privilege escalation with relatively little effort. If cross-database access is required, use the database-level setting only for specific databases that explicitly require it, and ensure the configuration is tightly controlled and well documented.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '034' = [pscustomobject]@{ CheckName = 'XP_cmdshell setting'; Recommendation = @'
xp_cmdshell can be abused for command execution and lateral movement and should only be enabled temporarily when absolutely necessary. Disable it by default and document any approved exception with compensating controls.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '036' = [pscustomobject]@{ CheckName = 'Ad hoc distributed queries setting'; Recommendation = @'
The Ad Hoc Distributed Queries setting allows users to access external data sources directly using functions such as OPENROWSET and OPENDATASOURCE. This increases the attack surface by enabling arbitrary connections to external systems, which can lead to unauthorized data access, data exfiltration, or execution of unintended queries—especially when combined with elevated permissions. Disable Ad Hoc Distributed Queries unless there is a clear and documented technical requirement. Where external data access is necessary, prefer controlled mechanisms such as linked servers with explicitly defined security contexts. Due to the increased risk, consider isolating databases that require this setting on a dedicated SQL Server instance.he Ad Hoc Distributed Queries setting allows users to access external data sources directly using functions such as OPENROWSET and OPENDATASOURCE, significantly increasing the attack surface. It enables arbitrary connections to external or untrusted systems, facilitates data exfiltration, and may allow privilege escalation or code execution through vulnerable OLE DB providers under the SQL Server service account. In the event of compromise, it can also be used as a pivot point to access other systems on the network. Where external access is needed, prefer controlled mechanisms such as linked servers with defined security contexts. Disable this setting unless there is a clear and documented technical requirement. Due to the increased risk, consider isolating databases that require this setting on a dedicated SQL Server instance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '038' = [pscustomobject]@{ CheckName = 'OLE Automation Procedures setting'; Recommendation = @'
The OLE Automation Procedures setting allows Transact-SQL code to instantiate COM objects and interact with external Windows components. Enabling this feature represents a significant security risk, as it can be used by an attacker with database access to execute arbitrary commands, modify the registry, or read and write files—effectively bypassing standard SQL Server security boundaries and enabling privilege escalation under the SQL Server service account. Disable OLE Automation Procedures unless there is a strict and documented requirement. Where external interaction is needed, prefer safer alternatives such as SQL Server Agent jobs, CLR integration with strict permission sets, or application-layer logic outside the database. Ensure any required functionality is implemented using controlled, auditable mechanisms rather than direct OS-level access from within SQL Server.
'@.Trim(); ReferenceTitle = 'OLE Automation stored procedures (Transact-SQL)'; ReferenceUrl = 'https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/ole-automation-stored-procedures-transact-sql?view=sql-server-ver17'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '050' = [pscustomobject]@{ CheckName = 'Number of ErrorLogs kept'; Recommendation = @'
Fewer than 30 SQL Server error logs are being retained. Increase the setting to 90 to improve the available history for security investigations, troubleshooting, and forensic review. In practice, there is no downside for having one ErrorLog per day with 90 days history.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '072' = [pscustomobject]@{ CheckName = 'Database Owner sysadmin'; Recommendation = @'
ome databases are owned by logins with sysadmin privileges. This can be abused by users with elevated permissions within the database to escalate privileges to the server level and should therefore be avoided. Use a dedicated, low-privileged login as the database owner instead. If using sa as a consistently available owner, ensure the associated risks are fully understood—especially in combination with settings such as TRUSTWORTHY or features that execute code as the database owner.
'@.Trim(); ReferenceTitle = 'SQL Server Database Ownership: survey results & recommendations'; ReferenceUrl = 'https://andreas-wolter.com/en/sql-server-database-ownership-survey-results-recommendations/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '078' = [pscustomobject]@{ CheckName = 'Database Owner Windows account'; Recommendation = @'
Some databases are owned by Windows accounts. This can cause issues after restores to different servers or if the associated login is removed, and it often indicates weaknesses in database deployment processes. Ensure that all databases are owned by a consistently available account on every server.
'@.Trim(); ReferenceTitle = 'SQL Server Database Ownership: survey results & recommendations'; ReferenceUrl = 'https://andreas-wolter.com/en/sql-server-database-ownership-survey-results-recommendations/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '123' = [pscustomobject]@{ CheckName = 'DBs with AUTO_CLOSE setting on'; Recommendation = @'
The assessment identified databases with AUTO_CLOSE enabled. This setting can negatively impact performance by causing frequent resource initialization and may contribute to instability or enable denial-of-service scenarios. It should not be used on server systems and is only appropriate for limited use cases such as single-user or desktop environments.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '129' = [pscustomobject]@{ CheckName = 'Orphaned Database Users'; Recommendation = @'
The assessment identified orphaned database users without a corresponding login. Review and remove or remap these users to reduce administrative overhead and prevent confusion or unintended permission issues. Orphaned users can also introduce risks such as privilege takeover and non-repudiation by misusing their identities.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '155' = [pscustomobject]@{ CheckName = 'Database Owner not valid'; Recommendation = @'
Some databases do no have a valid owner-match between master and th database itself. This can happen Some databases do not have a valid owner mapping between the metadata in master and the user database. This can occur after a restore when the original owner login does not exist on the target system, or when the owner login has been removed. Such mismatches can lead to unexpected behavior or code execution issues. Ensure that every database has a valid and existing owner. The owner can be set in SSMS under Database - Properties - Files, or by using the ALTER AUTHORIZATION statement.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '015' = [pscustomobject]@{ CheckName = 'Powerful server role membership'; Recommendation = @'
Individual user accounts were found assigned to powerful server roles. Avoid assigning such privileges directly to personal accounts. Instead, use centrally managed Windows groups to reduce the risk of orphaned logins and improve access governance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '026' = [pscustomobject]@{ CheckName = 'Server permissions granted to Logins'; Recommendation = @'
The assessment identified individual accounts with server-level permissions. Avoid assigning such permissions directly to personal accounts. Instead, use centrally managed Windows groups to improve governance, simplify access control, and reduce the risk of orphaned logins.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '027' = [pscustomobject]@{ CheckName = 'Custom server roles without members'; Recommendation = @'
The assessment identified custom server roles without any members. Review these roles and remove those that are no longer required to reduce clutter and maintain a clear and manageable security model.
'@.Trim(); ReferenceTitle = 'The SQL Server Database Application Security & High Availability Checklist by Sarpedon Quality Lab – Version 2'; ReferenceUrl = 'https://andreas-wolter.com/en/2026_sqlserverdatabaseapplicationsecurityandhighavailabilitychecklist_v2/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '008' = [pscustomobject]@{ CheckName = 'SA Login Name'; Recommendation = @'
Review the protection strategy for the built-in sa account carefully. Prioritize auditing both successful and failed logon attempts to detect misuse or attack activity early. Ensure all login attempts are logged, regularly reviewed, and integrated with centralized monitoring or alerting. Restrict direct use of sa to exceptional, well-justified cases and tightly control password exposure.
'@.Trim(); ReferenceTitle = 'To rename or not, that is the question – how to protect SQL Server’s built-in sysadmin account sa'; ReferenceUrl = 'https://andreas-wolter.com/en/202512_renaming-sql-servers-sa-account/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '010' = [pscustomobject]@{ CheckName = 'Sysadmin-members individual accounts'; Recommendation = @'
The assessment identified individual user accounts with sysadmin membership. Limit sysadmin privileges to tightly controlled administrative Windows groups managed in Active Directory, rather than assigning them directly to individual accounts.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '079' = [pscustomobject]@{ CheckName = 'SA Login State'; Recommendation = @'
Disabling the sa account is not a universal best practice and should not be relied upon as a primary security control, as it can lead to unexpected issues during patching or due to script and application dependencies. Instead, ensure that auditing of failed login attempts—especially targeting sa—is properly configured and regularly reviewed to detect brute-force and unauthorized access attempts.
'@.Trim(); ReferenceTitle = 'To rename or not, that is the question – how to protect SQL Server’s built-in sysadmin account sa'; ReferenceUrl = 'https://andreas-wolter.com/en/202512_renaming-sql-servers-sa-account/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '113' = [pscustomobject]@{ CheckName = 'Custom database roles without members'; Recommendation = @'
The assessment found custom database roles without members. Review whether these roles are still needed and remove obsolete roles to keep the permission model understandable and clutter-free.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '046' = [pscustomobject]@{ CheckName = 'Orphaned Windows Logins'; Recommendation = @'
The assessment found orphaned Windows logins that no longer exist in Active Directory. Review and remove them to reduce stale access paths and simplify access governance.
'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '059' = [pscustomobject]@{ CheckName = 'Security Auditing minimal setup'; Recommendation = @'
Security auditing is insufficiently configured. At a minimum, monitor failed login attempts, permission changes, role membership changes, and other security-relevant activities. Refer to established guidance for a comprehensive set of audit actions to ensure adequate visibility into security events.
'@.Trim(); ReferenceTitle = 'Recommendation for Security Auditing for databases – with example for Microsoft SQL Server'; ReferenceUrl = 'https://andreas-wolter.com/en/202507_recommended_security_auditing_databases_sql_server/'; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
    '069' = [pscustomobject]@{ CheckName = ''; Recommendation = @'

'@.Trim(); ReferenceTitle = ''; ReferenceUrl = ''; ReferenceTitle2 = ''; ReferenceUrl2 = '' }
}

$EmbeddedDetailsTemplateHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SQL Server Security Assessment Community Edition</title>
<style>
body{font-family:Segoe UI, Arial, sans-serif;background:#f4f7f6;margin:40px;color:#333;}
.page{max-width:1200px;margin:0 auto;min-height:calc(100vh - 80px);display:flex;flex-direction:column;}

.report-header{margin-bottom:20px;padding:0;}
.title-block{display:flex;flex-direction:column;gap:4px;}
h1{margin:0;color:#2c3e50;font-size:2rem;line-height:1.1;}
.header-subtitle{font-size:.98rem;color:#6b7280;font-weight:500;}

.exec-header-box{display:flex;flex-direction:column;gap:14px;margin-bottom:20px;}
.meta-strip{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:10px;margin:0;width:100%}
.meta-box{background:#f8f9fb;border:1px solid #e7eaee;border-radius:10px;padding:10px 12px;min-width:0}
.meta-title{font-size:11px;text-transform:uppercase;color:#667085;margin-bottom:4px}
.meta-value{font-size:14px;font-weight:600;color:#1f2937;word-break:break-word;overflow-wrap:anywhere}

.visuals-panel,.controls,.detail-section{background:white;box-shadow:0 2px 5px rgba(0,0,0,0.1);}
.visuals-panel{margin-bottom:20px;padding:16px;page-break-inside:avoid;break-inside:avoid;}
.visuals-title{font-size:1rem;font-weight:700;color:#2c3e50;margin:0 0 14px 0;}

.chart-row{display:flex;align-items:flex-end;gap:14px;min-height:250px;}
.chart-bars{display:flex;align-items:flex-end;gap:18px;flex:1;min-height:220px;padding:10px 6px 0 6px;border-bottom:1px solid #d9e2ea;}
.chart-bar-wrap{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:8px;min-width:90px;flex:1;}
.chart-track{position:relative;width:100%;max-width:100px;height:160px;background:#eef2f6;border-radius:14px 14px 0 0;overflow:hidden;display:flex;align-items:flex-end;}
.chart-bar{position:relative;width:100%;min-height:8px;border-radius:14px 14px 0 0;}
.chart-bar-pct-inside{position:absolute;left:50%;top:8px;transform:translateX(-50%);font-size:.82rem;font-weight:700;line-height:1;color:#fff;white-space:nowrap;pointer-events:none;text-shadow:0 1px 1px rgba(0,0,0,.25);}
.chart-bar-pct-inside.dark-text{color:#212529;text-shadow:none;}
.chart-label{font-size:.85rem;color:#5b6b79;font-weight:700;text-align:center;letter-spacing:.02em;}
.chart-bar.outcome-PASS{background:#28a745;}
.chart-bar.outcome-OBSERVE{background:#0ea5e9;}
.chart-bar.outcome-WARNING{background:#ffc107;}
.chart-bar.outcome-FAIL{background:#dc3545;}

.controls{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-bottom:20px;padding:16px;}
.controls-left,.controls-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.controls-label{font-weight:600;color:#2c3e50;margin-right:2px;}
button{font:inherit;padding:10px 12px;border:1px solid #ccd3d9;border-radius:6px;background:#fff;cursor:pointer;}
button.disabled-btn{background:#e2e5e8;color:#777;border-color:#e2e5e8;cursor:not-allowed;}
.filter-btn{font-weight:600;}
.filter-btn.active{background:#2c3e50;color:#fff;border-color:#2c3e50;}

.detail-section{padding:18px;margin-bottom:20px;}
.compact-summary-table{width:100%;border-collapse:collapse;cursor:pointer;}
.compact-summary-table td{padding:10px;border:1px solid #ddd;background:#34495e;color:white;font-weight:bold;}
.summary-check-id{width:120px;white-space:nowrap;}
.summary-check-outcome{width:140px;text-align:center;}
.summary-check-name{position:relative;padding-right:40px !important;}
.summary-check-name::after{content:"\25BC";position:absolute;right:12px;top:50%;transform:translateY(-50%);}
.detail-section.open .summary-check-name::after{content:"\25B2";}
.detail-content{display:none;margin-top:15px;}
.detail-section.open .detail-content{display:block;}
.detail-table{border-collapse:collapse;width:100%;}
.detail-table th{background:#34495e;color:white;padding:8px;border:1px solid #ddd;text-align:left;}
.detail-table td{padding:8px;border:1px solid #ddd;}

.xml-expand summary{cursor:pointer;font-weight:600;color:#2c3e50;}
.xml-content{margin:8px 0 0 0;padding:10px;background:#f8f9fb;border:1px solid #e7eaee;border-radius:6px;white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;font-family:Consolas, Monaco, monospace;font-size:.85rem;}
.additional-info-cell{min-width:280px;}

.badge{padding:4px 8px;border-radius:4px;color:white;font-weight:bold;}
.outcome-PASS,.section-dot.outcome-PASS{background:#28a745;}
.outcome-OBSERVE,.section-dot.outcome-OBSERVE{background:#0ea5e9;}
.outcome-FAIL,.section-dot.outcome-FAIL{background:#dc3545;}
.outcome-WARNING,.section-dot.outcome-WARNING{background:#ffc107;color:#212529;}
.outcome-INFO,.section-dot.outcome-INFO{background:#17a2b8;}
.section-heading{margin:28px 0 10px;color:#2c3e50;border-bottom:2px solid #d9e2ea;padding-bottom:6px;}
.recommendation-panel{margin-top:14px;padding:14px 16px;background:#fafbfd;border-left:5px solid #ccd3d9;}
.recommendation-panel.outcome-FAIL{border-left-color:#dc3545;}
.recommendation-panel.outcome-WARNING{border-left-color:#ffc107;}
.recommendation-panel.outcome-INFO{border-left-color:#17a2b8;}
.recommendation-title{font-weight:700;color:#2c3e50;margin-bottom:6px;}
.recommendation-body{margin-bottom:6px;}
.empty-detail{color:#5b6b79;}
.hidden-by-filter{display:none !important;}

.report-footer{margin-top:auto;padding:14px 0 2px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:11px;line-height:1.35;}
.report-footer-inner{display:grid;grid-template-columns:1fr auto 1fr;align-items:end;gap:14px;}
.footer-left,.footer-center,.footer-right{white-space:nowrap;}
.footer-center{text-align:center;}
.footer-right{text-align:right;}
.footer-logo{height:32px;vertical-align:middle;margin-right:8px;opacity:.75;}
.footer-muted{display:block;}

@media print {
    body{background:#fff;margin:20px 24px;}
    .page{min-height:auto;}
    .visuals-panel,.controls,.detail-section,.meta-box{box-shadow:none;}
    .visuals-panel{page-break-inside:avoid;break-inside:avoid;}
    .chart-bar,.chart-track,.footer-logo{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .report-footer{position:fixed;bottom:0;left:0;right:0;padding:10px 24px 2px;background:#fff;}
}

@media (max-width: 900px){
    .meta-strip{grid-template-columns:1fr 1fr;}
    .report-footer-inner{grid-template-columns:1fr;gap:6px;}
    .footer-left,.footer-center,.footer-right{text-align:left;white-space:normal;}
}
@media (max-width: 720px){
    .controls{flex-direction:column;align-items:stretch;}
    .controls-left,.controls-right{width:100%;}
    .chart-bars{gap:10px;}
    .chart-bar-wrap{min-width:64px;}
}
</style>
</head>
<body>
<div class="page">
<div class='report-header'>
    <div class='title-block'>
        <h1>SQL Server Security Assessment</h1>
        <div class='header-subtitle'>Scope: High-Level Security Indicators (Community Edition) | Release: {RELEASE_VERSION}</div>
    </div>
</div>

<div class='exec-header-box'>
    <div class='meta-strip'>
        <div class='meta-box'><div class='meta-title'>Core Security Controls</div><div class='meta-value'>{CHECK_COUNT}</div></div>
        <div class='meta-box'><div class='meta-title'>Sections Analyzed</div><div class='meta-value'>{SECTION_COUNT}</div></div>
        <div class='meta-box'><div class='meta-title'>Report Date</div><div class='meta-value'>{REPORT_DATE}</div></div>
        <div class='meta-box'><div class='meta-title'>Target Server</div><div class='meta-value'>{TARGET_SERVER}</div></div>
    </div>
</div>

<div class="visuals-panel">
    <div class="visuals-title">Outcome Distribution</div>
    <div class="chart-row">
        <div class="chart-bars">
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-PASS" id="bar-pass" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-pass-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">PASS (<span id="bar-pass-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-OBSERVE" id="bar-observe" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-observe-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">OBSERVE (<span id="bar-observe-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-WARNING" id="bar-warning" style="height:0%;">
                        <div class="chart-bar-pct-inside dark-text" id="bar-warning-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">WARNING (<span id="bar-warning-value">0</span>)</div>
            </div>
            <div class="chart-bar-wrap">
                <div class="chart-track">
                    <div class="chart-bar outcome-FAIL" id="bar-fail" style="height:0%;">
                        <div class="chart-bar-pct-inside" id="bar-fail-pct">0%</div>
                    </div>
                </div>
                <div class="chart-label">FAIL (<span id="bar-fail-value">0</span>)</div>
            </div>
        </div>
    </div>
</div>

<div class="controls detail-controls">
    <div class="controls-left">
        <div class="controls-label">Filter results by Outcome</div>
        <button class="filter-btn active" type="button" data-filter="ALL">All</button>
        <button class="filter-btn" type="button" data-filter="PASS">PASS</button>
        <button class="filter-btn" type="button" data-filter="OBSERVE">OBSERVE</button>
        <button class="filter-btn" type="button" data-filter="WARNING">WARNING</button>
        <button class="filter-btn" type="button" data-filter="FAIL">FAIL</button>
        <button class="filter-btn" type="button" data-filter="INFO">INFO</button>
    </div>
    <div class="controls-right">
        <button id="expandAll" type="button">Expand All</button>
        <button id="collapseAll" type="button" class="disabled-btn" disabled>Collapse All</button>
    </div>
</div>

<!--DETAIL_BODY-->

<div class="report-footer">
    <div class="report-footer-inner">
        <div class="footer-left">
            <img class="footer-logo" src="data:image/png;base64,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" alt="logo" />
            &#169; 2026 Sarpedon Quality Lab
            <span class="footer-muted">Community Edition</span>
        </div>
        <div class="footer-center">
            Logic &amp; Engine by <a href="https://www.andreas-wolter.com" target="_blank" rel="noopener noreferrer">Andreas Wolter</a> (MCSM)
            <span class="footer-muted">Version {RELEASE_VERSION}</span>
        </div>
        <div class="footer-right">
            Documentation &amp; Resources:
            <span class="footer-muted"><a href="https://www.SarpedonQualityLab.US/resources" target="_blank" rel="noopener noreferrer">SarpedonQualityLab.US/resources</a></span>
        </div>
    </div>
</div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function(){
const sections = Array.from(document.querySelectorAll('.detail-section'));
const filterButtons = Array.from(document.querySelectorAll('.filter-btn'));
const expandBtn = document.getElementById('expandAll');
const collapseBtn = document.getElementById('collapseAll');
let activeOutcome = 'ALL';

function setExpanded(section, val){ if(!section) return; if(val) section.classList.add('open'); else section.classList.remove('open'); }
function getOutcome(section){ const badge = section.querySelector('.summary-check-outcome .badge'); return badge ? badge.textContent.trim().toUpperCase() : ''; }
function visibleSections(){ return sections.filter(s => !s.classList.contains('hidden-by-filter')); }

function updateButtons(){
    const visible = visibleSections();
    const anyVisibleOpen = visible.some(s => s.classList.contains('open'));
    if (expandBtn) {
        expandBtn.disabled = visible.length === 0 || anyVisibleOpen;
        expandBtn.classList.toggle('disabled-btn', expandBtn.disabled);
    }
    if (collapseBtn) {
        collapseBtn.disabled = visible.length === 0 || !anyVisibleOpen;
        collapseBtn.classList.toggle('disabled-btn', collapseBtn.disabled);
    }
}

function pct(count, total){
    if (!total) return '0%';
    return Math.round((count / total) * 100) + '%';
}

function setText(id, value){
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setBar(id, count, maxCount){
    const el = document.getElementById(id);
    if (!el) return;
    const height = maxCount > 0 ? Math.max(8, Math.round((count / maxCount) * 100)) : 0;
    el.style.height = (count > 0 ? height : 0) + '%';
}

function updateVisuals(){
    const order = ['PASS','OBSERVE','WARNING','FAIL'];
    const counts = {PASS:0, OBSERVE:0, WARNING:0, FAIL:0};
    sections.forEach(section => {
        const outcome = getOutcome(section);
        if (counts.hasOwnProperty(outcome)) counts[outcome] += 1;
    });
    const total = order.reduce((a, k) => a + counts[k], 0);
    const maxCount = Math.max(0, ...order.map(k => counts[k]));

    setText('bar-pass-value', counts.PASS);
    setText('bar-observe-value', counts.OBSERVE);
    setText('bar-warning-value', counts.WARNING);
    setText('bar-fail-value', counts.FAIL);

    setText('bar-pass-pct', pct(counts.PASS, total));
    setText('bar-observe-pct', pct(counts.OBSERVE, total));
    setText('bar-warning-pct', pct(counts.WARNING, total));
    setText('bar-fail-pct', pct(counts.FAIL, total));

    setBar('bar-pass', counts.PASS, maxCount);
    setBar('bar-observe', counts.OBSERVE, maxCount);
    setBar('bar-warning', counts.WARNING, maxCount);
    setBar('bar-fail', counts.FAIL, maxCount);
}

function applyFilters(){
    sections.forEach(section => {
        const oc = getOutcome(section);
        const show = activeOutcome === 'ALL' || oc === activeOutcome;
        section.classList.toggle('hidden-by-filter', !show);
    });
    updateButtons();
}

sections.forEach(section => {
    const summary = section.querySelector('.compact-summary-table');
    if (summary) {
        summary.addEventListener('click', function(){
            section.classList.toggle('open');
            updateButtons();
        });
    }
});

filterButtons.forEach(btn => {
    btn.addEventListener('click', function(){
        activeOutcome = (btn.getAttribute('data-filter') || 'ALL').toUpperCase();
        filterButtons.forEach(b => b.classList.toggle('active', b === btn));
        applyFilters();
    });
});

if (expandBtn) {
    expandBtn.addEventListener('click', function(){
        visibleSections().forEach(section => setExpanded(section, true));
        updateButtons();
    });
}

if (collapseBtn) {
    collapseBtn.addEventListener('click', function(){
        sections.forEach(section => setExpanded(section, false));
        updateButtons();
    });
}

updateVisuals();
applyFilters();
updateButtons();
});
</script>
</body>
</html>

'@







# --- XAML for the modern logon dialog ---
[xml]$XAML = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SQL Security Assessment" Width="420" Height="320"
        WindowStartupLocation="CenterScreen" Background="#F4F7F6" ResizeMode="NoResize"
        SizeToContent="Height" MinWidth="420">
    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Margin="0,0,0,6">
            <TextBlock Text="Connect to SQL Server" FontSize="16" FontWeight="Bold" Foreground="#2C3E50" Margin="0,0,0,2"/>
            <Grid Margin="0,4,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Server:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                <TextBox Name="ServerInput" Grid.Column="1" Text="localhost" FontSize="13" Padding="4" Height="24" BorderBrush="#3498DB" BorderThickness="1.2"/>
            </Grid>
        </StackPanel>

        <StackPanel Grid.Row="1">
            <Grid Margin="0,2,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Authentication:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                <StackPanel Grid.Column="1" Orientation="Horizontal">
                    <RadioButton Name="WinAuth" Content="Windows Authentication" IsChecked="True" Margin="0,0,16,0" FontSize="11" VerticalAlignment="Center"/>
                    <RadioButton Name="SqlAuth" Content="SQL Server Authentication" FontSize="11" VerticalAlignment="Center"/>
                </StackPanel>
            </Grid>

            <Grid Margin="0,6,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Windows User:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                <TextBlock Name="WinUserLabel" Grid.Column="1" Text="" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
            </Grid>

            <Grid Margin="0,6,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Username:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                <TextBox Name="UsernameInput" Grid.Column="1" FontSize="13" Padding="4" Height="24" IsEnabled="False"/>
            </Grid>

            <Grid Margin="0,6,0,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="110"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <TextBlock Text="Password:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                <PasswordBox Name="PasswordInput" Grid.Column="1" FontSize="13" Padding="4" Height="24" Width="Auto" IsEnabled="False"/>
            </Grid>

            <Expander Name="AdvancedExpander" Header="Advanced" Margin="0,6,0,0" FontSize="11" ToolTip="Older SQL Server versions may not support modern encryption modes.">
                <Border Background="#FFFFFF" BorderBrush="#D6DBDF" BorderThickness="1" CornerRadius="4" Padding="8" Margin="0,6,0,0" MinWidth="360">
                    <StackPanel>
                        <Grid Margin="0,0,0,4">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="110"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="Encryption:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                            <ComboBox Name="EncryptOption" Grid.Column="1" SelectedIndex="1" FontSize="13" Height="24">
                                <ComboBoxItem Content="Mandatory" Tag="Mandatory"/>
                                <ComboBoxItem Content="Optional" Tag="Optional"/>
                                <ComboBoxItem Content="Strict (SQL Server 2022+ / Azure SQL)" Tag="Strict"/>
                            </ComboBox>
                        </Grid>
                        <TextBlock Text="Strict requires SQL Server 2022 (16.x) or Azure SQL and a newer SQL client driver." TextWrapping="Wrap" FontSize="10.5" Foreground="#7F8C8D" Margin="110,0,0,6"/>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="110"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="Certificate:" FontSize="11" Foreground="#7F8C8D" VerticalAlignment="Center"/>
                            <CheckBox Name="TrustCert" Grid.Column="1" Content="Trust server certificate" FontSize="11" VerticalAlignment="Center"/>
                        </Grid>
                    </StackPanel>
                </Border>
            </Expander>
        </StackPanel>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button Name="TestBtn" Content="Test Connection" Width="110" Height="26" Margin="0,0,6,0"/>
            <Button Name="CancelBtn" Content="Cancel" Width="80" Height="26" Margin="0,0,6,0" IsCancel="True"/>
            <Button Name="ConnectBtn" Content="Start Assessment" Width="100" Height="26" Background="#3498DB" Foreground="White" IsDefault="True"/>
        </StackPanel>
    </Grid>
</Window>
"@

# --- Load XAML ---
$Reader = New-Object System.Xml.XmlNodeReader($XAML)
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# --- Find controls ---
$ServerInput      = $Window.FindName('ServerInput')
$WinAuth          = $Window.FindName('WinAuth')
$SqlAuth          = $Window.FindName('SqlAuth')
$UsernameInput    = $Window.FindName('UsernameInput')
$PasswordInput    = $Window.FindName('PasswordInput')
$EncryptOption    = $Window.FindName('EncryptOption')
$TrustCert        = $Window.FindName('TrustCert')
$ConnectBtn       = $Window.FindName('ConnectBtn')
$CancelBtn        = $Window.FindName('CancelBtn')
$TestBtn          = $Window.FindName('TestBtn')
$WinUserLabel     = $Window.FindName('WinUserLabel')
# --- Show current Windows user for Windows Auth ---
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$WinUserLabel.Text = $CurrentUser

# --- Enable/Disable username/password based on auth selection ---
$WinAuth.Add_Checked({
    $UsernameInput.IsEnabled = $false
    $PasswordInput.IsEnabled = $false
    $UsernameInput.Text = ''
    $PasswordInput.Password = ''
    $WinUserLabel.Visibility = 'Visible'
})

$SqlAuth.Add_Checked({
    $UsernameInput.IsEnabled = $true
    $PasswordInput.IsEnabled = $true
    $WinUserLabel.Visibility = 'Collapsed'
})

# --- Keyboard polish / initial focus ---
$Window.Add_ContentRendered({
    $this.Topmost = $true
    $this.Activate()
    $ServerInput.Focus() | Out-Null
    $ServerInput.SelectAll()
    $this.Topmost = $false
})

# --- Button actions ---
$ConnectBtn.Add_Click({
    $dialogInput = Get-DialogInput -ServerInput $ServerInput -WinAuth $WinAuth -UsernameInput $UsernameInput -PasswordInput $PasswordInput -EncryptOption $EncryptOption -TrustCert $TrustCert
    $validationMessage = Validate-DialogInput -InputObject $dialogInput -ForConnect

    if ($validationMessage) {
        Show-UiMessage -Message $validationMessage -Kind Warning
        return
    }

    $script:SqlServer     = $dialogInput.SqlServer
    $script:AuthMethod    = $dialogInput.AuthMethod
    $script:Username      = $dialogInput.Username
    $script:Password      = $dialogInput.Password
    $script:EncryptOption = $dialogInput.EncryptOption
    $script:TrustCert     = $dialogInput.TrustCert
    $Window.DialogResult = $true
    $Window.Close()
})

$TestBtn.Add_Click({
    $dialogInput = Get-DialogInput -ServerInput $ServerInput -WinAuth $WinAuth -UsernameInput $UsernameInput -PasswordInput $PasswordInput -EncryptOption $EncryptOption -TrustCert $TrustCert
    $validationMessage = Validate-DialogInput -InputObject $dialogInput

    if ($validationMessage) {
        Show-UiMessage -Message $validationMessage -Kind Warning
        return
    }

    try {
        $result = Test-SqlConnection -InputObject $dialogInput

        if ($null -eq $result) {
            Show-UiMessage -Message 'Connection succeeded, but the version probe returned no data.' -Kind Warning
            return
        }

        Show-UiMessage -Message ("{0}`n{1}`n{2}" -f $result.ProductVersion, $result.ProductLevel, $result.Edition) -Title 'Connection Succeeded' -Kind Info
    }
    catch {
        Show-UiMessage -Message ("Connection test failed.`n`n{0}" -f $_.Exception.Message) -Kind Error
    }
})

$CancelBtn.Add_Click({
    $Window.DialogResult = $false
    $Window.Close()
})

# --- Show dialog ---
$dialogResult = $Window.ShowDialog()

if (-not $dialogResult -or [string]::IsNullOrWhiteSpace([string]$script:SqlServer)) {
    Show-UiMessage -Message 'No SQL Server connection details were provided. The assessment was cancelled.' -Kind Warning
    return
}

$SqlServer     = [string]$script:SqlServer
$AuthMethod    = [string]$script:AuthMethod
$Username      = [string]$script:Username
$Password      = [string]$script:Password
$EncryptOption = [string]$script:EncryptOption
$TrustCert     = [bool]$script:TrustCert


$SqlServerDisplay = Format-ServerName $SqlServer

$TimeStamp = Get-Date -Format 'yyMMdd_HHmm'
$ReportDateDisplay = Get-Date -Format 'yyyy-MM-dd HH:mm'
$ScopeDisplay = [string]$SqlServerDisplay
$ReportServerName = ($SqlServerDisplay -replace '\\', '$')
$ReportServerName = ($ReportServerName -replace '[<>:"/\|?*]', '_')
$DetailsPath = Join-Path $ResultsFolder ("{0}_SQL_Security_Assessment_CommunityEdition_{1}.html" -f $ReportServerName, $TimeStamp)
$LogPath = Join-Path $ResultsFolder ("{0}_SQL_Security_Assessment_CommunityEdition_{1}.txt" -f $ReportServerName, $TimeStamp)


























# --- READ INPUT FILES ---
try {
    $SqlText = Get-Content -Raw -Path $SqlFilePath -ErrorAction Stop
}
catch {
    Write-Error ("Failed to read SQL file: {0}" -f $_.Exception.Message)
    return
}

$SqlDefinedChecks = @(Get-SqlDefinedChecks -SqlText $SqlText)
$SqlDefinedChecks = @($SqlDefinedChecks | Where-Object { $AllowedCheckIdLookup.ContainsKey($_.CheckId) })




# --- RUN SQL ---
try {
    $Data = Invoke-AssessmentSqlcmd -ServerInstance $SqlServer -Database $Database -InputFile $SqlFilePath -AuthMethod $AuthMethod -Username $Username -Password $Password -EncryptOption $EncryptOption -TrustCert $TrustCert
}
catch {
    Write-Error ("Failed to execute SQL file against server '{0}': {1}" -f $SqlServer, $_.Exception.Message)
    return
}

if ($null -eq $Data) {
    $Data = @()
}

$AllRows = @($Data)
$RowsWithoutCheckId = @($AllRows | Where-Object { [string]::IsNullOrWhiteSpace((Get-RowCheckId $_)) })
$RowsWithCheckId = @($AllRows | Where-Object { $id = Get-RowCheckId $_; -not [string]::IsNullOrWhiteSpace($id) -and $AllowedCheckIdLookup.ContainsKey($id) })

$CatalogLookup = @{}
foreach ($catalogRow in $Catalog) {
    $normalizedId = Normalize-CheckId $catalogRow.'Check ID'
    if ($null -eq $normalizedId) { continue }
    if (-not $CatalogLookup.ContainsKey($normalizedId)) {
        $CatalogLookup[$normalizedId] = $catalogRow
    }
}

$ProcessedData = @()
$GroupedRows = $RowsWithCheckId | Group-Object { Get-RowCheckId $_ }

foreach ($group in $GroupedRows) {
    $checkId = [string]$group.Name
    $firstRow = $group.Group[0]
    $checkName = Get-RowCheckName $firstRow

    $section = 'Unmapped'
    $sectionId = 999

    if ($CatalogLookup.ContainsKey($checkId)) {
        $catalogRow = $CatalogLookup[$checkId]
        $section = [string]$catalogRow.Section
        $sectionIdValue = 999
        if ([int]::TryParse([string]$catalogRow.SectionID, [ref]$sectionIdValue)) {
            $sectionId = $sectionIdValue
        }}

    $rows = @($group.Group)
    $outcome = Get-CheckOutcome -CheckId $checkId -Rows $rows -RecommendationLookup $RecommendationLookup

    $ProcessedData += [PSCustomObject]@{
        CheckId   = $checkId
        CheckName = $checkName
        Outcome   = $outcome
        Section   = $section
        SectionID = $sectionId
        Rows      = $rows
    }
}

# add SQL-defined checks with no returned data rows
$ExistingProcessedIds = @{}
foreach ($p in $ProcessedData) {
    $ExistingProcessedIds[$p.CheckId] = $true
}

foreach ($sqlCheck in $SqlDefinedChecks) {
    if ($ExistingProcessedIds.ContainsKey($sqlCheck.CheckId)) { continue }

    $section = 'Unmapped'
    $sectionId = 999

    if ($CatalogLookup.ContainsKey($sqlCheck.CheckId)) {
        $catalogRow = $CatalogLookup[$sqlCheck.CheckId]
        $section = [string]$catalogRow.Section
        $sectionIdValue = 999
        if ([int]::TryParse([string]$catalogRow.SectionID, [ref]$sectionIdValue)) {
            $sectionId = $sectionIdValue
        }}

    $emptyRows = @()
    $outcome = Get-CheckOutcome -CheckId $sqlCheck.CheckId -Rows $emptyRows -RecommendationLookup $RecommendationLookup

    $ProcessedData += [PSCustomObject]@{
        CheckId   = [string]$sqlCheck.CheckId
        CheckName = [string]$sqlCheck.CheckName
        Outcome   = $outcome
        Section   = $section
        SectionID = $sectionId
        Rows      = $emptyRows
    }
}

$ProcessedData = @(
    $ProcessedData |
    Sort-Object SectionID, @{ Expression = { [int]([string]$_.CheckId -as [int]) } }, CheckId
)

# --- LOGGING ---
$MissingFromCatalog = @($SqlDefinedChecks | Where-Object { -not $CatalogLookup.ContainsKey($_.CheckId) })
$lines = @()
$lines += 'Checks executed by the SQL script but returning no data rows:'

$NoDataChecks = @($ProcessedData | Where-Object { $_.Rows.Count -eq 0 })
foreach ($item in $NoDataChecks) {
    $line = ('{0} | {1} | {2}' -f $item.CheckId, $item.CheckName, $item.Section)
    $lines += $line
}

$lines += ''

if ($MissingFromCatalog.Count -gt 0) {
    $lines += 'SQL-defined checks missing from ChecksSectionsTiers.csv:'
    foreach ($item in $MissingFromCatalog) {
        $lines += ('{0} | {1}' -f $item.CheckId, $item.CheckName)
    }
}
else {
    $lines += 'No SQL-defined checks are missing from the embedded catalog.'
}

$lines += ''
$lines += 'Rows returned by SQL script without a Check ID:'
$lines += ('Count: {0}' -f $RowsWithoutCheckId.Count)

if (([string]$Debug -eq 'true')) {
    $lines | Out-File -FilePath $LogPath -Encoding utf8
}

# --- SUMMARY COUNTS / DETAILS REPORT ---
$TotalChecks = @($ProcessedData).Count
$Fails  = @($ProcessedData | Where-Object { $_.Outcome -eq 'FAIL' }).Count
$Warns  = @($ProcessedData | Where-Object { $_.Outcome -eq 'WARNING' }).Count
$Passes = @($ProcessedData | Where-Object { $_.Outcome -eq 'PASS' }).Count
$Observes = @($ProcessedData | Where-Object { $_.Outcome -eq 'OBSERVE' }).Count
$ReportDateDisplay = Protect-HeaderValue (Get-Date -Format 'yyyy-MM-dd HH:mm')
$ScopeDisplay = Protect-HeaderValue ([string]$SqlServerDisplay)
$DetailSectionCount = @(
    $ProcessedData |
    Where-Object { $_.SectionID -ne 999 -and -not [string]::IsNullOrWhiteSpace($_.Section) } |
    Group-Object Section |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
).Count

$DetailSectionsGrouped = @(
    $ProcessedData |
    Group-Object Section |
    Sort-Object { [int]($_.Group[0].SectionID) }, Name
)

$DetailBlocks = @()

foreach ($sectionGroup in $DetailSectionsGrouped) {
    $sectionName = [string]$sectionGroup.Name
    $sectionId = [string]$sectionGroup.Group[0].SectionID
    $safeSectionName = [System.Net.WebUtility]::HtmlEncode($sectionName)
    $safeSectionAnchor = 'detail-section-' + $sectionId
    $DetailBlocks += "<h2 class='section-heading' id='$safeSectionAnchor'>$safeSectionName</h2>"

    foreach ($item in $sectionGroup.Group) {
        $safeCheckId = [System.Net.WebUtility]::HtmlEncode([string]$item.CheckId)
        $safeCheckName = [System.Net.WebUtility]::HtmlEncode([string]$item.CheckName)
        $outcome = [string]$item.Outcome
        $outcomeBadge = Get-OutcomeBadgeHtml -Outcome $outcome
        $detailTable = Convert-DataRowsToHtmlTable -Rows $item.Rows
        $recommendationPanel = Get-RecommendationPanelHtml -Outcome $outcome -CheckId $item.CheckId -RecommendationLookup $RecommendationLookup

        $DetailBlocks += @"
<section class='detail-section' data-check-id='$safeCheckId' data-outcome='$outcome'>
    <table class='compact-summary-table'>
        <tr>
            <td class='summary-check-id'>$safeCheckId</td>
            <td class='summary-check-name'>$safeCheckName</td>
            <td class='summary-check-outcome'>$outcomeBadge</td>
        </tr>
    </table>
    <div class='detail-content'>
        $detailTable
        $recommendationPanel
    </div>
</section>
"@
    }
}

$DetailsHeaderHtml = ''
$DetailsNavigationHtml = ''
$DetailsBodyHtml = $DetailBlocks -join "`r`n"

$DetailsTemplateHtml = $EmbeddedDetailsTemplateHtml

$DetailsHtml = $DetailsTemplateHtml.Replace('<!--DETAIL_HEADER-->', $DetailsHeaderHtml)
$DetailsHtml = $DetailsHtml.Replace('<!--DETAIL_NAVIGATION-->', $DetailsNavigationHtml)
$DetailsHtml = $DetailsHtml.Replace('<!--DETAIL_BODY-->', $DetailsBodyHtml)
$DetailsHtml = $DetailsHtml.Replace('{RELEASE_VERSION}', [string]$ReleaseVersion)
$DetailsHtml = $DetailsHtml.Replace('{CHECK_COUNT}', [string]$TotalChecks)
$DetailsHtml = $DetailsHtml.Replace('{SECTION_COUNT}', [string]$DetailSectionCount)
$DetailsHtml = $DetailsHtml.Replace('{REPORT_DATE}', [string]$ReportDateDisplay)
$DetailsHtml = $DetailsHtml.Replace('{TARGET_SERVER}', [string]$ScopeDisplay)
$DetailsHtml = $DetailsHtml.Replace('__RELEASE_VERSION__', [string]$ReleaseVersion)
$DetailsHtml = $DetailsHtml.Replace('__CHECK_COUNT__', [string]$TotalChecks)
$DetailsHtml = $DetailsHtml.Replace('__SECTION_COUNT__', [string]$DetailSectionCount)
$DetailsHtml = $DetailsHtml.Replace('__REPORT_DATE__', [string]$ReportDateDisplay)
$DetailsHtml = $DetailsHtml.Replace('__TARGET_SERVER__', [string]$ScopeDisplay)
$DetailsHtml = $DetailsHtml.Replace('{{RELEASE_VERSION}}', [string]$ReleaseVersion)
$DetailsHtml = $DetailsHtml.Replace('{{CHECK_COUNT}}', [string]$TotalChecks)
$DetailsHtml = $DetailsHtml.Replace('{{SECTION_COUNT}}', [string]$DetailSectionCount)
$DetailsHtml = $DetailsHtml.Replace('{{REPORT_DATE}}', [string]$ReportDateDisplay)
$DetailsHtml = $DetailsHtml.Replace('{{TARGET_SERVER}}', [string]$ScopeDisplay)
$DetailsHtml = $DetailsHtml.Replace('__RELEASE_VERSION__', [string]$ReleaseVersion)
$DetailsHtml = $DetailsHtml.Replace('__CHECK_COUNT__', [string]$TotalChecks)
$DetailsHtml = $DetailsHtml.Replace('__SECTION_COUNT__', [string]$DetailSectionCount)
$DetailsHtml = $DetailsHtml.Replace('__REPORT_DATE__', [string]$ReportDateDisplay)
$DetailsHtml = $DetailsHtml.Replace('__TARGET_SERVER__', [string]$ScopeDisplay)

$DetailsHtml | Out-File -FilePath $DetailsPath -Encoding utf8

Write-Host ("Success! Details report created at: {0}" -f $DetailsPath) -ForegroundColor Green
if (([string]$Debug -eq 'true')) { Write-Host ("Debug log written to: {0}" -f $LogPath) -ForegroundColor Green }
