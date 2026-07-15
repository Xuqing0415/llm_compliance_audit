param(
    [string]$LogDir = "logs/audit",
    [string]$ExemptionsFile = "configs/exemptions.yaml",
    [int]$TopN = 20,
    [string]$Date = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd"),
    [bool]$AutoReload = $false
)

$businessKeywords = @(
    "task_id", "taskId", "taskid",
    "order_no", "orderNo", "orderno", "order_id", "orderId", "orderid",
    "user_id", "userId", "userid", "uid",
    "product_id", "productId", "productid",
    "project_id", "projectId", "projectid",
    "tenant_id", "tenantId", "tenantid",
    "org_id", "orgId", "orgid",
    "app_id", "appId", "appid",
    "trace_id", "traceId", "traceid",
    "request_id", "requestId", "requestid",
    "session_id", "sessionId", "sessionid",
    "transaction_id", "transactionId", "transactionid",
    "batch_id", "batchId", "batchid",
    "job_id", "jobId", "jobid",
    "flow_id", "flowId", "flowid",
    "node_id", "nodeId", "nodeid",
    "rule_id", "ruleId", "ruleid",
    "config_id", "configId", "configid",
    "version_id", "versionId", "versionid",
    "api_key", "apikey", "apiKey",
    "access_token", "accesstoken", "accessToken",
    "secret_key", "secretkey", "secretKey",
    "test", "demo", "sample", "example",
    "123456", "111111", "000000",
    "localhost", "127.0.0.1", "0.0.0.0",
    "internal", "staging", "sandbox", "dev"
)

$logFile = Join-Path $LogDir "audit-$Date.log"

if (-not (Test-Path $logFile)) {
    Write-Host "ERROR: Log file not found: $logFile"
    exit 1
}

Write-Host "`n=== Analyzing false positives for $Date ==="
Write-Host "Log file: $logFile"

$hitCounts = @{}
$ruleHitMap = @{}

Get-Content $logFile -Raw | ForEach-Object {
    $lines = $_ -split "`n" | Where-Object { $_.Trim() -ne "" }
    
    foreach ($line in $lines) {
        try {
            $json = $line | ConvertFrom-Json
            
            if ($json.detection_results) {
                foreach ($result in $json.detection_results) {
                    if ($result.matched -eq $true) {
                        $ruleId = $result.hit_rule_id
                        $matchedText = $result.matched_text
                        
                        if ($matchedText -and $matchedText.Trim() -ne "") {
                            $key = "$ruleId|$matchedText"
                            $hitCounts[$key] = ($hitCounts[$key] + 1)
                            
                            if (-not $ruleHitMap.ContainsKey($ruleId)) {
                                $ruleHitMap[$ruleId] = @{}
                            }
                            $ruleHitMap[$ruleId][$matchedText] = ($ruleHitMap[$ruleId][$matchedText] + 1)
                        }
                    }
                }
            }
        } catch {
            continue
        }
    }
}

$totalHits = $hitCounts.Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum
Write-Host "Total matched records: $totalHits"

$topMatches = $hitCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $TopN

Write-Host "`n=== Top $TopN Hit Patterns ==="
Write-Host ("{0,5} | {1,20} | {2,40} | {3}" -f "Count", "Rule ID", "Matched Text", "Is Business")

$potentialExemptions = @()

foreach ($entry in $topMatches) {
    $parts = $entry.Key -split "\|", 2
    $ruleId = $parts[0]
    $matchedText = $parts[1]
    $count = $entry.Value
    
    $isBusiness = $false
    foreach ($keyword in $businessKeywords) {
        if ($matchedText -match [regex]::Escape($keyword)) {
            $isBusiness = $true
            break
        }
    }
    
    Write-Host ("{0,5} | {1,20} | {2,40} | {3}" -f $count, $ruleId, ($matchedText.Substring(0, [Math]::Min(40, $matchedText.Length))), $isBusiness)
    
    if ($isBusiness) {
        $potentialExemptions += [PSCustomObject]@{
            RuleId      = $ruleId
            MatchedText = $matchedText
            Count       = $count
        }
    }
}

Write-Host "`n=== Rule Distribution ==="
foreach ($ruleId in $ruleHitMap.Keys | Sort-Object) {
    $ruleTotal = $ruleHitMap[$ruleId].Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $percent = [math]::Round(($ruleTotal / $totalHits) * 100, 2)
    Write-Host ("{0,20} : {1,6} hits ({2,5}%)" -f $ruleId, $ruleTotal, "$percent%")
}

if ($potentialExemptions.Count -gt 0) {
    Write-Host "`n=== Potential False Positives to Exempt ==="
    Write-Host "Found $($potentialExemptions.Count) entries that match business keywords"
    
    $exemptionContent = @"
`n# Auto-generated exemptions for $Date
"@
    
    foreach ($exemption in $potentialExemptions) {
        $exemptionContent += @"

- rule_name: "$($exemption.RuleId)"
  patterns:
    - "^$([regex]::Escape($exemption.MatchedText))`$"
"@
    }
    
    Write-Host "`nExemption content to add:"
    Write-Host $exemptionContent
    
    if ($AutoReload) {
        Add-Content -Path $ExemptionsFile -Value $exemptionContent
        Write-Host "`nAppended to $ExemptionsFile"
        
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:9090/admin/exemptions/reload" -Method Post -ContentType "application/json"
            Write-Host "`nExemptions reloaded successfully"
            Write-Host "Response: $($response | ConvertTo-Json)"
        } catch {
            Write-Host "`nWARNING: Failed to reload exemptions via API: $_"
            Write-Host "Please manually run: curl -X POST http://localhost:9090/admin/exemptions/reload"
        }
    } else {
        Write-Host "`nRun with -AutoReload to automatically add these exemptions and trigger hot-reload"
    }
} else {
    Write-Host "`nNo potential false positives found matching business keywords"
}

$exemptedCount = $potentialExemptions.Count
$coveragePercent = if ($topMatches.Count -gt 0) { [math]::Round(($exemptedCount / $topMatches.Count) * 100, 2) } else { 0 }

Write-Host "`n=== Summary ==="
Write-Host ("Top {0} hits: {1}" -f $TopN, $topMatches.Count)
Write-Host ("Potential exemptions: {0}" -f $exemptedCount)
Write-Host ("Coverage of Top {0}: {1}%" -f $TopN, $coveragePercent)

if ($coveragePercent -ge 75) {
    Write-Host "`nSUCCESS: Your whitelist is maturing! Coverage >= 75% indicates readiness to consider disabling audit_only_mode."
} elseif ($coveragePercent -ge 50) {
    Write-Host "`nPROGRESS: Your whitelist is improving. Continue adding exemptions until coverage >= 75%."
} else {
    Write-Host "`nACTION REQUIRED: Your whitelist needs more entries. Consider expanding business keyword dictionary."
}
