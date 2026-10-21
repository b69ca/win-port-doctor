$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$issues = [System.Collections.Generic.List[object]]::new()
function Read-Section([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { $issues.Add([ordered]@{ area = $Name; message = $_.Exception.Message }) }
}
function Read-Events($Filter, [int]$Maximum) {
    try {
        @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Maximum -ErrorAction Stop | ForEach-Object {
            [ordered]@{ timeUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id; provider = $_.ProviderName; message = $_.Message }
        })
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
$portNumber = [int]$env:WD_PORT
$tcp = @(); $udp = @()
try { $tcp = @(Get-NetTCPConnection -LocalPort $portNumber -ErrorAction Stop) } catch { if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') { $issues.Add(@{area='tcp';message=$_.Exception.Message}) } }
try { $udp = @(Get-NetUDPEndpoint -LocalPort $portNumber -ErrorAction Stop) } catch { if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') { $issues.Add(@{area='udp';message=$_.Exception.Message}) } }
$owners = @{}
$rows = @(@($tcp | ForEach-Object { @{protocol='TCP';address=$_.LocalAddress;state=$_.State.ToString();pid=[int]$_.OwningProcess} }) + @($udp | ForEach-Object { @{protocol='UDP';address=$_.LocalAddress;state='Bound';pid=[int]$_.OwningProcess} }))
$truncated = $rows.Count -gt 500
$rows = @($rows | Select-Object -First 500 | ForEach-Object {
    $ownerId = $_.pid
    if (-not $owners.ContainsKey($ownerId)) {
        $processInfo = $null; $serviceNames = @()
        if ($ownerId -gt 0) {
            $processInfo = Read-Section "process-$ownerId" { Get-CimInstance Win32_Process -Filter "ProcessId = $ownerId" | Select-Object @{n='name';e={$_.Name}},@{n='path';e={$_.ExecutablePath}} }
            $serviceNames = @(Read-Section "services-$ownerId" { Get-CimInstance Win32_Service -Filter "ProcessId = $ownerId" | ForEach-Object { $_.Name } })
        }
        $owners[$ownerId] = @{process=$processInfo;services=$serviceNames}
    }
    $_.process = $owners[$ownerId].process; $_.services = @($owners[$ownerId].services); $_
})
@{evidence=@{port=$portNumber;listeners=$rows;truncated=$truncated};issues=@($issues.ToArray())} | ConvertTo-Json -Depth 10 -Compress
