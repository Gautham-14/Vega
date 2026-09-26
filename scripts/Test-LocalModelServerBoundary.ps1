# Read-only snapshot. It cannot prove zero egress or loaded model bytes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ExecutablePath,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedExeSha256,
    [ValidateRange(1, 2147483647)]
    [int] $ModelProcessId
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\LocalModelBoundary.ps1"
$file = Resolve-AegisLocalExecutable $ExecutablePath
$resolvedPath = $file.FullName
$actualHash = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pathDigest = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($resolvedPath.ToLowerInvariant()))
$suffix = -join ($pathDigest[0..7] | ForEach-Object { $_.ToString('x2') })
$ruleName = "Aegis local-model outbound deny $suffix"
$rules = @(Get-NetFirewallRule -DisplayName $ruleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$ruleValid = $false
if ($rules.Count -eq 1) {
    $ruleValid = Test-AegisOutboundRule $rules[0] $resolvedPath
}
$profiles = @(Get-NetFirewallProfile)
$profilesEnabled = ($profiles.Count -gt 0 -and @($profiles | Where-Object { $_.Enabled -ne 'True' }).Count -eq 0)
$processes = @()
$unruledChildren = @()
$externalConnections = 0
$connectionCheck = 'NOT_RUN'
if ($ModelProcessId -gt 0) {
    $all = @(Get-CimInstance Win32_Process)
    $rootProcess = $all | Where-Object { $_.ProcessId -eq $ModelProcessId } | Select-Object -First 1
    if (-not $rootProcess) { throw 'Model process ID is not running.' }
    if ($rootProcess.ExecutablePath -ne $resolvedPath) { throw 'Model process does not run the selected executable.' }
    $pending = @($rootProcess)
    $seen = @{}
    while ($pending.Count -gt 0) {
        $current = $pending[0]
        $pending = @($pending | Select-Object -Skip 1)
        if ($seen.ContainsKey([string]$current.ProcessId)) { continue }
        $seen[[string]$current.ProcessId] = $true
        $processes += [pscustomobject]@{
            Id = $current.ProcessId
            Path = $current.ExecutablePath
            MatchesSelectedExecutable = ($current.ExecutablePath -eq $resolvedPath)
        }
        $pending += @($all | Where-Object { $_.ParentProcessId -eq $current.ProcessId })
    }
    $unruledChildren = @($processes | Where-Object { -not $_.MatchesSelectedExecutable })
    try {
        $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            $seen.ContainsKey([string]$_.OwningProcess) -and $_.State -in @('Established', 'SynSent', 'CloseWait')
        })
        foreach ($connection in $connections) {
            $parsed = [Net.IPAddress]::None
            if ([Net.IPAddress]::TryParse($connection.RemoteAddress, [ref]$parsed) -and -not [Net.IPAddress]::IsLoopback($parsed)) {
                $externalConnections++
            }
        }
        $connectionCheck = 'POINT_IN_TIME_ONLY'
    } catch {
        $connectionCheck = 'UNAVAILABLE'
    }
}

[pscustomobject]@{
    Executable = $resolvedPath
    ExecutableSha256 = $actualHash
    ExecutableHashMatches = ($ExpectedExeSha256 -and $actualHash -eq $ExpectedExeSha256.ToLowerInvariant())
    RuleName = $ruleName
    OutboundDenyRuleValid = $ruleValid
    AllFirewallProfilesEnabled = $profilesEnabled
    ProcessTree = $processes
    ChildExecutablesNeedingSeparateRules = $unruledChildren
    ExternalTcpConnectionsObserved = $externalConnections
    ConnectionCheck = $connectionCheck
    EgressMeasured = $false
    LoadedModelBytesVerified = $false
    ProductionEligible = $false
}
