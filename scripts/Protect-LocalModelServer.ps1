# Apply an outbound deny rule to each explicitly selected local model executable.
# Run in an elevated PowerShell after installing the model server. This does not
# constrain child executables or replace a network-isolated VM/container.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $ExecutablePath,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\LocalModelBoundary.ps1"
$resolved = foreach ($item in $ExecutablePath) {
    $file = Resolve-AegisLocalExecutable $item
    $file.FullName
}

if ($Apply) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated PowerShell is required to add Windows Firewall rules.'
    }
}

foreach ($path in $resolved) {
    $digest = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant()))
    $suffix = -join ($digest[0..7] | ForEach-Object { $_.ToString('x2') })
    $name = "Aegis local-model outbound deny $suffix"
    if (-not $Apply) {
        [pscustomobject]@{ Program = $path; Rule = $name; Applied = $false }
        continue
    }
    $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($rule) {
        if (@($rule).Count -ne 1 -or -not (Test-AegisOutboundRule $rule $path)) {
            throw "Existing rule conflicts with expected outbound deny: $name"
        }
        $filter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
        if (@($filter).Count -ne 1 -or $filter.Program -ne $path) {
            throw "Existing rule targets a different executable: $name"
        }
    } else {
        $rule = New-NetFirewallRule -DisplayName $name -Direction Outbound -Action Block -Program $path -Profile Any -Enabled True
        $filter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
        if (-not (Test-AegisOutboundRule $rule $path)) {
            throw "Firewall rule verification failed: $name"
        }
    }
    [pscustomobject]@{ Program = $path; Rule = $name; Applied = $true }
}
