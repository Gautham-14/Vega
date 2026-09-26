$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\LocalModelBoundary.ps1"
$script:remote = 'Any'
$script:protocol = 'Any'
function Get-NetFirewallApplicationFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ Program='C:\Models\server.exe'; Package='Any' } }
function Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ LocalAddress='Any'; RemoteAddress=$script:remote } }
function Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ LocalPort='Any'; RemotePort='Any'; Protocol=$script:protocol } }
function Get-NetFirewallServiceFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ Service='Any' } }
function Get-NetFirewallInterfaceFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ InterfaceAlias='Any' } }
function Get-NetFirewallInterfaceTypeFilter { param($AssociatedNetFirewallRule) [pscustomobject]@{ InterfaceType='Any' } }
$rule = [pscustomobject]@{ Enabled='True'; Direction='Outbound'; Action='Block'; Profile='Any' }
if (-not (Test-AegisOutboundRule $rule 'C:\Models\server.exe')) { throw 'Complete deny was rejected' }
$script:remote = '192.0.2.1'
if (Test-AegisOutboundRule $rule 'C:\Models\server.exe') { throw 'Address-restricted deny was accepted' }
$script:remote = 'Any'
$script:protocol = 'TCP'
if (Test-AegisOutboundRule $rule 'C:\Models\server.exe') { throw 'TCP-only deny was accepted' }
$script:protocol = 'Any'
$rule.Profile = 'Private'
if (Test-AegisOutboundRule $rule 'C:\Models\server.exe') { throw 'Single-profile deny was accepted' }
Write-Output 'Firewall scope fixtures passed; no host policy was read or changed.'
