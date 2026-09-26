# Shared read-only validation. Importing this file never changes host policy.
function Resolve-AegisLocalExecutable {
    param([string] $Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')) {
        throw 'Select an absolute local drive path, not a network/device path or alternate stream.'
    }
    $absolute = [IO.Path]::GetFullPath($Path)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($absolute))
    if ($drive.DriveType -notin @('Fixed', 'Removable', 'CDRom', 'Ram')) {
        throw 'Select an available local drive.'
    }
    $file = Get-Item -LiteralPath $absolute -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Extension -ne '.exe') { throw 'Select a regular .exe file.' }
    $part = $file
    while ($null -ne $part) {
        if ($part.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Links and junctions are not allowed.' }
        $part = if ($part -is [IO.FileInfo]) { $part.Directory } else { $part.Parent }
    }
    return $file
}

function Test-AegisOutboundRule {
    param($Rule, [string] $Executable)
    if ($null -eq $Rule -or $Rule.Enabled -ne 'True' -or $Rule.Direction -ne 'Outbound' -or
        $Rule.Action -ne 'Block' -or $Rule.Profile -ne 'Any') { return $false }
    $application = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $address = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $service = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interface = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    $interfaceType = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
    if ($application.Count -ne 1 -or $application[0].Program -ne $Executable -or $application[0].Package -ne 'Any' -or
        $address.Count -ne 1 -or $port.Count -ne 1 -or $service.Count -ne 1 -or
        $interface.Count -ne 1 -or $interfaceType.Count -ne 1) { return $false }
    foreach ($scope in @(@($address[0].LocalAddress), @($address[0].RemoteAddress),
                         @($port[0].LocalPort), @($port[0].RemotePort), @($port[0].Protocol),
                         @($service[0].Service), @($interface[0].InterfaceAlias), @($interfaceType[0].InterfaceType))) {
        if ($scope.Count -ne 1 -or $scope[0] -ne 'Any') { return $false }
    }
    return $true
}
