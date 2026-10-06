#Requires -Version 5.1
<#
.SYNOPSIS
    Endpoint Security Compliance Audit Script (41 checkpoints)
    Maps to CIS Controls v8.1 / ISO/IEC 27001:2022 / NIST SP 800-53 Rev.5

.DESCRIPTION
    Runs 41 read-only checks. Each checkpoint writes its own .txt file
    (01_... to 41_...) and everything is merged into
    00_COMPREHENSIVE_REPORT_<Computer>_<IPv4>_<Date_Time>.txt

    OUTPUT LOCATION
      A folder named  <ComputerName>_<IPv4>_<yyyy-MM-dd_HH-mm-ss>  is created
      in the SAME FOLDER AS THIS SCRIPT (also after the elevated relaunch).

    FORCED EXECUTION
      * Relaunches itself as Administrator with -ExecutionPolicy Bypass
      * Sets Bypass for this process only, removes the Zone.Identifier block
      * Errors are no longer hidden: they are written into each checkpoint file
      * A transcript (00_RunLog.txt) is saved in the output folder

.PARAMETER OutputRoot
    Optional override. Default = folder containing this script.

.PARAMETER OnDesktop
    Put the output folder on the current user's Desktop instead.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\EndpointComplianceAudit.ps1"
#>

[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$OnDesktop,
    [switch]$Elevated      # internal: set when the script relaunches itself as Administrator
)

# ==================================================================
# 0. FORCE EXECUTION: output path, elevation, Bypass, unblock
# ==================================================================
$ScriptPath = $PSCommandPath
$IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Resolve the output location FIRST so it survives the elevated relaunch.
if ($OnDesktop) { $OutputRoot = [Environment]::GetFolderPath('Desktop') }
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    if     ($PSScriptRoot) { $OutputRoot = $PSScriptRoot }
    elseif ($ScriptPath)   { $OutputRoot = Split-Path -Parent $ScriptPath }
    else                   { $OutputRoot = (Get-Location).Path }
}

# Not elevated? Relaunch this same script as Administrator with Bypass.
if (-not $IsAdmin -and -not $Elevated -and $ScriptPath) {
    Write-Host "[i] Not elevated - relaunching as Administrator with -ExecutionPolicy Bypass..." -ForegroundColor Yellow
    $argRoot = $OutputRoot
    if ($argRoot.EndsWith('\')) { $argRoot += '\' }   # stops a trailing backslash escaping the closing quote
    $relaunchArgs = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$ScriptPath`" -OutputRoot `"$argRoot`" -Elevated"
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $relaunchArgs -Verb RunAs -ErrorAction Stop
        exit
    } catch {
        Write-Host "[!] Elevation declined - continuing WITHOUT Administrator rights (some checks will be empty)." -ForegroundColor Yellow
    }
}

try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    Write-Host "[i] Execution policy set to Bypass for this process only." -ForegroundColor DarkGray
} catch {
    Write-Host "[!] Could not set process execution policy: $($_.Exception.Message)" -ForegroundColor Yellow
}
try { if ($ScriptPath) { Unblock-File -Path $ScriptPath -ErrorAction SilentlyContinue } } catch { }

Write-Host "[i] Execution policy (all scopes):" -ForegroundColor DarkGray
Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "[i] PowerShell language mode: $($ExecutionContext.SessionState.LanguageMode)" -ForegroundColor DarkGray

# ==================================================================
# SETUP
# ==================================================================
$ErrorActionPreference = 'Continue'     # errors are visible, not hidden
$ProgressPreference    = 'Continue'

$ComputerName = $env:COMPUTERNAME
$CurrentUser  = "$env:USERDOMAIN\$env:USERNAME"
$Timestamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$RunDateTime  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Get-PrimaryIPv4 {
    $ip = $null
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
               Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
               Select-Object -First 1
        if ($cfg) { $ip = @($cfg.IPv4Address.IPAddress)[0] }
    } catch { }
    if (-not $ip) {
        try {
            $ip = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                    Sort-Object InterfaceMetric | Select-Object -First 1).IPAddress
        } catch { }
    }
    if (-not $ip) {
        try {
            $ip = @([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.IPAddressToString -notmatch '^(127\.|169\.254\.)' })[0].IPAddressToString
        } catch { }
    }
    if (-not $ip) { $ip = 'NoIPv4' }
    return "$ip"
}

$IPv4     = Get-PrimaryIPv4
$IPv4Safe = $IPv4 -replace '[^0-9A-Za-z\.\-]', '_'

# Folder name = COMPUTERNAME _ IPv4 _ Date_Time  (created in the script's folder)
$FolderName = "${ComputerName}_${IPv4Safe}_${Timestamp}"
$BasePath   = Join-Path -Path $OutputRoot -ChildPath $FolderName
try {
    New-Item -ItemType Directory -Path $BasePath -Force -ErrorAction Stop | Out-Null
} catch {
    $fallback = [Environment]::GetFolderPath('Desktop')
    Write-Host "[!] Cannot write to '$OutputRoot' ($($_.Exception.Message)). Falling back to Desktop." -ForegroundColor Yellow
    $BasePath = Join-Path -Path $fallback -ChildPath $FolderName
    New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
}

try { Start-Transcript -Path (Join-Path $BasePath '00_RunLog.txt') -Force | Out-Null } catch { }

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " ENDPOINT SECURITY COMPLIANCE AUDIT - 41 CHECKPOINTS" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Computer      : $ComputerName"
Write-Host " IPv4 Address  : $IPv4"
Write-Host " User          : $CurrentUser"
Write-Host " Started       : $RunDateTime"
Write-Host " Elevated      : $IsAdmin"
Write-Host " Output folder : $BasePath"
Write-Host "==================================================================" -ForegroundColor Cyan
if (-not $IsAdmin) {
    Write-Host "[!] NOT running as Administrator - Defender, BitLocker, Firewall," -ForegroundColor Yellow
    Write-Host "    Audit Policy, Secure Boot and AppLocker checks may be incomplete." -ForegroundColor Yellow
}
Write-Host ""

# ==================================================================
# HELPERS
# ==================================================================
$Global:AllResults = [System.Collections.Generic.List[PSObject]]::new()

$Script:CachedComputerInfo = $null
function Get-CachedComputerInfo {
    if (-not $Script:CachedComputerInfo) { $Script:CachedComputerInfo = Get-ComputerInfo }
    return $Script:CachedComputerInfo
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory)][string]$Name)
    $safe = $Name -replace '&', 'and'
    $safe = $safe -replace '[\\/:\*\?"<>\|]', ' '
    $safe = $safe -replace '\s+', ' '
    return ($safe.Trim() -replace ' ', '_')
}

function Invoke-SafeBlock {
    param([Parameter(Mandatory)][scriptblock]$Block)
    try {
        # 2>&1 merges errors into the output so they appear inside the .txt file
        $out = & $Block 2>&1 | Out-String -Width 4096
        if ([string]::IsNullOrWhiteSpace($out)) {
            return "No data returned. The feature may not exist on this system, or the cmdlet needs Administrator rights / Windows Defender as the active antivirus."
        }
        return $out.Trim()
    } catch {
        return "Could not complete check. Error: $($_.Exception.Message)"
    }
}

function New-CheckReport {
    param(
        [Parameter(Mandatory)][int]    $Number,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][string] $Content
    )

    $fileName = "{0:D2}_{1}.txt" -f $Number, (ConvertTo-SafeFileName $Title)
    $filePath = Join-Path -Path $BasePath -ChildPath $fileName

    $header = @"
==================================================================
CHECKPOINT $Number : $Title
------------------------------------------------------------------
Computer   : $ComputerName
IPv4       : $IPv4
User       : $CurrentUser
Elevated   : $IsAdmin
Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
==================================================================

"@

    $fullText = $header + $Content + "`r`n"
    $fullText | Out-File -FilePath $filePath -Encoding UTF8 -Force

    $Global:AllResults.Add([PSCustomObject]@{
        Number = $Number; Title = $Title; FileName = $fileName; Content = $fullText
    })

    Write-Host ("[{0,2}/41] {1,-45} -> {2}" -f $Number, $Title, $fileName) -ForegroundColor Green
}

# ==================================================================
# CHECKPOINT DEFINITIONS
# ==================================================================
$Checks = @(

    @{ N = 1; Title = 'Asset / Computer Name'; Code = {
        Get-CachedComputerInfo | Select-Object CsName, CsDomain, CsManufacturer, CsModel,
            WindowsProductName, OsArchitecture, BiosSeralNumber | Format-List
        "IPv4 Address (primary) : $IPv4"
    }},

    @{ N = 2; Title = 'Assigned User / Asset Owner'; Code = {
        "Currently logged-on user : $CurrentUser"
        ""
        "Registered Owner / Organization (from registry):"
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
            Select-Object RegisteredOwner, RegisteredOrganization | Format-List
        "NOTE: Compare the above against the organizational Asset Register to confirm correct assignment."
    }},

    @{ N = 3; Title = 'Operating System & Version'; Code = {
        Get-CachedComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, OsArchitecture,
            OsInstallDate, OsLastBootUpTime, WindowsVersion | Format-List
        $ubr = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        "DisplayVersion / Release : $($ubr.DisplayVersion)"
        "Full build (UBR)         : $($ubr.CurrentBuild).$($ubr.UBR)"
    }},

    @{ N = 4; Title = 'Domain Membership'; Code = {
        Get-CimInstance Win32_ComputerSystem |
            Select-Object Name, Domain, PartOfDomain, Workgroup, DomainRole | Format-List
        "DomainRole legend: 0/1 = Standalone/Member Workstation, 2/3 = Standalone/Member Server, 4/5 = Domain Controller"
    }},

    @{ N = 5; Title = 'Local Administrator Membership'; Code = {
        "Members of the local Administrators group:"
        Get-LocalGroupMember -Group 'Administrators' |
            Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize
        "NOTE: Every account listed above must be justified and approved. Standard users should not appear here."
    }},

    @{ N = 6; Title = 'Domain Administrator / Privileged Access'; Code = {
        "NOTE: Full Domain Admin membership requires the ActiveDirectory module and Domain Controller access."
        "This check reports local privileged group membership as a proxy indicator."
        ""
        "Local Administrators:"
        Get-LocalGroupMember -Group 'Administrators' | Format-Table -AutoSize
        ""
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory
            "Domain Admins group members (if reachable):"
            Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SamAccountName | Format-Table -AutoSize
        } else {
            "ActiveDirectory module not available on this host."
            "Verify Domain Admin / privileged access centrally via AD tooling."
        }
    }},

    @{ N = 7; Title = 'Unauthorized User Accounts'; Code = {
        "All local user accounts (review for unknown / unapproved accounts):"
        Get-LocalUser |
            Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description |
            Sort-Object Name | Format-Table -AutoSize
    }},

    @{ N = 8; Title = 'Password / PIN Configuration'; Code = {
        "Local password policy (net accounts):"
        net accounts
        ""
        "Password policy registry indicators:"
        $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        "LimitBlankPasswordUse : $($lsa.LimitBlankPasswordUse)  (1 = blank passwords restricted to console)"
        ""
        "Windows Hello / PIN configuration presence (registry indicator):"
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' |
            Select-Object -ExpandProperty PSChildName
    }},

    @{ N = 9; Title = 'Automatic Screen Lock'; Code = {
        $d = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
        "ScreenSaveActive        : $($d.ScreenSaveActive)   (1 = screen saver enabled)"
        "ScreenSaveTimeOut (sec) : $($d.ScreenSaveTimeOut)"
        "ScreenSaverIsSecure     : $($d.ScreenSaverIsSecure)   (1 = password required on resume)"
        ""
        "Machine inactivity limit policy (if set):"
        $inact = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue
        "InactivityTimeoutSecs   : $($inact.InactivityTimeoutSecs)"
        "BENCHMARK: Auto-lock should trigger at or below 900 seconds (15 minutes) with password on resume."
    }},

    @{ N = 10; Title = 'Installation Rights'; Code = {
        "Current user group memberships (whoami /groups):"
        whoami /groups
        ""
        "Windows Installer restriction policies:"
        $msi = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue
        "DisableMSI            : $($msi.DisableMSI)"
        "AlwaysInstallElevated : $($msi.AlwaysInstallElevated)  (1 = INSECURE, should be 0/absent)"
        ""
        "NOTE: Membership of 'Administrators' generally allows software installation."
        "Standard (non-admin) users should NOT appear in the Administrators group - see Checkpoint 5."
    }},

    @{ N = 11; Title = 'Last Windows Security Update'; Code = {
        $hf = Get-HotFix | Sort-Object InstalledOn -Descending
        "Most recent 15 installed hotfixes / updates:"
        $hf | Select-Object -First 15 HotFixID, Description, InstalledOn, InstalledBy | Format-Table -AutoSize
        ""
        $last = $hf | Select-Object -First 1
        if ($last -and $last.InstalledOn) {
            $age = (New-TimeSpan -Start $last.InstalledOn -End (Get-Date)).Days
            "Last update installed : $($last.HotFixID) on $($last.InstalledOn)  ($age days ago)"
        }
    }},

    @{ N = 12; Title = 'Latest Cumulative Update'; Code = {
        Get-CimInstance Win32_OperatingSystem |
            Select-Object Caption, Version, BuildNumber, ServicePackMajorVersion | Format-List
        $ubr = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        "Current build with revision : $($ubr.CurrentBuild).$($ubr.UBR)"
        ""
        "Recent KB installs (top 10 by date):"
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Format-Table -AutoSize
        ""
        "Windows Update service status:"
        Get-Service wuauserv | Select-Object Name, Status, StartType | Format-Table -AutoSize
    }},

    @{ N = 13; Title = 'Defender Security Intelligence Update'; Code = {
        Get-MpComputerStatus |
            Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion, AntivirusSignatureAge,
                          AntispywareSignatureLastUpdated, AntispywareSignatureVersion,
                          NISSignatureLastUpdated, NISSignatureVersion | Format-List
        "BENCHMARK: Signature age should be 1 day or less."
    }},

    @{ N = 14; Title = 'Application Update Status'; Code = {
        "Installed versions of common high-risk applications (verify each against current vendor release):"
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Chrome|Edge|Firefox|Adobe|Java|Office|Zoom|Teams|7-Zip|WinRAR|Notepad\+\+|VLC' } |
            Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Format-Table -AutoSize
    }},

    @{ N = 15; Title = 'Unauthorized / Unlicensed Applications'; Code = {
        "Full installed application inventory - compare against the approved / licensed software list:"
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName -Unique | Format-Table -AutoSize
        ""
        "Windows licensing status:"
        Get-CimInstance SoftwareLicensingProduct |
            Where-Object { $_.PartialProductKey -and $_.Name -like 'Windows*' } |
            Select-Object Name, LicenseStatus, GracePeriodRemaining | Format-List
        "LicenseStatus legend: 1 = Licensed, 0 = Unlicensed, 2 = OOB Grace, 5 = Notification"
    }},

    @{ N = 16; Title = 'Unnecessary Applications'; Code = {
        "Review the inventory below and identify unused / unnecessary software for removal:"
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, Publisher, InstallDate |
            Sort-Object DisplayName -Unique | Format-Table -AutoSize
        ""
        "Microsoft Store / bloatware packages for current user:"
        Get-AppxPackage | Where-Object { -not $_.IsFramework } |
            Select-Object Name, Version | Sort-Object Name | Format-Table -AutoSize
    }},

    @{ N = 17; Title = 'Antivirus / EDR Installed'; Code = {
        "Registered security products (Windows Security Center):"
        Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct |
            Select-Object displayName, productState, pathToSignedProductExe, timestamp | Format-List
        ""
        "Known EDR / AV agent services detected on this host:"
        Get-Service |
            Where-Object { $_.DisplayName -match 'Defender|CrowdStrike|SentinelOne|Sophos|Symantec|McAfee|Trend Micro|ESET|Kaspersky|Bitdefender|Carbon Black|Cortex|Cylance|Trellix|Elastic Agent' } |
            Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
    }},

    @{ N = 18; Title = 'Antivirus Enabled & Running'; Code = {
        Get-MpComputerStatus |
            Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
                          RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled,
                          OnAccessProtectionEnabled, TamperProtectionSource, IsTamperProtected | Format-List
        ""
        "Defender service states:"
        Get-Service WinDefend, WdNisSvc, Sense -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
        "BENCHMARK: Real-time protection and tamper protection must both be enabled."
    }},

    @{ N = 19; Title = 'Antivirus Signature / Engine Updated'; Code = {
        Get-MpComputerStatus |
            Select-Object AntivirusSignatureVersion, AntivirusSignatureAge, AntivirusSignatureLastUpdated,
                          AMEngineVersion, AMProductVersion, AMRunningMode | Format-List
    }},

    @{ N = 20; Title = 'Antivirus Exclusions / Exceptions'; Code = {
        "NOTE: Every exclusion below weakens protection and must be documented and approved."
        Get-MpPreference |
            Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress | Format-List
        ""
        "Defender feature settings that affect coverage:"
        Get-MpPreference |
            Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableScriptScanning,
                          DisableArchiveScanning, DisableRemovableDriveScanning, MAPSReporting,
                          SubmitSamplesConsent, PUAProtection | Format-List
    }},

    @{ N = 21; Title = 'Last Antivirus / Malware Scan'; Code = {
        Get-MpComputerStatus |
            Select-Object QuickScanStartTime, QuickScanEndTime, QuickScanAge,
                          FullScanStartTime, FullScanEndTime, FullScanAge | Format-List
        "BENCHMARK: A quick scan should have run within the last 7 days and a full scan within the last 30 days."
        "(Age value of 4294967295 means the scan has never been run.)"
    }},

    @{ N = 22; Title = 'Host Firewall Enabled'; Code = {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                          AllowInboundRules, LogBlocked | Format-Table -AutoSize
        ""
        "Enabled inbound ALLOW rules (review for unapproved openings):"
        Get-NetFirewallRule |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
            Select-Object DisplayName, Profile, Action | Sort-Object DisplayName | Format-Table -AutoSize
    }},

    @{ N = 23; Title = 'Open / Listening Ports'; Code = {
        "Listening TCP ports with owning process:"
        Get-NetTCPConnection -State Listen | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                ProcessId    = $_.OwningProcess
                ProcessName  = $proc.ProcessName
                ProcessPath  = $proc.Path
            }
        } | Sort-Object LocalPort | Format-Table -AutoSize
        ""
        "Listening UDP endpoints:"
        Get-NetUDPEndpoint | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort    = $_.LocalPort
                ProcessId    = $_.OwningProcess
                ProcessName  = $proc.ProcessName
            }
        } | Sort-Object LocalPort | Format-Table -AutoSize
    }},

    @{ N = 24; Title = 'Unnecessary Network Services'; Code = {
        "High-risk / legacy services and their current state:"
        $watch = 'TlntSvr','FTPSVC','SNMP','RemoteRegistry','SSDPSRV','upnphost','LanmanServer','Browser','SharedAccess','WinRM','TermService','Spooler','SessionEnv','RasMan','fdPHost','FDResPub'
        Get-Service | Where-Object { $watch -contains $_.Name } |
            Select-Object Name, DisplayName, Status, StartType | Sort-Object Name | Format-Table -AutoSize
        ""
        "All currently running services (review for anything not required by the business role):"
        Get-Service | Where-Object { $_.Status -eq 'Running' } |
            Select-Object Name, DisplayName, StartType | Sort-Object Name | Format-Table -AutoSize
    }},

    @{ N = 25; Title = 'SMBv1 Disabled'; Code = {
        "SMB1Protocol Windows optional feature:"
        Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol |
            Select-Object FeatureName, State | Format-List
        ""
        "SMB server configuration:"
        Get-SmbServerConfiguration |
            Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData | Format-List
        ""
        "SMB client SMB1 driver:"
        $mrx = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue
        "mrxsmb10 Start value : $($mrx.Start)   (4 = disabled, which is the required state)"
        "BENCHMARK: SMBv1 must be disabled / removed."
    }},

    @{ N = 26; Title = 'Remote Desktop Disabled / Restricted'; Code = {
        $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
        "fDenyTSConnections : $deny   (1 = RDP disabled, 0 = RDP enabled)"
        ""
        "Network Level Authentication (NLA) and security layer:"
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
            Select-Object UserAuthentication, SecurityLayer, MinEncryptionLevel, PortNumber | Format-List
        "(UserAuthentication 1 = NLA required)"
        ""
        "Members of the 'Remote Desktop Users' group:"
        Get-LocalGroupMember -Group 'Remote Desktop Users' |
            Select-Object Name, PrincipalSource | Format-Table -AutoSize
    }},

    @{ N = 27; Title = 'Default Network Shares'; Code = {
        "All SMB shares on this host (administrative shares end with a `$ sign):"
        Get-SmbShare | Select-Object Name, Path, Description, ShareType, CurrentUsers | Format-Table -AutoSize
        ""
        "Share-level permissions for non-administrative shares:"
        Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object {
            "Share: $($_.Name)"
            Get-SmbShareAccess -Name $_.Name |
                Select-Object AccountName, AccessControlType, AccessRight | Format-Table -AutoSize
        }
        "NOTE: Flag any user-created share that grants Everyone / Authenticated Users full access."
    }},

    @{ N = 28; Title = 'LAN / Wi-Fi Configuration'; Code = {
        "IP configuration for all active interfaces:"
        Get-NetIPConfiguration |
            Select-Object InterfaceAlias, InterfaceDescription, IPv4Address, IPv4DefaultGateway, DNSServer | Format-List
        ""
        "Primary IPv4 recorded for this audit : $IPv4"
        ""
        "Network adapters:"
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Format-Table -AutoSize
        ""
        "Wireless interface state (if applicable):"
        netsh wlan show interfaces
        ""
        "Saved wireless profiles:"
        netsh wlan show profiles
        "NOTE: Confirm Wi-Fi uses WPA2-Enterprise/WPA3 and that no unapproved or open SSID profiles are saved."
    }},

    @{ N = 29; Title = 'Public Internet Exposure'; Code = {
        "NOTE: This check requires outbound internet access and must also be validated against firewall / NAT rules centrally."
        "Internal IPv4 of this host : $IPv4"
        try {
            $publicIP = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 5 -ErrorAction Stop
            "Detected public-facing IP (via outbound request) : $($publicIP.ip)"
            if ($publicIP.ip -eq $IPv4) {
                "WARNING: The host IPv4 matches the public IP - this asset may be directly internet-exposed."
            } else {
                "Host appears to be behind NAT (internal IP differs from public IP)."
            }
        } catch {
            "Could not determine public IP automatically (no internet access or outbound request blocked)."
        }
        ""
        "Manually verify that no unauthorized inbound port-forwarding, DMZ placement, or direct public exposure exists for this asset."
    }},

    @{ N = 30; Title = 'Browser Version & Updates'; Code = {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        "Installed browsers:"
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Chrome|Edge|Firefox|Opera|Brave|Vivaldi|Chromium' } |
            Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName -Unique | Format-Table -AutoSize
        ""
        "Browser executable file versions (authoritative):"
        $exes = @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
        )
        foreach ($exe in $exes) {
            if (Test-Path $exe) { "$exe  =>  $((Get-Item $exe).VersionInfo.ProductVersion)" }
        }
        "NOTE: Compare each version against the current vendor stable release."
    }},

    @{ N = 31; Title = 'Unauthorized Browser Extensions'; Code = {
        "NOTE: Extension lists are stored per-user. Below are extension folder IDs for the CURRENT user."
        "Cross-reference each ID against the approved extension list (chrome://extensions or edge://extensions shows friendly names)."
        ""
        $profiles = @(
            @{ Name = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
            @{ Name = 'Edge';   Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
            @{ Name = 'Brave';  Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
        )
        foreach ($p in $profiles) {
            if (Test-Path $p.Path) {
                "--- $($p.Name) ---"
                Get-ChildItem -Path $p.Path -Directory |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | ForEach-Object {
                        $extDir = Join-Path $_.FullName 'Extensions'
                        if (Test-Path $extDir) {
                            "Profile: $($_.Name)"
                            Get-ChildItem $extDir -Directory | Select-Object -ExpandProperty Name
                        }
                    }
                ""
            }
        }
        "Firefox extensions (if installed):"
        $ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $ffProfiles) {
            Get-ChildItem $ffProfiles -Directory | ForEach-Object {
                $extDir = Join-Path $_.FullName 'extensions'
                if (Test-Path $extDir) {
                    "Profile: $($_.Name)"
                    Get-ChildItem $extDir | Select-Object -ExpandProperty Name
                }
            }
        } else {
            "Firefox profile folder not found."
        }
    }},

    @{ N = 32; Title = 'Saved Browser Passwords'; Code = {
        "This check reviews SETTINGS ONLY. No passwords are accessed, read, decrypted or stored by this script."
        ""
        "Password-saving is controlled by the 'PasswordManagerEnabled' policy (0 = disabled / compliant)."
        $chromePolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name PasswordManagerEnabled -ErrorAction SilentlyContinue
        $edgePolicy   = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name PasswordManagerEnabled -ErrorAction SilentlyContinue
        "Chrome PasswordManagerEnabled policy : $($chromePolicy.PasswordManagerEnabled)"
        "Edge   PasswordManagerEnabled policy : $($edgePolicy.PasswordManagerEnabled)"
        ""
        "Presence of a browser credential store file (existence only - contents NOT read):"
        $stores = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
        )
        foreach ($s in $stores) {
            if (Test-Path $s) { "PRESENT : $s" } else { "Not found : $s" }
        }
        "If no policy is set, verify manually in browser settings whether password saving is enabled."
    }},

    @{ N = 33; Title = 'Unauthorized Startup / Autorun'; Code = {
        "Startup commands (registry Run keys and Startup folder items):"
        Get-CimInstance Win32_StartupCommand |
            Select-Object Name, Command, Location, User | Format-Table -AutoSize -Wrap
        ""
        "Startup folder contents:"
        $startupDirs = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        foreach ($d in $startupDirs) {
            if (Test-Path $d) {
                "--- $d ---"
                Get-ChildItem $d | Select-Object Name, LastWriteTime | Format-Table -AutoSize
            }
        }
    }},

    @{ N = 34; Title = 'PowerShell Configuration'; Code = {
        "PowerShell version table:"
        $PSVersionTable | Format-Table -AutoSize
        ""
        "Execution Policy (all scopes):"
        Get-ExecutionPolicy -List | Format-Table -AutoSize
        ""
        "Logging policy settings:"
        $sb = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
        $md = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
        $tr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
        "EnableScriptBlockLogging : $($sb.EnableScriptBlockLogging)  (1 = enabled, recommended)"
        "EnableModuleLogging      : $($md.EnableModuleLogging)"
        "EnableTranscripting      : $($tr.EnableTranscripting)"
        ""
        "PowerShell v2 engine (legacy, should be disabled):"
        Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 |
            Select-Object FeatureName, State | Format-List
    }},

    @{ N = 35; Title = 'Windows Security / Audit Logging'; Code = {
        "Audit policy (auditpol /get /category:*):"
        auditpol /get /category:*
        ""
        "Event log sizes and retention:"
        Get-WinEvent -ListLog Security, System, Application, 'Windows PowerShell' |
            Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount | Format-Table -AutoSize
        ""
        "Most recent Security log entry (confirms logging is live):"
        Get-WinEvent -LogName Security -MaxEvents 1 |
            Select-Object TimeCreated, Id, LevelDisplayName | Format-List
    }},

    @{ N = 36; Title = 'Keylogger / Malware Check'; Code = {
        "Recent Defender threat detections (if any):"
        Get-MpThreatDetection |
            Select-Object ThreatID, ProcessName, DetectionTime, InitialDetectionTime, CleaningActionID, Resources |
            Sort-Object DetectionTime -Descending | Format-Table -AutoSize -Wrap
        ""
        "Detected threat history summary:"
        Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive, DidThreatExecute | Format-Table -AutoSize
        ""
        "Processes running from user-writable / temporary locations (common malware staging paths):"
        Get-CimInstance Win32_Process |
            Where-Object { $_.ExecutablePath -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Public\\' } |
            Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize -Wrap
        ""
        "NOTE: A dedicated full AV/EDR scan (see Checkpoint 21) must also be run or verified as part of this check."
    }},

    @{ N = 37; Title = 'Device Encryption'; Code = {
        "BitLocker volume status:"
        Get-BitLockerVolume |
            Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionPercentage,
                          EncryptionMethod, ProtectionStatus, KeyProtector | Format-Table -AutoSize -Wrap
        ""
        "TPM status (required for transparent BitLocker protection):"
        Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel | Format-List
        "BENCHMARK: System drive should show FullyEncrypted with ProtectionStatus = On, and the recovery key must be escrowed."
    }},

    @{ N = 38; Title = 'Removable Media / USB Security'; Code = {
        $usbStor = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -ErrorAction SilentlyContinue
        "USBSTOR service Start value           : $($usbStor.Start)   (3 = enabled, 4 = disabled)"
        $writeProtect = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name WriteProtect -ErrorAction SilentlyContinue
        "Removable storage WriteProtect policy : $($writeProtect.WriteProtect)"
        ""
        "Removable Storage Access group policy (Deny_* = 1 means blocked):"
        Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\*' -ErrorAction SilentlyContinue |
            Select-Object PSChildName, Deny_Read, Deny_Write, Deny_Execute | Format-Table -AutoSize
        ""
        "BitLocker To Go policy for removable drives:"
        Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -ErrorAction SilentlyContinue |
            Select-Object RDVDenyWriteAccess, RDVDenyCrossOrg | Format-List
        ""
        "Currently attached removable drives:"
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' |
            Select-Object DeviceID, VolumeName, Size | Format-Table -AutoSize
        ""
        "Historical USB storage devices seen by this host:"
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty PSChildName
    }},

    @{ N = 39; Title = 'Secure Boot Status'; Code = {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            "Secure Boot Enabled : $sb"
        } catch {
            "Could not query Secure Boot status - the system may be using Legacy BIOS instead of UEFI, or the check requires elevation. ($($_.Exception.Message))"
        }
        ""
        "Firmware / boot mode:"
        $env:firmware_type
        ""
        "Virtualization-based security and Credential Guard:"
        Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard |
            Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning, RequiredSecurityProperties | Format-List
        "BENCHMARK: Secure Boot must be enabled on all UEFI systems."
    }},

    @{ N = 40; Title = 'Scheduled Tasks Review'; Code = {
        "Enabled scheduled tasks and the commands they execute (review for anything unrecognised):"
        Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
            $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
            [PSCustomObject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                State    = $_.State
                RunAs    = $_.Principal.UserId
                Actions  = $actions
            }
        } | Sort-Object TaskPath, TaskName | Format-Table -AutoSize -Wrap
    }},

    @{ N = 41; Title = 'Application Control / Allowlisting'; Code = {
        "AppLocker effective policy (if configured):"
        $policy = Get-AppLockerPolicy -Effective
        if ($policy -and $policy.RuleCollections.Count -gt 0) {
            $policy.RuleCollections | Format-Table -AutoSize -Wrap
        } else {
            "No effective AppLocker policy found on this host."
        }
        ""
        "Application Identity service (required for AppLocker enforcement):"
        Get-Service AppIDSvc | Select-Object Name, Status, StartType | Format-Table -AutoSize
        ""
        "Windows Defender Application Control (WDAC) / Code Integrity enforcement status:"
        Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard |
            Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus | Format-List
        "Legend: 0 = Off, 1 = Audit mode, 2 = Enforced"
        ""
        "SmartScreen:"
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue |
            Select-Object SmartScreenEnabled | Format-List
    }}
)

# ==================================================================
# RUN ALL CHECKPOINTS IN ORDER
# ==================================================================
$total = $Checks.Count
$i     = 0

foreach ($check in $Checks) {
    $i++
    Write-Progress -Activity 'Endpoint Compliance Audit' `
                   -Status "Checkpoint $($check.N) of $total : $($check.Title)" `
                   -PercentComplete (($i / $total) * 100)

    $content = Invoke-SafeBlock -Block $check.Code
    New-CheckReport -Number $check.N -Title $check.Title -Content $content
}

Write-Progress -Activity 'Endpoint Compliance Audit' -Completed

# Report any checkpoint that produced no data or contains errors
$empty = $Global:AllResults | Where-Object { $_.Content -match 'No data returned' }
if ($empty) {
    Write-Host ""
    Write-Host "[!] $(@($empty).Count) checkpoint(s) returned no data:" -ForegroundColor Yellow
    $empty | ForEach-Object { Write-Host ("    {0:D2} {1}" -f $_.Number, $_.Title) -ForegroundColor Yellow }
}
$errored = $Global:AllResults | Where-Object { $_.Content -match 'Could not complete check|Exception|CategoryInfo' }
if ($errored) {
    Write-Host "[!] Checkpoint(s) containing errors (see the .txt files):" -ForegroundColor Yellow
    $errored | ForEach-Object { Write-Host ("    {0:D2} {1}" -f $_.Number, $_.Title) -ForegroundColor Yellow }
}

# ==================================================================
# BUILD COMPREHENSIVE REPORT (same 1 -> 41 order)
# ==================================================================
Write-Host ""
Write-Host "Building comprehensive report..." -ForegroundColor Cyan

$comprehensiveName = "00_COMPREHENSIVE_REPORT_${ComputerName}_${IPv4Safe}_${Timestamp}.txt"
$comprehensivePath = Join-Path -Path $BasePath -ChildPath $comprehensiveName

$sorted = $Global:AllResults | Sort-Object Number
$toc = ($sorted | ForEach-Object { "  {0,2}. {1,-45} [{2}]" -f $_.Number, $_.Title, $_.FileName }) -join "`r`n"

$reportHeader = @"
==================================================================
COMPREHENSIVE ENDPOINT SECURITY COMPLIANCE AUDIT REPORT
==================================================================
Computer Name : $ComputerName
IPv4 Address  : $IPv4
Audited User  : $CurrentUser
Generated     : $RunDateTime
Run as Admin  : $IsAdmin
Output Folder : $BasePath
Total Checks  : $(@($sorted).Count) / 41
==================================================================

Frameworks referenced: CIS Critical Security Controls v8.1,
ISO/IEC 27001:2022, NIST SP 800-53 Rev. 5.

This report consolidates every checkpoint result below, in the same
order as the individual files in this folder.

------------------------------------------------------------------
TABLE OF CONTENTS
------------------------------------------------------------------
$toc
------------------------------------------------------------------


"@

$reportHeader | Out-File -FilePath $comprehensivePath -Encoding UTF8 -Force
foreach ($result in $sorted) { $result.Content | Out-File -FilePath $comprehensivePath -Encoding UTF8 -Append }

@"

==================================================================
END OF REPORT - $ComputerName ($IPv4) - $RunDateTime
==================================================================
"@ | Out-File -FilePath $comprehensivePath -Encoding UTF8 -Append

# ==================================================================
# SUMMARY
# ==================================================================
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " AUDIT COMPLETE" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Computer            : $ComputerName"
Write-Host " IPv4                : $IPv4"
Write-Host " Checks completed    : $(@($sorted).Count) / 41"
Write-Host " Output folder       : $BasePath"
Write-Host " Individual reports  : 01_*.txt ... 41_*.txt"
Write-Host " Comprehensive report: $comprehensiveName" -ForegroundColor Green
Write-Host " Run log             : 00_RunLog.txt"
Write-Host "==================================================================" -ForegroundColor Cyan

try { Stop-Transcript | Out-Null } catch { }
try { Start-Process explorer.exe -ArgumentList "`"$BasePath`"" -ErrorAction SilentlyContinue } catch { }

if ($Elevated) { Read-Host "Press Enter to close" | Out-Null }
