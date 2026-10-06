<#
.SYNOPSIS
    Captures Windows security screenshots (Windows Security app, Windows Update /
    activation / encryption / sign-in settings, Defender Firewall, Remote access,
    Task Scheduler) PLUS the complete installed programs list.

.DESCRIPTION
    Saves one PNG per page into an evidence folder created INSIDE THE FOLDER THE
    SCRIPT IS RUN FROM, named after the PC, its IPv4 address and the run time:

        <script folder>\SecurityAudit_PC-ACCOUNTS01_192.168.1.25_2026-10-06_14-30-05

    File numbers: 01-23, 39, 48, 53 (as in the original run), plus:
        54  Programs and Features window (screenshot)
        55  Settings > Installed apps page (screenshot)
        56  COMPLETE installed programs list rendered to PNG page(s)
            (every program, not just what fits on screen) + CSV + TXT copy

    Duplicate protection: each PNG is SHA-256 hashed; identical captures are
    retried, then deleted and logged as SKIPPED. Missing windows are SKIPPED.

.NOTES
    - Run in an interactive, ELEVATED PowerShell session on the logged-in desktop.
    - Do not use the mouse or keyboard while it runs.

.PARAMETER OutputRoot
    Root folder for the evidence subfolder. Default: the folder containing this script.

.PARAMETER WaitSeconds
    Seconds to wait after a window appears so the UI finishes rendering.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File "C:\Users\ZOHAIB\Downloads\Capture-WindowsSecurityAudit-Selected.ps1"
#>

param(
    [string]$OutputRoot = "",
    [int]$WaitSeconds = 3,
    [switch]$Elevated          # internal: set when the script relaunches itself as Administrator
)

# ---------------------------------------------------------------------------
# Bootstrap: resolve output folder, execution policy and elevation
# ---------------------------------------------------------------------------

$scriptPath = $PSCommandPath

# Default output = the folder the script is in (fallback: current directory)
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    if ($PSScriptRoot)      { $OutputRoot = $PSScriptRoot }
    elseif ($scriptPath)    { $OutputRoot = Split-Path -Parent $scriptPath }
    else                    { $OutputRoot = (Get-Location).Path }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 1) Not elevated? Relaunch this same script as Administrator with Bypass.
if (-not $isAdmin -and -not $Elevated -and $scriptPath) {
    Write-Host "Not elevated - relaunching as Administrator with -ExecutionPolicy Bypass..." -ForegroundColor Yellow
    $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" " +
                    "-OutputRoot `"$OutputRoot`" -WaitSeconds $WaitSeconds -Elevated"
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $relaunchArgs -Verb RunAs -ErrorAction Stop
        exit
    } catch {
        Write-Warning "Elevation was declined - continuing without Administrator rights."
    }
}

# 2) Bypass for this session so nothing in the run is blocked.
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch { }

# 3) Remove the "downloaded from the internet" mark from this script.
if ($scriptPath) { Unblock-File -Path $scriptPath -ErrorAction SilentlyContinue }

# 4) Force the persistent policy to RemoteSigned.
try {
    if ($isAdmin) { Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop }
    else          { Set-ExecutionPolicy -Scope CurrentUser  -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop }
    Write-Host "Execution policy set to RemoteSigned." -ForegroundColor Green
} catch {
    Write-Warning "Could not set RemoteSigned (a Group Policy may be enforcing a policy): $($_.Exception.Message)"
}
Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String | Write-Host

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Win32Audit {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetWindowText(IntPtr h, StringBuilder s, int max);

    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    public static IntPtr FindByTitle(string title, bool exact) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            if (!IsWindowVisible(h)) return true;
            int len = GetWindowTextLength(h);
            if (len == 0) return true;
            StringBuilder sb = new StringBuilder(len + 1);
            GetWindowText(h, sb, sb.Capacity);
            string t = sb.ToString();
            bool match = exact
                ? string.Equals(t, title, StringComparison.OrdinalIgnoreCase)
                : t.IndexOf(title, StringComparison.OrdinalIgnoreCase) >= 0;
            if (match) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

[void][Win32Audit]::SetProcessDPIAware()

if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some windows may trigger UAC prompts."
}

function Get-PrimaryIPv4 {
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop |
               Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
               Select-Object -First 1
        if ($cfg -and $cfg.IPv4Address) { return @($cfg.IPv4Address)[0].IPAddress }

        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
              Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
              Select-Object -First 1
        if ($ip) { return $ip.IPAddress }
    } catch { }
    return "NoIPv4"
}

$pcName    = $env:COMPUTERNAME
$ipv4      = Get-PrimaryIPv4
$runTime   = Get-Date
$timestamp = $runTime.ToString("yyyy-MM-dd_HH-mm-ss")

$folderName  = "SecurityAudit_{0}_{1}_{2}" -f $pcName, $ipv4, $timestamp
$folderName  = $folderName -replace '[^\w\.\-]', '_'
$evidenceDir = Join-Path $OutputRoot $folderName
New-Item -Path $evidenceDir -ItemType Directory -Force | Out-Null

Write-Host "PC name:         $pcName"      -ForegroundColor Cyan
Write-Host "IPv4 address:    $ipv4"        -ForegroundColor Cyan
Write-Host "Evidence folder: $evidenceDir" -ForegroundColor Cyan

$script:hashes  = @{}
$script:results = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Add-Result {
    param([string]$Label, [string]$Status, [string]$Detail = "")
    $script:results.Add([pscustomobject]@{ Label = $Label; Status = $Status; Detail = $Detail })
}

function Stop-Leftovers {
    foreach ($n in "SecHealthUI", "SystemSettings", "SystemPropertiesRemote", "mmc") {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
}

function Wait-ForWindow {
    param([string]$Title, [bool]$Exact, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $h = [Win32Audit]::FindByTitle($Title, $Exact)
        if ($h -ne [IntPtr]::Zero) { return $h }
        Start-Sleep -Milliseconds 400
    }
    return [IntPtr]::Zero
}

function Save-Window {
    param([IntPtr]$hWnd, [string]$Path)

    [void][Win32Audit]::ShowWindow($hWnd, 3)          # SW_MAXIMIZE
    Start-Sleep -Milliseconds 500
    [void][Win32Audit]::SetForegroundWindow($hWnd)
    Start-Sleep -Milliseconds 700

    $rect = New-Object Win32Audit+RECT
    [void][Win32Audit]::GetWindowRect($hWnd, [ref]$rect)
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top
    if ($w -le 0 -or $h -le 0) { return $false }

    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bmp.Size)
    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    return $true
}

function Capture-Item {
    param(
        [int]$Number,
        [string]$Name,
        [string]$Target,
        [string]$Arguments = "",
        [string]$Title,
        [bool]$Exact = $true,
        [int]$TimeoutSeconds = 20
    )

    $Label = "{0:D2}_{1}" -f $Number, $Name

    Write-Host "Capturing: $Label" -ForegroundColor Yellow
    Stop-Leftovers

    if ($Arguments) { Start-Process -FilePath $Target -ArgumentList $Arguments -ErrorAction SilentlyContinue }
    else            { Start-Process -FilePath $Target -ErrorAction SilentlyContinue }

    $hWnd = Wait-ForWindow -Title $Title -Exact $Exact -TimeoutSeconds $TimeoutSeconds
    if ($hWnd -eq [IntPtr]::Zero) {
        Write-Warning "  Window '$Title' never appeared - SKIPPED."
        Add-Result $Label "SKIPPED" "Window '$Title' not found"
        return
    }

    Start-Sleep -Seconds $WaitSeconds
    $file = Join-Path $evidenceDir "$Label.png"

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if (-not (Save-Window -hWnd $hWnd -Path $file)) {
            Write-Warning "  Could not read window bounds - SKIPPED."
            Add-Result $Label "SKIPPED" "Invalid window bounds"
            break
        }

        $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
        if ($script:hashes.ContainsKey($hash)) {
            if ($attempt -lt 3) {
                Start-Sleep -Seconds 2
                continue
            }
            $dupOf = $script:hashes[$hash]
            Remove-Item $file -Force -ErrorAction SilentlyContinue
            Write-Warning "  Identical to '$dupOf' - duplicate removed."
            Add-Result $Label "SKIPPED" "Duplicate of $dupOf"
            break
        }

        $script:hashes[$hash] = $Label
        Write-Host "  Saved: $file" -ForegroundColor Green
        Add-Result $Label "OK" "$Label.png"
        break
    }

    [void][Win32Audit]::PostMessage($hWnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)   # WM_CLOSE
}

function Save-InstalledProgramsList {
    # Reads every installed program from the registry (same source as Programs and
    # Features) and renders the COMPLETE list to one or more PNG pages, plus CSV/TXT.
    param([int]$Number = 56, [int]$RowsPerPage = 40)

    $base = "{0:D2}_Installed_Programs_Complete_List" -f $Number
    Write-Host "Building: $base" -ForegroundColor Yellow

    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $apps = @(Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
        Select-Object @{n='Name';e={$_.DisplayName}},
                      @{n='Version';e={$_.DisplayVersion}},
                      @{n='Publisher';e={$_.Publisher}},
                      @{n='InstallDate';e={$_.InstallDate}} |
        Sort-Object Name, Version -Unique)

    if ($apps.Count -eq 0) {
        Write-Warning "  No installed programs found - SKIPPED."
        Add-Result $base "SKIPPED" "No programs found in registry"
        return
    }

    # CSV + TXT copies of the same list
    $csvPath = Join-Path $evidenceDir "$base.csv"
    $txtPath = Join-Path $evidenceDir "$base.txt"
    $apps | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $apps | Format-Table -AutoSize -Wrap | Out-String -Width 400 | Out-File -FilePath $txtPath -Encoding UTF8

    # Render PNG pages
    $pages   = [int][math]::Ceiling($apps.Count / $RowsPerPage)
    $width   = 1800
    $rowH    = 26
    $headerH = 100
    $footerH = 20
    $fontTitle = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $fontInfo  = New-Object System.Drawing.Font("Segoe UI", 10)
    $fontHead  = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $fontRow   = New-Object System.Drawing.Font("Segoe UI", 11)
    $fmt = New-Object System.Drawing.StringFormat
    $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
    $fmt.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap

    $colX = @(20, 800, 1030, 1570)
    $colW = @(770, 220, 530, 210)

    for ($p = 0; $p -lt $pages; $p++) {
        $slice = @($apps | Select-Object -Skip ($p * $RowsPerPage) -First $RowsPerPage)
        $height = $headerH + ($slice.Count + 1) * $rowH + $footerH
        $bmp = New-Object System.Drawing.Bitmap $width, $height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.Clear([System.Drawing.Color]::White)
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $black = [System.Drawing.Brushes]::Black
        $g.DrawString("Installed Programs - Complete List", $fontTitle, $black, 20, 8)
        $info = "Computer: $pcName   IPv4: $ipv4   Generated: $runTime   Total programs: $($apps.Count)   Page $($p+1) of $pages"
        $g.DrawString($info, $fontInfo, $black, 22, 48)

        $y = $headerH - 4
        $g.FillRectangle((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(225,232,245))), 0, $y, $width, $rowH)
        $heads = @("Name", "Version", "Publisher", "Install date")
        for ($c = 0; $c -lt 4; $c++) {
            $g.DrawString($heads[$c], $fontHead, $black, (New-Object System.Drawing.RectangleF($colX[$c], ($y+3), $colW[$c], $rowH)), $fmt)
        }
        $y += $rowH

        $alt = $false
        foreach ($a in $slice) {
            if ($alt) { $g.FillRectangle((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(245,245,245))), 0, $y, $width, $rowH) }
            $alt = -not $alt
            $vals = @([string]$a.Name, [string]$a.Version, [string]$a.Publisher, [string]$a.InstallDate)
            for ($c = 0; $c -lt 4; $c++) {
                $g.DrawString($vals[$c], $fontRow, $black, (New-Object System.Drawing.RectangleF($colX[$c], ($y+3), $colW[$c], $rowH)), $fmt)
            }
            $y += $rowH
        }

        $pageName = if ($pages -gt 1) { "{0}_Page{1:D2}of{2:D2}.png" -f $base, ($p+1), $pages } else { "$base.png" }
        $out = Join-Path $evidenceDir $pageName
        $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
        Write-Host "  Saved: $out" -ForegroundColor Green
        Add-Result ($pageName -replace '\.png$','') "OK" "$pageName ($($slice.Count) programs)"
    }

    Add-Result "$base (CSV/TXT)" "OK" "$($apps.Count) programs total"
}

# ---------------------------------------------------------------------------
# Capture set 1: Windows Security app pages (01-12)
# ---------------------------------------------------------------------------

$securityPages = @(
    @{ Number = 1;  Name = "Windows_Security_Home";             Uri = "windowsdefender:" },
    @{ Number = 2;  Name = "Virus_And_Threat_Protection";       Uri = "windowsdefender://threat" },
    @{ Number = 3;  Name = "Virus_Threat_Protection_Settings";  Uri = "windowsdefender://threatsettings" },
    @{ Number = 4;  Name = "Protection_History";                Uri = "windowsdefender://history" },
    @{ Number = 5;  Name = "Account_Protection";                Uri = "windowsdefender://account" },
    @{ Number = 6;  Name = "Firewall_And_Network_Protection";   Uri = "windowsdefender://network" },
    @{ Number = 7;  Name = "App_And_Browser_Control";           Uri = "windowsdefender://appbrowser" },
    @{ Number = 8;  Name = "Device_Security";                   Uri = "windowsdefender://devicesecurity" },
    @{ Number = 9;  Name = "Core_Isolation_Memory_Integrity";   Uri = "windowsdefender://coreisolation" },
    @{ Number = 10; Name = "Security_Processor_TPM";            Uri = "windowsdefender://securityprocessor" },
    @{ Number = 11; Name = "Device_Performance_And_Health";     Uri = "windowsdefender://deviceperformance" },
    @{ Number = 12; Name = "Family_Options";                    Uri = "windowsdefender://family" }
)

foreach ($p in $securityPages) {
    Capture-Item -Number $p.Number -Name $p.Name -Target $p.Uri -Title "Windows Security" -Exact $true
}

# ---------------------------------------------------------------------------
# Capture set 2: Settings app pages (13-23)
# ---------------------------------------------------------------------------

$settingsPages = @(
    @{ Number = 13; Name = "Windows_Update_Status";            Uri = "ms-settings:windowsupdate" },
    @{ Number = 14; Name = "Windows_Update_History";           Uri = "ms-settings:windowsupdate-history" },
    @{ Number = 15; Name = "Windows_Update_Advanced_Options";  Uri = "ms-settings:windowsupdate-options" },
    @{ Number = 16; Name = "Windows_Update_Optional_Updates";  Uri = "ms-settings:windowsupdate-optionalupdates" },
    @{ Number = 17; Name = "Delivery_Optimization";            Uri = "ms-settings:delivery-optimization" },
    @{ Number = 18; Name = "Windows_Activation_Status";        Uri = "ms-settings:activation" },
    @{ Number = 19; Name = "About_Windows_Version_Build";      Uri = "ms-settings:about" },
    @{ Number = 20; Name = "Device_Encryption";                Uri = "ms-settings:deviceencryption" },
    @{ Number = 21; Name = "Sign_In_Options";                  Uri = "ms-settings:signinoptions" },
    @{ Number = 22; Name = "Lock_Screen";                      Uri = "ms-settings:lockscreen" },
    @{ Number = 23; Name = "Power_And_Sleep_Screen_Timeout";   Uri = "ms-settings:powersleep" }
)

foreach ($p in $settingsPages) {
    Capture-Item -Number $p.Number -Name $p.Name -Target $p.Uri -Title "Settings" -Exact $true
}

# ---------------------------------------------------------------------------
# Capture set 3: Classic Windows tools (39, 48, 53)
# ---------------------------------------------------------------------------

Capture-Item -Number 39 -Name "Defender_Firewall_Control_Panel" `
             -Target "control.exe" -Arguments "firewall.cpl" `
             -Title "Windows Defender Firewall" -Exact $true

Capture-Item -Number 48 -Name "Remote_Access_System_Properties" `
             -Target "SystemPropertiesRemote.exe" `
             -Title "System Properties" -Exact $true

Capture-Item -Number 53 -Name "Task_Scheduler_Persistence_Check" `
             -Target "taskschd.msc" `
             -Title "Task Scheduler" -Exact $false

# ---------------------------------------------------------------------------
# Capture set 4: Installed programs (54-56)
# ---------------------------------------------------------------------------

# 54: classic Programs and Features window
Capture-Item -Number 54 -Name "Programs_And_Features" `
             -Target "control.exe" -Arguments "appwiz.cpl" `
             -Title "Programs and Features" -Exact $true

# 55: Settings > Apps > Installed apps
Capture-Item -Number 55 -Name "Installed_Apps_Settings" `
             -Target "ms-settings:appsfeatures" `
             -Title "Settings" -Exact $true

# 56: complete list (every program, rendered across as many pages as needed)
Save-InstalledProgramsList -Number 56

Stop-Leftovers

# ---------------------------------------------------------------------------
# Summary file
# ---------------------------------------------------------------------------

$summaryPath = Join-Path $evidenceDir "00_Summary.txt"

$summary = @"
Windows Security Audit - Selected Screenshots
Generated:  $runTime
Computer:   $pcName
IPv4:       $ipv4
User:       $env:USERDOMAIN\$env:USERNAME
Elevated:   $isAdmin
Folder:     $evidenceDir

---- Screenshot Results (OK / SKIPPED) ----
$($script:results | Format-Table -AutoSize -Wrap | Out-String)
"@

$summary | Out-File -FilePath $summaryPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

$ok      = @($script:results | Where-Object Status -eq "OK").Count
$skipped = @($script:results | Where-Object Status -eq "SKIPPED").Count

Write-Host ""
Write-Host "Audit capture complete: $ok item(s) saved, $skipped skipped." -ForegroundColor Cyan
Write-Host "Evidence folder: $evidenceDir" -ForegroundColor Cyan
Write-Host "Summary file:    $summaryPath" -ForegroundColor Cyan

if ($Elevated) { Read-Host "Press Enter to close" | Out-Null }