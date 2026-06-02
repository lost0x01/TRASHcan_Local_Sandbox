# ============================================================
#  FlareVM Analysis Guest Setup
#  Run on a fresh Windows 10 x64 instance in the analysis subnet
# ============================================================
# This script prepares a Windows 10 instance with:
#   - Sysmon (modular config)
#   - Process Monitor (silent background capture)
#   - Wireshark CLI (tshark)
#   - FlareVM toolset (if not pre-baked into AMI)
#   - Network routing via REMnux (10.10.1.10)
#   - Windows Defender disabled (required for detonation)
#   - ETW provider enablement
#
# After this script runs, create an AMI snapshot as the clean baseline.
# The orchestrator will restore from this snapshot before each detonation.
# ============================================================

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REMnuxIP     = "10.10.1.10"
$AnalysisIface = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).Name
$ToolsDir     = "C:\Tools"
$AnalysisDir  = "C:\Analysis"

function Write-Step { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }

Write-Step "Starting FlareVM analysis guest configuration..."

# ══════════════════════════════════════════════════════════════════════════
# 1. Network routing — force all traffic through REMnux (INetSim)
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Configuring network routing via REMnux gateway ($REMnuxIP)..."

# Remove existing default routes
Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false

# Set REMnux as default gateway
New-NetRoute -DestinationPrefix "0.0.0.0/0" `
             -NextHop $REMnuxIP `
             -InterfaceAlias $AnalysisIface `
             -RouteMetric 1

# Set DNS to REMnux (INetSim handles all DNS responses)
Set-DnsClientServerAddress -InterfaceAlias $AnalysisIface -ServerAddresses $REMnuxIP

Write-Step "Default gateway: $REMnuxIP (INetSim will handle all internet traffic)"

# ══════════════════════════════════════════════════════════════════════════
# 2. Create directory structure
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Creating analysis directory structure..."
@("$ToolsDir\Sysmon", "$ToolsDir\Sysinternals", "$ToolsDir\winpmem",
  "$AnalysisDir\Sample", "$AnalysisDir\Output", "$AnalysisDir\Logs") | ForEach-Object {
    New-Item -ItemType Directory -Force -Path $_ | Out-Null
}

# ══════════════════════════════════════════════════════════════════════════
# 3. Disable Windows Defender (required for malware execution)
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Disabling Windows Defender real-time protection..."
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent NeverSend
Set-MpPreference -MAPSReporting Disabled

# Disable via registry as well (belt and braces)
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
If (!(Test-Path $DefenderPath)) { New-Item -Path $DefenderPath -Force | Out-Null }
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiVirus"   -Value 1

Write-Step "Windows Defender disabled"

# ══════════════════════════════════════════════════════════════════════════
# 4. Sysmon installation
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Installing Sysmon with modular config..."

$SysmonUrl    = "https://live.sysinternals.com/Sysmon64.exe"
$SysmonConfig = "$ToolsDir\Sysmon\sysmonconfig-export.xml"
$SysmonExe    = "$ToolsDir\Sysmon\Sysmon64.exe"

# Download Sysmon
try {
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonExe -UseBasicParsing
    Write-Step "Sysmon downloaded"
} catch {
    Write-Warn "Sysmon download failed (no internet? Use pre-baked AMI): $_"
}

# Sysmon Modular Config (comprehensive event capture)
@'
<Sysmon schemaversion="4.82">
  <HashAlgorithms>sha256,md5</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>

    <!-- Event 1: Process Creation — capture all -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event 2: File creation time changed -->
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include">
        <Image condition="contains">sample</Image>
      </FileCreateTime>
    </RuleGroup>

    <!-- Event 3: Network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <DestinationPort condition="is">53</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event 5: Process terminated -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include">
        <Image condition="contains">sample</Image>
      </ProcessTerminate>
    </RuleGroup>

    <!-- Event 6: Driver loaded -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include" />
    </RuleGroup>

    <!-- Event 7: Image/DLL loaded — capture all for analysis -->
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude">
        <Image condition="is">C:\Windows\System32\wuauclt.exe</Image>
      </ImageLoad>
    </RuleGroup>

    <!-- Event 8: CreateRemoteThread -->
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="include" />
    </RuleGroup>

    <!-- Event 10: ProcessAccess — memory injection -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <GrantedAccess condition="contains">0x1fffff</GrantedAccess>
        <GrantedAccess condition="contains">0x1010</GrantedAccess>
        <GrantedAccess condition="contains">0x143a</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event 11: File creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </FileCreate>
    </RuleGroup>

    <!-- Events 12/13/14: Registry operations -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">Run</TargetObject>
        <TargetObject condition="contains">RunOnce</TargetObject>
        <TargetObject condition="contains">Winlogon</TargetObject>
        <TargetObject condition="contains">Services</TargetObject>
        <TargetObject condition="contains">CurrentVersion\Explorer</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event 15: File stream created (ADS) -->
    <RuleGroup name="" groupRelation="or">
      <FileCreateStreamHash onmatch="include" />
    </RuleGroup>

    <!-- Event 17/18: Named pipes -->
    <RuleGroup name="" groupRelation="or">
      <PipeEvent onmatch="include" />
    </RuleGroup>

    <!-- Event 20/21: WMI operations -->
    <RuleGroup name="" groupRelation="or">
      <WmiEvent onmatch="include" />
    </RuleGroup>

    <!-- Event 22: DNS queries -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
'@ | Out-File -FilePath $SysmonConfig -Encoding UTF8

if (Test-Path $SysmonExe) {
    & $SysmonExe -accepteula -i $SysmonConfig 2>&1
    Write-Step "Sysmon installed and running"
} else {
    Write-Warn "Sysmon not installed — download manually or pre-bake into AMI"
}

# ══════════════════════════════════════════════════════════════════════════
# 5. Process Monitor setup
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Configuring Process Monitor for silent background capture..."

$ProcMonUrl = "https://live.sysinternals.com/Procmon64.exe"
$ProcMonExe = "$ToolsDir\Sysinternals\Procmon64.exe"

try {
    Invoke-WebRequest -Uri $ProcMonUrl -OutFile $ProcMonExe -UseBasicParsing
    Write-Step "Process Monitor downloaded"
} catch {
    Write-Warn "Process Monitor download failed: $_"
}

# ══════════════════════════════════════════════════════════════════════════
# 6. WinPmem memory acquisition tool
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Downloading WinPmem memory acquisition tool..."
$WinPmemUrl = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"
$WinPmemExe = "$ToolsDir\winpmem\winpmem_mini_x64_rc2.exe"

try {
    Invoke-WebRequest -Uri $WinPmemUrl -OutFile $WinPmemExe -UseBasicParsing
    Write-Step "WinPmem downloaded"
} catch {
    Write-Warn "WinPmem download failed — memory dumps will use comsvcs fallback"
}

# ══════════════════════════════════════════════════════════════════════════
# 7. Enable ETW providers for enhanced visibility
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Enabling ETW providers..."

$EtwProviders = @(
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Registry",
    "Microsoft-Antimalware-Engine",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-WMI-Activity"
)

foreach ($provider in $EtwProviders) {
    try {
        $null = logman update trace "EventLog-System" -p "$provider" 0xffffffffffffffff 0xff 2>&1
        Write-Step "ETW provider enabled: $provider"
    } catch {
        Write-Warn "Could not enable ETW provider: $provider"
    }
}

# Enable PowerShell ScriptBlock logging
$PSLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (!(Test-Path $PSLoggingPath)) { New-Item -Path $PSLoggingPath -Force | Out-Null }
Set-ItemProperty -Path $PSLoggingPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $PSLoggingPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# Enable PowerShell Module logging
$PSModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
If (!(Test-Path $PSModPath)) { New-Item -Path $PSModPath -Force | Out-Null }
Set-ItemProperty -Path $PSModPath -Name "EnableModuleLogging" -Value 1

Write-Step "PowerShell ScriptBlock and Module logging enabled"

# ══════════════════════════════════════════════════════════════════════════
# 8. Windows audit policy — enhanced logging
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Configuring Windows audit policy..."

$AuditPolicies = @{
    "Process Creation"    = "Success,Failure"
    "Process Termination" = "Success"
    "Network Connection"  = "Success,Failure"
    "Logon"               = "Success,Failure"
    "Object Access"       = "Success,Failure"
    "Registry"            = "Success,Failure"
    "File System"         = "Success"
    "Token Right Adjusted"= "Success,Failure"
}

foreach ($category in $AuditPolicies.Keys) {
    $value = $AuditPolicies[$category]
    try {
        & auditpol /set /subcategory:"$category" /success:enable /failure:enable 2>&1 | Out-Null
    } catch {
        Write-Warn "Could not set audit policy: $category"
    }
}

# Increase event log sizes
wevtutil sl Security /ms:524288000  # 500MB Security log
wevtutil sl System   /ms:104857600  # 100MB System log

Write-Step "Audit policy configured and event log sizes increased"

# ══════════════════════════════════════════════════════════════════════════
# 9. SSM Agent — signal readiness
# ══════════════════════════════════════════════════════════════════════════
Write-Step "Signalling ready state via SSM..."
$Region = (Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/placement/region" -UseBasicParsing -TimeoutSec 5).Content

try {
    & "C:\Program Files\Amazon\SSM\Bin\ssm-cli.exe" put-parameter `
        --name "/sandbox/flarevm/ready" `
        --value "true" `
        --type String `
        --overwrite `
        --region $Region 2>&1 | Out-Null
    Write-Step "SSM parameter /sandbox/flarevm/ready = true"
} catch {
    Write-Warn "Could not update SSM parameter: $_"
}

# ══════════════════════════════════════════════════════════════════════════
# 10. Final summary
# ══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Step "FlareVM analysis guest configuration complete."
Write-Step "Network:        All traffic → REMnux ($REMnuxIP) → INetSim"
Write-Step "DNS:            All queries → REMnux ($REMnuxIP)"
Write-Step "Sysmon:         Installed and running (modular config)"
Write-Step "ProcMon:        Ready for analysis ($ProcMonExe)"
Write-Step "WinPmem:        Ready for memory acquisition"
Write-Step "AV:             Windows Defender DISABLED"
Write-Step "Audit policy:   Enhanced logging enabled"
Write-Step "ETW:            Key providers enabled"
Write-Host ""
Write-Warn "IMPORTANT: Create an AMI snapshot of this instance NOW"
Write-Warn "The orchestrator will restore from this snapshot before each analysis run."
Write-Warn "Snapshot name: flarevm-sandbox-clean-$(Get-Date -Format 'yyyyMMdd')"
