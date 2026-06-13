rule TRASHcan_PowerShell_EncodedCommand_Artifacts
{
    meta:
        description = "Flags common encoded PowerShell execution artifacts in dropped files or scripts"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "powershell"

    strings:
        $ps1 = "powershell -enc" ascii wide nocase
        $ps2 = "powershell.exe -encodedcommand" ascii wide nocase
        $ps3 = "FromBase64String(" ascii wide nocase
        $ps4 = "IEX(" ascii wide nocase
        $ps5 = "DownloadString(" ascii wide nocase

    condition:
        3 of ($ps*)
}

rule TRASHcan_Windows_LOLBIN_Dropper_Artifacts
{
    meta:
        description = "Flags common Windows LOLBIN downloader and script execution patterns"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "lolbin"

    strings:
        $lol1 = "certutil -urlcache -f" ascii wide nocase
        $lol2 = "bitsadmin /transfer" ascii wide nocase
        $lol3 = "mshta http" ascii wide nocase
        $lol4 = "regsvr32 /s /n /u /i:http" ascii wide nocase
        $lol5 = "rundll32 javascript:" ascii wide nocase

    condition:
        2 of ($lol*)
}

rule TRASHcan_Ransomware_Disruption_Artifacts
{
    meta:
        description = "Flags common shadow copy and recovery disruption commands seen in ransomware"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "ransomware"

    strings:
        $ran1 = "vssadmin delete shadows" ascii wide nocase
        $ran2 = "wmic shadowcopy delete" ascii wide nocase
        $ran3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $ran4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $ran5 = "wbadmin delete catalog" ascii wide nocase

    condition:
        2 of ($ran*)
}

rule TRASHcan_Remote_Access_Tool_Artifacts
{
    meta:
        description = "Flags common remote-access and tunnel tooling artifacts"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "remote-access"

    strings:
        $rat1 = "AnyDesk" ascii wide nocase
        $rat2 = "RustDesk" ascii wide nocase
        $rat3 = "ScreenConnect.ClientService" ascii wide nocase
        $rat4 = "ngrok" ascii wide nocase
        $rat5 = "tailscale up" ascii wide nocase

    condition:
        2 of ($rat*)
}

rule TRASHcan_Credential_Access_Artifacts
{
    meta:
        description = "Flags common credential-access tooling and LSASS targeting strings"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "credential-access"

    strings:
        $cred1 = "Mimikatz" ascii wide nocase
        $cred2 = "sekurlsa::logonpasswords" ascii wide nocase
        $cred3 = "lsadump::sam" ascii wide nocase
        $cred4 = "comsvcs.dll, MiniDump" ascii wide nocase
        $cred5 = "lsass.exe" ascii wide nocase

    condition:
        2 of ($cred*)
}

rule TRASHcan_Stealer_Exfil_Artifacts
{
    meta:
        description = "Flags strings commonly seen in browser-data and wallet stealer exfil workflows"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "stealer"

    strings:
        $st1 = "Login Data" ascii wide nocase
        $st2 = "Cookies" ascii wide nocase
        $st3 = "wallet.dat" ascii wide nocase
        $st4 = "discord webhook" ascii wide nocase
        $st5 = "tdata" ascii wide nocase

    condition:
        3 of ($st*)
}

rule TRASHcan_Loader_Stager_Artifacts
{
    meta:
        description = "Flags generic loader and staging command artifacts"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "loader"

    strings:
        $ld1 = "Start-BitsTransfer" ascii wide nocase
        $ld2 = "URLDownloadToFile" ascii wide nocase
        $ld3 = "VirtualAlloc" ascii wide nocase
        $ld4 = "CreateThread" ascii wide nocase
        $ld5 = "WriteProcessMemory" ascii wide nocase

    condition:
        3 of ($ld*)
}

rule TRASHcan_Ransomware_Note_Artifacts
{
    meta:
        description = "Flags common ransom-note and encryption status artifacts"
        author = "RAIccoon local sandbox"
        date = "2026-06-13"
        category = "ransomware-note"

    strings:
        $rn1 = "README.txt" ascii wide nocase
        $rn2 = "RECOVER" ascii wide nocase
        $rn3 = "Your files are encrypted" ascii wide nocase
        $rn4 = "decryptor" ascii wide nocase
        $rn5 = "TOX" ascii wide nocase

    condition:
        3 of ($rn*)
}
