# ==============================
# Detect-UserAssistServiceNowAcl.ps1
# ==============================

$ErrorActionPreference = 'Stop'
$ServiceNowAccount = 'servicenow'

# Root + BackupDir (Logs)
$root = "C:\ProgramData\UserAssistACL" # Kan ändra path om kund önskar
$BackupDir = Join-Path $Root 'Logs'
$LogFile = Join-Path $BackupDir 'UserAssistAcl.log'

if (-not (Test-Path $BackupDir)) {
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO','CHANGE','ERROR')]
        [string]$Level = 'INFO'
    )

    try {
        $Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Add-Content -Path $LogFile -Value "$Time [$Level] $Message"
    } catch {}
}

Write-Log "Detection started."

# Resolve ServiceNow SID
try {
    $ServiceNowSid = (New-Object System.Security.Principal.NTAccount($ServiceNowAccount)).
        Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Log "Resolved ServiceNow SID: $ServiceNowSid"
}
catch {
    Write-Log "Failed to resolve ServiceNow SID." 'ERROR'
    exit 1
}

$NonCompliant = $false

# Enumerate user hives
try {
    $UserSids = Get-ChildItem Registry::HKEY_USERS | Where-Object {
        ($_.PSChildName -match '^S-1-5-21-' -or $_.PSChildName -match '^S-1-12-1-') -and
        ($_.PSChildName -notmatch '_Classes$')
    }
    Write-Log "Enumerated $($UserSids.Count) user hives."
}
catch {
    Write-Log "Failed to enumerate HKEY_USERS." 'ERROR'
    exit 1
}

foreach ($Sid in $UserSids) {

    $UserAssistPath = "Registry::HKEY_USERS\$($Sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

    if (-not (Test-Path $UserAssistPath)) {
        Write-Log "UserAssist missing for $($Sid.PSChildName)."
        continue
    }

    try {
        $Acl = Get-Acl $UserAssistPath
    }
    catch {
        Write-Log "Failed to read ACL: $UserAssistPath" 'ERROR'
        $NonCompliant = $true
        continue
    }

    $HasRead = $false

    foreach ($Ace in $Acl.Access) {
      
        if ($AceSid -eq $ServiceNowSid -and
            ($Ace.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)) {
            $HasRead = $true
            break
        }
    }

    if (-not $HasRead) {
        Write-Log "Missing ReadKey permission on $UserAssistPath" 'INFO'
        $NonCompliant = $true
    }
}

Write-Log "Detection completed."

if ($NonCompliant) {
    Write-Log "Exit code 1 sent (non-compliant)"
    exit 1
}
else {
    Write-Log "Exit code 0 sent (compliant)"
    exit 0
}

