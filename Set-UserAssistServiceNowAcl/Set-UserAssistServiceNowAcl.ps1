# ==============================
# Set-UserAssistServiceNowAcl.ps1
# ==============================
param (
    [switch]$Restore
)

$ErrorActionPreference = 'Stop'
$ServiceNowAccount = 'servicenow'

# Root + BackupDir (Logs)
$root = "C:\ProgramData\UserAssistACL" # Kan ändra path om kund önskar
$BackupDir = Join-Path $Root 'Logs'
$LogFile = Join-Path $BackupDir 'UserAssistAcl.log'
$BackupRoot = Join-Path $Root 'Backups'


if (-not (Test-Path $BackupDir)) {
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $BackupRoot)) {
    New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO', 'CHANGE', 'ERROR')]
        [string]$Level = 'INFO'
    )

    try {
        $Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Add-Content -Path $LogFile -Value "$Time [$Level] $Message"
    }
    catch {}
}

if ($Restore) {
    Write-Log "Restore started"
}
else {
    Write-Log "Remediation started."
}


function Backup-UserAssistKey {
    param (
        [string]$RegPath,
        [string]$Sid
    )

    try {
        $Timestamp = Get-Date -Format "yyyyMMdd"
        $BackupPath = Join-Path $BackupRoot "$Sid-$Timestamp"

        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }

        reg.exe export "$RegPath" (Join-Path $BackupPath 'UserAssist.reg') /y | Out-Null

        Get-Acl "Registry::$RegPath" |
        Format-List * |
        Out-File (Join-Path $BackupPath 'UserAssist_ACL.txt') -Encoding UTF8

        Write-Log "Backup created for $Sid"
    }
    catch {
        Write-Log "Backup failed for $Sid : $_" 'ERROR'
        throw
    }
}

function Remove-ServiceNowAcl {
    param (
        [string]$UserAssistPath
    )

    try {
        $Acl = Get-Acl $UserAssistPath
        $Removed = $false

        foreach ($Ace in $Acl.Access) {

            try {
                $AceSid = $Ace.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            }
            catch {
                continue
            }

            if ($AceSid -eq $ServiceNowSid -and
                ($Ace.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)) {

                $Acl.RemoveAccessRule($Ace)
                $Removed = $true
            }
        }

        if ($Removed) {
            Set-Acl -Path $UserAssistPath -AclObject $Acl
            Write-Log "Removed ServiceNow ReadKey from $UserAssistPath" 'CHANGE'
        }
        else {
            Write-Log "No ServiceNow ReadKey found on $UserAssistPath"
        }
    }
    catch {
        Write-Log "Failed to remove ServiceNow ACL on $UserAssistPath : $_" 'ERROR'
    }
}


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

    $RegPath = "HKEY_USERS\$($Sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    $UserAssistPath = "Registry::$RegPath" 
    
    if ($Restore) {       
        Remove-ServiceNowAcl -UserAssistPath $UserAssistPath
        continue
    }


    if (-not (Test-Path $UserAssistPath)) {
        Write-Log "UserAssist missing for $($Sid.PSChildName)."
        continue
    }

    try {
        Backup-UserAssistKey -RegPath $RegPath -Sid $Sid.PSChildName
        $Acl = Get-Acl $UserAssistPath
    }
    catch {
        Write-Log "Failed to read ACL: $UserAssistPath" 'ERROR'
        continue
    }

    $AlreadyPresent = $false

    foreach ($Ace in $Acl.Access) { 
        try {
            $AceSid = $Ace.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            continue
        }

        if ($AceSid -eq $ServiceNowSid -and
            ($Ace.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)) {
            $AlreadyPresent = $true
            break
        }
    }

    if ($AlreadyPresent) {
        Write-Log "ReadKey already present on $UserAssistPath"
        continue
    }

    try {
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $ServiceNowAccount,
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $Acl.AddAccessRule($Rule)
        Set-Acl -Path $UserAssistPath -AclObject $Acl

        Write-Log "Granted ReadKey with inheritance to ServiceNow on $UserAssistPath" 'CHANGE'
    }
    catch {
        Write-Log "Failed to set inherited ReadKey ACL on $UserAssistPath" 'ERROR'
    }

}
if ($Restore) {
    Write-Log "Restore completed."
}
else {
    Write-Log "Remediation completed."
}
exit 0
