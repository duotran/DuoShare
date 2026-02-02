<#
Intune install commands
powershell.exe -ExecutionPolicy Bypass -File UserAssistACL.ps1 -Action Install
powershell.exe -ExecutionPolicy Bypass -File UserAssistACL.ps1 -Action Restore
#>


param(
    [ValidateSet("Install", "Restore")] 
    [string]$Action = "Install",

    [string]$LocalUser = "servicenow",

    [string]$TargetSubPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" # registry path som behörighet ska läggas på
)

$root = "C:\ProgramData\UserAssistACL" # Kan ändra path om kund önskar
$backupDir = Join-Path $root "Backup"
$statePath = Join-Path $root "state.json"

New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

function Get-UserSids {
    Get-ChildItem Registry::HKEY_USERS |
    Where-Object { $_.Name -match "S-1-5-21-" } | # Tar endast ur riktiga användarkonton
    ForEach-Object { $_.PSChildName }
}

function Save-BackupIfMissing {
    param([string]$Sid, [string]$RegPath)

    $backupPath = Join-Path $backupDir "$Sid.json"
    if (Test-Path $backupPath) { return }

    try {
        $acl = Get-Acl $RegPath
        $obj = [pscustomobject]@{
            Sid        = $Sid
            Path       = $RegPath
            Sddl       = $acl.Sddl
            SavedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        }
        $obj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupPath -Encoding UTF8
    }
    catch {
        # If backup fails, still continue (per your ignore-and-proceed requirement)
    }
}

function Add-ReadRule {
    param([string]$RegPath)

    $acl = Get-Acl $RegPath

    $already = $acl.Access | Where-Object {
        $_.IdentityReference -match $LocalUser -and
        ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)
    }

    if (-not $already) {
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $LocalUser,
            "ReadKey",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule) | Out-Null
        Set-Acl -Path $RegPath -AclObject $acl
    }
}

function Remove-ReadRuleBestEffort {
    param([string]$RegPath)

    $acl = Get-Acl $RegPath

    $rulesToRemove = $acl.Access | Where-Object {
        $_.IdentityReference -match $LocalUser -and
        ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)
    }

    foreach ($r in $rulesToRemove) {
        [void]$acl.RemoveAccessRule($r)
    }

    Set-Acl -Path $RegPath -AclObject $acl
}

function Restore-FromBackupOrFallback {
    param([string]$Sid, [string]$RegPath)

    $backupPath = Join-Path $backupDir "$Sid.json"
    if (Test-Path $backupPath) {
        try {
            $data = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
            if ($null -ne $data.Sddl -and $data.Sddl.Length -gt 0) {
                $acl = Get-Acl $RegPath
                $acl.SetSecurityDescriptorSddlForm($data.Sddl)
                Set-Acl -Path $RegPath -AclObject $acl
                return
            }
        }
        catch {
            # If restore fails, fallback below
        }
    }

    # No backup or restore failed: best-effort remove the servicenow read rule
    try { Remove-ReadRuleBestEffort -RegPath $RegPath } catch {}
}

# Do the work
$sids = Get-UserSids
foreach ($sid in $sids) {
    $regPath = "Registry::HKEY_USERS\$sid\$TargetSubPath"

    if (-not (Test-Path $regPath)) {
        continue
    }

    try {
        if ($Action -eq "Install") {
            Save-BackupIfMissing -Sid $sid -RegPath $regPath
            Add-ReadRule -RegPath $regPath
        }
        else {
            Restore-FromBackupOrFallback -Sid $sid -RegPath $regPath
        }
    }
    catch {
        continue
    }
}

# Write state so detection knows what "good" looks like
$state = [pscustomobject]@{
    Mode         = $Action.ToLowerInvariant()
    UpdatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
}
$state | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $statePath -Encoding UTF8
exit 0
