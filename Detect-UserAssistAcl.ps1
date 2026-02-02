param(
    [switch]$VerboseOutput
)

function Write-VerboseHost {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    if ($VerboseOutput) {
        Write-Host $Message -ForegroundColor $Color
    }
}

$targetSubPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
$localUser = "servicenow"
$statePath = "C:\ProgramData\UserAssistACL\state.json"

Write-VerboseHost "=== UserAssist ACL Detection Script ===" Cyan
Write-VerboseHost "Target subpath : $targetSubPath" DarkGray
Write-VerboseHost "Local user     : $localUser" DarkGray
Write-VerboseHost "State file     : $statePath" DarkGray
Write-VerboseHost ""

$mode = "install"
if (Test-Path $statePath) {
    try {
        $mode = ((Get-Content $statePath -Raw | ConvertFrom-Json).Mode)
        if ([string]::IsNullOrWhiteSpace($mode)) {
            $mode = "install"
        }
    }
    catch {
        Write-VerboseHost "Failed to read state file, defaulting to INSTALL mode" Yellow
        $mode = "install"
    }
}
else {
    Write-VerboseHost "State file not found, defaulting to INSTALL mode" Yellow
}

Write-VerboseHost "Detection mode : $mode" Cyan
Write-VerboseHost ""

$sids = Get-ChildItem Registry::HKEY_USERS |
Where-Object { $_.Name -match "S-1-5-21-" } |
ForEach-Object { $_.PSChildName }

foreach ($sid in $sids) {

    $regPath = "Registry::HKEY_USERS\$sid\$targetSubPath"
    Write-VerboseHost "Checking SID   : $sid" White

    if (-not (Test-Path $regPath)) {
        Write-VerboseHost "  UserAssist key not found — skipping" DarkGray
        Write-VerboseHost ""
        continue
    }

    Write-VerboseHost "  UserAssist key found" Gray

    $acl = Get-Acl $regPath
    $hasRead = $acl.Access | Where-Object {
        $_.IdentityReference -match $localUser -and
        ($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey)
    }

    if ($mode -eq "restore") {
        if ($hasRead) {
            Write-VerboseHost "  ❌ FAIL: '$localUser' still has Read permission (restore mode)" Red
            exit 1
        }
        else {
            Write-VerboseHost "  ✅ OK: '$localUser' does NOT have Read permission (restore mode)" Green
        }
    }
    else {
        if (-not $hasRead) {
            Write-VerboseHost "  ❌ FAIL: '$localUser' does NOT have Read permission (install mode)" Red
            exit 1
        }
        else {
            Write-VerboseHost "  ✅ OK: '$localUser' has Read permission (install mode)" Green
        }
    }

    Write-VerboseHost ""
}

Write-VerboseHost "=== Detection SUCCESS: system is compliant ===" Green
exit 0
