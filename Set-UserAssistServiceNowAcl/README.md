# UserAssist ServiceNow ACL – Intune Remediation

## Overview

This project consists of **two PowerShell scripts** designed to be used together as an **Intune proactive remediation**. Their purpose is to ensure that a designated **ServiceNow account** has **read-only access** to the Windows *UserAssist* registry keys, without modifying ownership or adding unnecessary permissions.

The solution is:

* Safe to run repeatedly (idempotent)
* Designed to run as **SYSTEM** (Intune context)
* Fully logged for troubleshooting and auditing

---

## Files in This Project

### 1. Detect-UserAssistServiceNowAcl.ps1

**Purpose:**
Determines whether the device is *compliant*.

**What it does:**

* Locates all UserAssist registry keys under `HKEY_USERS`
* Checks whether the **ServiceNow account** exists in the ACL
* Verifies that:

  * Permissions are **ReadKey only**
  * No write / full control permissions are granted
  * Inheritance is enabled

**Outcome:**

* **Exit code 0** → Compliant (no remediation needed)
* **Exit code 1** → Non-compliant (triggers remediation)

**What Intune receives:**

* Only the exit code (0 or 1)
* Detailed reasoning is written to the local log file

---

### 2. Set-UserAssistServiceNowAcl.ps1

**Purpose:**
Remediates non-compliant devices.

**What it does:**

* Enables ACL inheritance on UserAssist registry keys
* Adds the ServiceNow account **if missing**
* Assigns **ReadKey only** permissions
* Does **not** remove other existing ACL entries
* Does **not** take ownership

The script is safe to rerun and will only apply changes when required.

---

## Registry Location

The UserAssist keys are located here:

```
HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

* `<SID>` represents each user profile on the device
* The scripts iterate all relevant SIDs automatically

---

## Logging

Both scripts write to the same log file:

```
C:\ProgramData\UserAssistACL\Logs\UserAssistAcl.log
```

Log levels:

* `INFO`   – General execution details
* `CHANGE` – ACL changes applied
* `ERROR`  – Failures or unexpected conditions

These logs are **local only** and not sent to Intune.

---
## `-Restore` Switch

The remediation script supports an optional **`-Restore`** parameter.

**Purpose:**

* Forces the UserAssist registry keys back to the **intended baseline state**
* Removes **read-only** permissions for the ServiceNow account

**Important notes:**

* This does **not** restore historical or backed-up ACLs
* No ACL snapshots are stored or replayed
* Ownership is not changed
* Existing unrelated ACEs are preserved
* Snapshot is stored in the backup folder prior to any change

`-Restore` should be used intentionally (manual or break-glass scenarios) and is **not** required for normal Intune remediation.

---

## Intune Configuration

### Detection Script

Use:

* `Detect-UserAssistServiceNowAcl.ps1`

### Remediation Script

Use:

* `Set-UserAssistServiceNowAcl.ps1`

### Settings

* Run scripts as **SYSTEM**
* Run scripts in **64-bit PowerShell**

---

## Compliance Logic (Summary)

| Condition                       | Result        |
| ------------------------------- | ------------- |
| ServiceNow account missing      | Non-compliant |
| Incorrect permissions           | Non-compliant |
| Read-only + inheritance enabled | Compliant     |

---

## Install Commands (Intune)

When packaging with the **Microsoft Win32 Content Prep Tool**, include both scripts in the same source folder.

### Detection Command

```
powershell.exe -ExecutionPolicy Bypass -File .\Detect-UserAssistServiceNowAcl.ps1
```

### Remediation Command

```
powershell.exe -ExecutionPolicy Bypass -File .\Set-UserAssistServiceNowAcl.ps1
```

### Optional Restore (Manual / Break-glass)

```
powershell.exe -ExecutionPolicy Bypass -File .\Set-UserAssistServiceNowAcl.ps1 -Restore
```

---

## Packaging

When packaging with the **Intune Win32 Content Prep Tool**, include both scripts in the same folder. Detection and remediation are referenced separately inside Intune.

---

## Change Control

This solution:

* Makes minimal changes
* Avoids destructive ACL operations
* Preserves existing security principals

Suitable for production environments.

---

**Author:** Duong.tran@advania.se
