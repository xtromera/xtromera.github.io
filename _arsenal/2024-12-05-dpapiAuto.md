---
layout: post
title: "Windows/DPAPI automated discovery"
subtitle: "Powerhsell script to automated DPAPI discovery"
date: 2024-12-05 23:45:13
author: "xtromera"
background: '/img/bg-arsenal.jpg'
excerpt: "Powerhsell script to automated DPAPI discovery"

---


# Automating DPAPI Discovery with PowerShell

## Introduction
As a penetration tester or security researcher, discovering sensitive artifacts like **DPAPI keys** is an essential part of post-exploitation or system analysis. To streamline this process, I’ve developed a PowerShell script that automates the discovery of DPAPI-related paths across user profiles on a Windows machine. This script handles permission issues gracefully and ensures clean, actionable output.

In this post, I'll share the script, explain its key features, and guide you on how to use it effectively.

---

## Features of the Script
- **Automated User Profile Scanning**: Loops through user directories in `C:\Users` and checks for default DPAPI-related paths.
- **Handles Permission Issues**: Silently handles "access denied" errors, displaying a clear warning instead.
- **System-Wide Scanning**: Includes checks for system-wide DPAPI paths.
- **Clean and Readable Output**: Provides a concise summary of findings without cluttering the terminal with raw errors.
- **Customizable Path List**: Easily add or modify paths to extend functionality.

---

## The Script

Here is the PowerShell script in its entirety:

```powershell
# Function to check if a directory exists and handle access errors silently
function Check-Directory {
    param ([string]$Path)
    try {
        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

# Function to scan for DPAPI-related paths
function Scan-DPAPI {
    $basePath = "C:\Users"

    # Check if base path exists
    if (!(Test-Path $basePath -ErrorAction SilentlyContinue)) {
        Write-Error "Base path $basePath does not exist!"
        return
    }

    # Get all user directories
    $userDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

    # List of DPAPI-related paths to check for each user
    $pathsToCheck = @(
        "\AppData\Roaming\Microsoft\Protect",        # User-specific DPAPI Master Keys
        "\AppData\Local\Microsoft\Credentials",     # Windows Credential Manager
        "\AppData\Roaming\Microsoft\Vault",         # Credential Vault
        "\AppData\Local\Microsoft\Edge\User Data",  # Microsoft Edge Data
        "\AppData\Roaming\Microsoft\Internet Explorer" # Internet Explorer Data
    )

    # Scan each user directory
    foreach ($userDir in $userDirs) {
        Write-Host "Scanning user directory: $userDir" -ForegroundColor Cyan
        try {
            # Ensure we can access the user directory
            if (!(Test-Path $userDir -ErrorAction SilentlyContinue)) {
                Write-Warning "No permissions on directory of user: $userDir"
                continue
            }

            foreach ($subPath in $pathsToCheck) {
                $fullPath = Join-Path -Path $userDir -ChildPath $subPath
                if (Check-Directory -Path $fullPath) {
                    Write-Host "Found DPAPI-related path: $fullPath" -ForegroundColor Green
                }
            }
        } catch {
            Write-Warning "No permissions on directory of user: $userDir"
        }
    }

    # Check system-wide DPAPI paths
    $systemPaths = @(
        "C:\Windows\System32\Microsoft\Protect" # System-Wide DPAPI Keys
    )
    Write-Host "Scanning system-wide paths..." -ForegroundColor Yellow
    foreach ($sysPath in $systemPaths) {
        if (Check-Directory -Path $sysPath) {
            Write-Host "Found DPAPI-related path: $sysPath" -ForegroundColor Green
        } else {
            Write-Warning "No permissions or path not accessible: $sysPath"
        }
    }
}

# Run the DPAPI scan
Scan-DPAPI
```

---

## How It Works
1. **Base Directory**: The script starts by examining the `C:\Users` directory for all user profiles.
2. **Path Discovery**: For each user, it checks a list of common DPAPI-related paths (e.g., `Microsoft\Protect` and `Microsoft\Vault`).
3. **Error Handling**: If a user profile or path cannot be accessed due to permission issues, the script logs a warning and continues scanning.
4. **System Paths**: The script also examines system-level DPAPI keys in `C:\Windows\System32\Microsoft\Protect`.

---

## Running the Script
1. Save the script as a `.ps1` file (e.g., `ScanDPAPI.ps1`).
2. Open PowerShell.
3. Run the script:
   ```powershell
   .\ScanDPAPI.ps1
   ```

### Sample Output
```
Scanning user directory: C:\Users\Administrator
Scanning user directory: C:\Users\C.Neri
Found DPAPI-related path: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect
Found DPAPI-related path: C:\Users\C.Neri\AppData\Local\Microsoft\Credentials
Found DPAPI-related path: C:\Users\C.Neri\AppData\Roaming\Microsoft\Vault
Found DPAPI-related path: C:\Users\C.Neri\AppData\Local\Microsoft\Edge\User Data
Found DPAPI-related path: C:\Users\C.Neri\AppData\Roaming\Microsoft\Internet Explorer
Scanning user directory: C:\Users\c.neri_adm
Scanning user directory: C:\Users\Public
Scanning system-wide paths...
Found DPAPI-related path: C:\Windows\System32\Microsoft\Protect
```

