# Endpoint Security Agent — Phase 1 (Windows Agent)

A lightweight .NET 8 Windows Service that collects device security posture
and reports it to a central server (built in Phase 2). This is the client
half of the architecture in your plan.

## What's implemented

| # | Function | File | How |
|---|----------|------|-----|
| 1 | Device info | `Services/DeviceInfoCollector.cs` | WMI (`Win32_ComputerSystemProduct`, `Win32_BIOS`, `Win32_OperatingSystem`) + `NetworkInterface` |
| 2 | Firewall status | `Services/FirewallChecker.cs` | `netsh advfirewall show allprofiles state` |
| 3 | Defender status | `Services/DefenderChecker.cs` | WMI `root\Microsoft\Windows\Defender` → `MSFT_MpComputerStatus` |
| 4 | BitLocker status | `Services/BitLockerChecker.cs` | WMI `root\CIMV2\Security\MicrosoftVolumeEncryption` → `Win32_EncryptableVolume` |
| 5 | Windows Update status | `Services/WindowsUpdateChecker.cs` | `Win32_QuickFixEngineering` + Windows Update Agent COM API |
| 6 | Installed software / unauthorized software | `Services/SoftwareInventoryMonitor.cs` | Registry `...\Uninstall` keys diffed against `ApprovedSoftware` allowlist |
| 7 | Download monitor | `Services/FileDownloadMonitor.cs` | `FileSystemWatcher` on Downloads/Desktop/Documents (+ USB roots) → SHA-256 + Authenticode signature check |
| 8 | USB detection | `Services/UsbMonitor.cs` | WMI event watcher on `Win32_VolumeChangeEvent` |
| 9 | Wi-Fi detection | `Services/WifiChecker.cs` | `netsh wlan show interfaces` vs `TrustedWifiSsids` |
| 10 | Risk score | `Services/RiskScoreCalculator.cs` | Weighted sum, capped at 100, config-driven weights |

`Worker.cs` ties it all together on a timer (`ReportIntervalSeconds`,
default 300s = 5 minutes) and POSTs a `DeviceReport` JSON payload to
`{ServerBaseUrl}api/device/report` via `Services/ApiClient.cs`.

## Requirements

- Windows 10/11 (agent must run **on Windows** — it will not build/run on Linux/macOS)
- .NET 8 SDK
- Run as **LocalSystem** (installed as a Windows Service) — required for the
  BitLocker WMI check and for reliable operation at login/logoff/no-user-session

## Build

```powershell
cd EndpointSecurityAgent
dotnet restore
dotnet build -c Release
```

## Publish a self-contained single-file exe

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Output: `bin\Release\net8.0-windows\win-x64\publish\EndpointSecurityAgent.exe`

## Install as a Windows Service

Run as Administrator:

```powershell
sc.exe create EndpointSecurityAgent binPath= "C:\Path\To\EndpointSecurityAgent.exe" start= auto
sc.exe description EndpointSecurityAgent "Endpoint security posture monitoring agent"
sc.exe start EndpointSecurityAgent
```

To uninstall: `sc.exe stop EndpointSecurityAgent && sc.exe delete EndpointSecurityAgent`

## Configuration

All tunables live in `appsettings.json` next to the exe:

- `ServerBaseUrl` — Phase 2 API base URL
- `ApiKeyOrDeviceToken` — bearer token issued at device enrollment
- `ReportIntervalSeconds` — polling interval
- `HighRiskImmediateReportThreshold` — logs a warning (hook this up to an
  immediate out-of-cycle POST in Phase 2/5 if you want true real-time alerts)
- `ApprovedSoftware` — allowlist for the software inventory check
- `TrustedWifiSsids` — allowlist for the Wi-Fi check
- `UsbPolicyBlocked` — whether USB storage use itself should add risk
- `RiskWeights` — point values matching your plan's table (Firewall Off = 20,
  Defender Off = 30, BitLocker Off = 15, etc.)

## Testing locally without a server

Point `ServerBaseUrl` at a mock endpoint (e.g. `https://webhook.site/...`) or
temporarily comment out the `SendReportAsync` call in `Worker.cs` and
`_logger.LogInformation(JsonSerializer.Serialize(report))` instead, so you
can validate the collected data before Phase 2's API exists.

You can also run the agent as a plain console app first (without installing
it as a service) to iterate faster:

```powershell
dotnet run
```
Note: BitLocker checks will report "Access Denied" when run this way from a
non-elevated console — that's expected; install as a service (LocalSystem)
for that check to succeed.

## Known simplifications / things to harden before production

- **Unsent reports aren't queued/retried locally** — if the server is
  unreachable, that cycle's report is simply lost. Add a local SQLite/JSON
  queue with retry-and-flush if you need guaranteed delivery.
- **Windows Update Agent COM search can be slow** (several seconds) on some
  machines — consider caching pending-update count and refreshing less often
  than every report cycle.
- **3rd-party antivirus**: `MSFT_MpComputerStatus` only reports Defender. If
  a device uses e.g. CrowdStrike/Sophos instead, add a fallback WMI query
  against `root\SecurityCenter2` → `AntiVirusProduct`.
- **Digital signature check** uses `X509Certificate.CreateFromSignedFile`,
  which confirms a signature is *present* but doesn't verify the certificate
  chain/trust or check revocation. For stronger assurance, shell out to
  `signtool verify /pa` or use `WinVerifyTrust` via P/Invoke.
- **Tamper resistance** isn't addressed yet (e.g. protecting the service from
  being stopped by a local admin/malware, config file integrity). Worth a
  Phase 1.5 pass once the happy path works end-to-end.
