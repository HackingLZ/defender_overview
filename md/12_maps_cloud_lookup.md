# Stage 12 — MAPS Cloud Lookup (Microsoft Active Protection Service)

> Reverse engineering documentation for the MAPS cloud lookup stage inside `mpengine.dll`.
> All addresses, strings, and structures from RE of mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 12 is the **MAPS (Microsoft Active Protection Service) cloud lookup** — the only stage in the pipeline that reaches outside the local machine. When a local scan produces a low-confidence detection (a "lowfi" match), the engine builds a report about the scanned file, serializes it using the **Bond** binary protocol, and sends it via HTTPS POST to Microsoft's cloud infrastructure. The cloud backend applies its own analysis (including ML models, reputation data, and telemetry aggregation) and returns **FASTPATH signatures** — cloud-delivered detections that upgrade or drop the lowfi match.

This is the mechanism behind Defender's "cloud-delivered protection" feature. It enables the cloud backend to make detection decisions that would be too expensive or data-intensive for the local engine, such as global prevalence analysis, ML classification, and dynamic sandboxing correlation.

### Core Endpoints

| Endpoint | Address | Purpose |
|----------|---------|---------|
| `fastpath.wdcp.microsoft.com` | `0x10A09EC0` | Production MAPS endpoint (UTF-16) |
| `fastpath.wdcpppe.microsoft.com` | `0x10A09EF8` | PPE (Pre-Production Environment) endpoint (UTF-16) |
| `fastpath.wdcpppe.microsoft-ppe.com` | `0x10A09E48` | Alternative PPE endpoint (UTF-16) |

---

## Entry Conditions

Stage 12 triggers when three conditions are met:

1. **A lowfi (low-confidence) detection was produced** by earlier stages (3-11)
2. **MAPS is enabled** — not blocked by policy or user setting
3. **Network connectivity** is available to reach the MAPS endpoint

```
          Lowfi detection from Stages 3-11
                        |
                        v
              +-------------------+
              | MAPS enabled?     |---- NO ----> Skip Stage 12
              | (policy + config) |               (keep lowfi or
              +-------------------+                drop it)
                        |
                       YES
                        |
                        v
              +-------------------+
              | Build SpynetReport|
              | (file metadata,   |
              |  hashes, attrs,   |
              |  detection info)  |
              +-------------------+
                        |
                        v
              +-------------------+
              | Bond serialize    |
              | (CompactBinaryV1) |
              +-------------------+
                        |
                        v
              +-------------------+
              | HTTPS POST to     |
              | fastpath.wdcp.    |
              | microsoft.com     |
              +-------------------+
                        |
                        v
              +-------------------+
              | Parse response:   |
              | FASTPATH sigs     |
              | (SDN, TDN, DATA)  |
              +-------------------+
                        |
                        v
              +-------------------+
              | Apply FASTPATH    |
              | sigs to scan      |
              +-------------------+
                        |
                        v
                 Stage 13 (Verdict)
```

---

## Key Strings from mpengine.dll

### MAPS Core Strings

| String | Address | Section | Type | Description |
|--------|---------|---------|------|-------------|
| `MAPS` | `0x109C546C` | .rdata | ASCII | Core identifier |
| `MAPSURL` | `0x109CB000` | .rdata | ASCII | URL configuration key |
| `MAPSURL` | `0x109CD894` | .rdata | UTF-16 | URL configuration key (wide) |
| `MAPSURL_%ls` | `0x109CE7B8` | .rdata | ASCII | Formatted URL key |
| `MAPSOff` | `0x10A08980` | .rdata | ASCII | MAPS disabled indicator |
| `URLMAPSOff` | `0x10A4FDAC` | .rdata | ASCII | URL-based MAPS off indicator |

### MAPS Latency Telemetry Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `MAPSClientLatency` | `0x109D1D4C` | UTF-16 | Total client-side latency |
| `MAPSGenerateLatency` | `0x109D1D70` | UTF-16 | Report generation time |
| `MAPSSendLatency` | `0x109D1D98` | UTF-16 | Network send time |
| `MAPSParseLatency` | `0x109D1DB8` | UTF-16 | Response parse time |
| `MAPSHresult` | `0x109D1DDC` | UTF-16 | Result HRESULT code |
| `MAPSHttpStatus` | `0x109D1DF4` | UTF-16 | HTTP response status code |
| `MAPSReportGuid` | `0x109D1E14` | UTF-16 | Report unique identifier |
| `MAPSCreateConnectionTime` | `0x109D1E34` | UTF-16 | TCP connection time |
| `MAPSSendRequestTime` | `0x109D1E68` | UTF-16 | Request send time |
| `MAPSSendOverheadTime` | `0x109D1E90` | UTF-16 | Send overhead time |
| `MAPSSendUrlAttempts` | `0x109D1EBC` | UTF-16 | URL attempt count |
| `MAPSReceiveResponseTime` | `0x109D1EE4` | UTF-16 | Response receive time |
| `MAPSOnSendStartTick` | `0x109D1F14` | UTF-16 | Send start timestamp |
| `MAPSOnResolvingNameTick` | `0x109D1F3C` | UTF-16 | DNS resolve start |
| `MAPSOnResolvedNameTick` | `0x109D1F6C` | UTF-16 | DNS resolve end |
| `MAPSOnConnectingTick` | `0x109D1F9C` | UTF-16 | TCP connect start |
| `MAPSOnConnectedTick` | `0x109D1FC8` | UTF-16 | TCP connect complete |
| `MAPSOnFirstSendingTick` | `0x109D1FF0` | UTF-16 | First byte sent |
| `MAPSOnFirstReceivingTick` | `0x109D2020` | UTF-16 | First byte received |
| `MAPSOnSendEndTick` | `0x109D2054` | UTF-16 | Send end timestamp |
| `MAPSReadResponseTime` | `0x109D2078` | UTF-16 | Response read time |
| `LastMAPSSuccessTime` | `0x109D24C0` | UTF-16 | Last successful query |
| `LastMAPSFailureTime` | `0x109D24E8` | UTF-16 | Last failed query |

*(from RE of mpengine.dll @ 0x109D1D4C-0x109D24E8 — consecutive string block)*

### SpyNet Report Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `SpynetReport` | `0x109C9E00` | UTF-16 | Report object name |
| `SpynetReportResponse` | `0x109CA8A8` | UTF-16 | Response wrapper |
| `SubmitSpynetReportResult` | `0x109CA874` | UTF-16 | Submission result |
| `<SubmitSpynetReportResult>` | `0x109C55C8` | UTF-16 | XML opening tag |
| `</SubmitSpynetReportResult>` | `0x109C55FE` | UTF-16 | XML closing tag |
| `SpynetReportGuid` | `0x109EE7CC` | UTF-16 | Report GUID |
| `SpynetCollectionErrors` | `0x109EF374` | UTF-16 | Collection error tracking |
| `SpynetErrors` | `0x109EA2B0` | UTF-16 | General error tracking |
| `SpynetReportingLevel` | `0x10BD32EE` | ASCII | Reporting level config |
| `MpMaxSpynetReports` | `0x10A4EDF4` | UTF-16 | Max concurrent reports |
| `MpUseNewSpynetExtra` | `0x109CD9E4` | UTF-16 | New extra data format |
| `MpDisableSyncSpynetCheck` | `0x10A0875C` | UTF-16 | Disable sync check |
| `MpDisableOplocksInSpynet` | `0x10A3454C` | UTF-16 | Disable oplocks in spynet |
| `MpDisableNewCertsInSpynetReports` | `0x10A4EFA0` | UTF-16 | Disable new cert format |
| `MpDisableLegacyCertsInSpynetReports` | `0x10A4EFE8` | UTF-16 | Disable legacy cert format |
| `CollectSpynetFailure` | `0x109D46E4` | ASCII | Collection failure event |
| `Spynet` | `0x109D46FC` | ASCII | General spynet identifier |

*(from RE of mpengine.dll — SpyNet string references)*

### SpyNet Configuration Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `Engine.Maps.SpynetLevelChanged` | `0x109C55B0` | ASCII | ETW event: level changed |
| `SpynetLevelValueChanged` | `0x109C55C8` | ASCII | Level value changed |
| `dssspynetcontext` | `0x109C8D44` | ASCII | DSS Spynet context init |
| `SpynetSigLoader` | `0x109C8104` | ASCII | Spynet signature loader |
| `SpynetBondKillbit` | `0x10A4EF70` | ASCII | Bond killbit flag |
| `SpynetBondResponseKillbit` | `0x10A4EF84` | ASCII | Bond response killbit |

*(from RE of mpengine.dll — SpyNet config strings)*

### Spynet Registry Paths

| String | Address | Type |
|--------|---------|------|
| `Software\Microsoft\MpScan\Spynet` | `0x109C4C98` | UTF-16 |
| `SOFTWARE\Microsoft\Microsoft Antimalware\Spynet` | `0x109C6CC8` | UTF-16 |
| `SOFTWARE\Microsoft\Windows Defender\Spynet` | `0x109C6D28` | UTF-16 |
| `AntiMalwareServices.Components.SpynetReport` | `0x109C9940` | UTF-16 |

*(from RE of mpengine.dll — registry path strings)*

---

## Bond Serialization

The SpynetReport is serialized using Microsoft's **Bond** binary protocol (an internal protocol buffer-like system). The `CompactBinaryV1` serialization format is used:

### Bond-Related Strings

| String | Address | Section | Type |
|--------|---------|---------|------|
| `BondSerializer` | `0x109C80E0` | .rdata | ASCII |
| `fastpath` | `0x109C8D38` | .rdata | ASCII |
| `GetBond` | `0x109CAA34` | .rdata | UTF-16 |
| `Bond` | `0x109CAA44` | .rdata | UTF-16 |
| `BondDeserializationFailure` | `0x109D9A70` | .rdata | ASCII |
| `uEngine.Maps.BondDeserializationFailure` | `0x109D9A47` | .rdata | ASCII |
| `GetBondReportEntityElementFromName: %ls` | `0x109D9C68` | .rdata | UTF-16 |
| `Entities.CommonToBondConverter.LowercaseNoDashes` | `0x109D9CE0` | .rdata | UTF-16 |
| `Entities.CommonToBondConverter.ConvertStringGuid` | `0x109D9D50` | .rdata | UTF-16 |

*(from RE of mpengine.dll — Bond string references)*

### Bond RTTI Classes

| Class | Address | Purpose |
|-------|---------|---------|
| `CompactBinaryV1Serializer` | `0x10C823C4` | Serialization format implementation |
| `BondNode` | `0x10C82368` | Bond protocol node |
| `IBondSerializer` | `0x10C823EC` | Serializer interface |
| `Bond_SignatureInfo` | `0x10C8240C` | Signature information |
| `Bond_SubmitSpynetReportResult` | `0x10C82430` | Report result |
| `Bond_UrlResponseContext` | `0x10C8245C` | URL response context |
| `Bond_CertificateResponse` | `0x10C82484` | Certificate response |
| `Bond_SignatureMatch` | `0x10C824AC` | Signature match info |
| `Bond_CertificateResult` | `0x10C824D0` | Certificate result |
| `Bond_SampleRequest` | `0x10C824F8` | Sample request |
| `Bond_UrlResponse` | `0x10C8251C` | URL response |
| `Bond_SpynetReportResponse` | `0x10C8253C` | Report response |
| `Bond_SpynetReport` | `0x10C831AC` | Report data |

*(from RE of mpengine.dll — RTTI type descriptors in .data section)*

### Serialization Flow

```
SpynetReport Construction:
+---------------------------------------------------------------+
| 1. Collect File Metadata                                      |
|    - File hash (SHA-256, SHA-1, MD5)                          |
|    - File size, path, content type                            |
|    - Certificate chain (if signed)                            |
+---------------------------------------------------------------+
| 2. Collect Scan Results                                       |
|    - Lowfi detection name and ID                              |
|    - Matched signatures (sig ID, sig seq)                     |
|    - Collected attributes from all stages                     |
+---------------------------------------------------------------+
| 3. Collect Context                                            |
|    - Scan source (real-time, on-demand, AMSI)                 |
|    - Machine GUID, Windows version                            |
|    - SpynetReportGuid (unique per report)                     |
|    - lowficontext, threatcontext_lowfi                        |
+---------------------------------------------------------------+
| 4. Bond Serialize                                             |
|    - CompactBinaryV1Serializer                                |
|    - Binary blob ready for HTTPS POST                         |
+---------------------------------------------------------------+
            |
            v
    +----------------------------+
    | HTTPS POST to:             |
    | fastpath.wdcp.microsoft.com|
    +----------------------------+
```

---

## Lowfi Detection Trigger

The MAPS lookup is triggered by "lowfi" (low-fidelity) detections — matches that are not confident enough to declare a verdict locally:

### Lowfi-Related Strings

| String | Address | Description |
|--------|---------|-------------|
| `lowfi` | `0x109C60D0` | Lowfi identifier |
| `lowfis.log` | `0x109C5F4C` | Lowfi log filename (UTF-16) |
| `lowfis-%d.log` | `0x109C5F30` | Lowfi numbered log (UTF-16) |
| `lowficontext` | `0x109E2378` | Lowfi context (UTF-16) |
| `lowficount` | `0x109E9BA4` | Lowfi count metric (UTF-16) |
| `metastorelowficache` | `0x109C8CB0` | Lowfi cache in metastore |
| `threatcontext_lowfi=` | `0x10A0F3F0` | Lowfi threat context |
| `threatcontext_lowfi` | `0x10A54358` | Lowfi threat context (UTF-16) |
| `Lowfi detection supressed` | `0x10A536B0` | Suppression log entry |
| `Supressed lowfi per named attribute` | `0x10A53FE8` | Attribute-based suppression |
| `SMS lowfi match: %hs, sigseq=0x%016llX, sigsha=%ls, pid=%u` | `0x10B4AF98` | SMS lowfi match log (UTF-16) |
| `command line reported as lowfi: %ls(%ls)` | `0x10B6A088` | Command line lowfi (UTF-16) |
| `Engine.Det.LowfiNonInt` | `0x10A53670` | Non-interactive lowfi event |
| `Engine.Det.LowfiTrusted` | `0x10A536E0` | Trusted lowfi event |
| `MP_FASTPATH_LOWFI_LIFETIME` | `0x1098C998` | Lowfi lifetime constant (UTF-16) |

*(from RE of mpengine.dll — lowfi string references)*

### Lowfi Flow

```
Lowfi Detection Flow:
+-------------------------------------------+
| Stage 3-11: Scan produces lowfi match     |
| (not confident enough for local verdict)  |
+-------------------------------------------+
              |
              v
+-------------------------------------------+
| Lowfi attributes stored:                  |
|   lowficontext   @ 0x109E2378             |
|   lowficount     @ 0x109E9BA4             |
|   threatcontext_lowfi @ 0x10A54358        |
+-------------------------------------------+
              |
              v
+-------------------------------------------+
| Check suppression:                        |
|   "Lowfi detection supressed" @ 0x10A536B0|
|   - Per named attribute filter            |
|   - Trust status check                    |
|   - Cache hit (metastorelowficache)       |
+-------------------------------------------+
              |
       Not suppressed
              |
              v
+-------------------------------------------+
| Build SpynetReport and submit to MAPS     |
+-------------------------------------------+
```

---

## FASTPATH Response Signatures

The cloud backend responds with FASTPATH signatures — cloud-delivered detection rules that are applied immediately to the current scan:

### FASTPATH Signature Types

| Signature Type | Address | Purpose |
|----------------|---------|---------|
| `SIGNATURE_TYPE_FASTPATH_SDN` | `0x109869AC` | **SDN** (Signature Delivery Notification) — cloud detection name |
| `SIGNATURE_TYPE_FASTPATH_SDN_EX` | `0x10986110` | Extended SDN with additional data |
| `SIGNATURE_TYPE_FASTPATH_TDN` | `0x1098647C` | **TDN** (Threat Delivery Notification) — threat identity |
| `SIGNATURE_TYPE_FASTPATH_DATA` | `0x1098691C` | **DATA** — binary signature data for local matching |

*(from RE of mpengine.dll — SIGNATURE_TYPE string table)*

### SDN (Signature Delivery Notification)

The SDN provides a detection name that the cloud wants applied. If the cloud determines the file is malicious, it returns an SDN with the final threat name:

```
SDN Response:
+---------------------------------------+
| Detection Name: "Trojan:Win32/X.A"    |
| Confidence:     High                  |
| Action:         Upgrade lowfi to full |
+---------------------------------------+
```

Related strings:
- `"Issuing SDN query for %ls (%ls)"` @ `0x10A53D68` (UTF-16)
- `"Issuing SDN query for %ls (%ls) (sha1=%hs, sha2=%hs)"` @ `0x10A53DB0` (UTF-16)
- `"SDN recieved, rescanning impacted resources"` @ `0x10A53E40` (UTF-16)
- `"SDN/TDN matched, dropped detection for %ls (ThreatID=0x%08lx, SigSeq=0x%llx)"` @ `0x10A53EB0` (UTF-16)
- `"SDN query completed: %08lx"` @ `0x10A53F4C` (UTF-16)
- `"Defender_Engine_CachedSDN"` @ `0x10A53BA8`
- `"SCANSOURCE_SDNCHECK"` @ `0x1098067C`

*(from RE of mpengine.dll — SDN string references)*

### TDN (Threat Delivery Notification)

The TDN provides threat identity information — can be used to match or drop detections:

- `"SDN/TDN matched, dropped detection for %ls (ThreatID=0x%08lx, SigSeq=0x%llx)"` @ `0x10A53EB0`

### FASTPATH DATA

Binary signature data delivered from the cloud that can be loaded and matched locally. This allows the cloud to deliver new signatures in real-time during a scan.

---

## CSpynetResponse Processing

The response from the MAPS cloud is processed by the `CSpynetResponse` class:

### Response RTTI Classes

| Class | Address | Description |
|-------|---------|-------------|
| `spynet_report` | `0x10C74FE4` | Report object |
| `spynet_wrapper` | `0x10C890CC` | Wrapper around report |
| `CSpynetResponse::ProcessSignatureResponses` | `0x10C890F0` | Main response handler |
| `DssSpynetContext` | `0x10C84760` | DSS context (sig delivery thread) |

*(from RE of mpengine.dll — RTTI type descriptors in .data section)*

### Response Processing Flow

```
MAPS Response Processing:
+-----------------------------------------------+
| 1. Receive HTTPS response                     |
|    - Parse HTTP status (MAPSHttpStatus)        |
|    - Check HRESULT (MAPSHresult)               |
+-----------------------------------------------+
                |
                v
+-----------------------------------------------+
| 2. Bond Deserialize                            |
|    - CompactBinaryV1 → Bond_SpynetReportResponse
|    - Error: "BondDeserializationFailure"        |
|      @ 0x109D9A70                               |
+-----------------------------------------------+
                |
                v
+-----------------------------------------------+
| 3. Extract FASTPATH signatures                 |
|    - FASTPATH_SDN → detection name             |
|    - FASTPATH_TDN → threat identity            |
|    - FASTPATH_DATA → binary sig data           |
+-----------------------------------------------+
                |
                v
+-----------------------------------------------+
| 4. ProcessSignatureResponses                   |
|    - Apply SDN/TDN to current scan             |
|    - "SDN recieved, rescanning impacted         |
|       resources" @ 0x10A53E40                   |
|    - May trigger rescan of affected files       |
+-----------------------------------------------+
                |
                v
+-----------------------------------------------+
| 5. Update detection status                     |
|    - Upgrade lowfi → full detection            |
|    - Or: drop lowfi (cloud says clean)         |
|    - "SDN/TDN matched, dropped detection"       |
|      @ 0x10A53EB0                               |
+-----------------------------------------------+
```

---

## Network Protocol Details

### Request Format

```
HTTPS POST Request:
+-----------------------------------------------+
| URL:  https://fastpath.wdcp.microsoft.com      |
|       @ 0x10A09EC0 (UTF-16)                    |
+-----------------------------------------------+
| Method: POST                                   |
| Content-Type: application/bond-compact-binary  |
+-----------------------------------------------+
| Body:                                          |
|   Bond CompactBinaryV1 serialized              |
|   SpynetReport:                                |
|     - File hashes (SHA256, SHA1, MD5)          |
|     - File metadata (size, type, path)         |
|     - Certificate chain                        |
|     - Lowfi detection info                     |
|     - Scan context attributes                  |
|     - Machine context (GUID, OS version)       |
|     - SpynetReportGuid                         |
+-----------------------------------------------+
```

### Response Format

```
HTTPS Response:
+-----------------------------------------------+
| Status: 200 OK (MAPSHttpStatus @ 0x109D1DF4)  |
+-----------------------------------------------+
| Body:                                          |
|   Bond CompactBinaryV1 serialized              |
|   SubmitSpynetReportResult:                    |
|     - FASTPATH_SDN signatures (0 or more)      |
|     - FASTPATH_TDN signatures (0 or more)      |
|     - FASTPATH_DATA signatures (0 or more)     |
|     - Certificate validation results           |
|     - Sample request (optional)                |
|     - URL response context (optional)          |
+-----------------------------------------------+
```

### Latency Tracking

The engine tracks every phase of the MAPS network request with granular telemetry:

```
MAPS Latency Timeline:
                                          Time →
    ├──────────┼─────────┼──────────┼────────────┼──────────┤
    │ Generate │ DNS     │ Connect  │ Send       │ Receive  │
    │ Report   │ Resolve │ TCP/TLS  │ Request    │ Response │
    │          │         │          │            │          │
    ▼          ▼         ▼          ▼            ▼          ▼
    OnSend   OnResolving OnConnecting OnFirstSending OnFirstReceiving
    Start    NameTick   Tick       Tick         Tick
    Tick

    Latency Metrics:
      MAPSGenerateLatency  @ 0x109D1D70  (report build time)
      MAPSSendLatency      @ 0x109D1D98  (network send time)
      MAPSParseLatency     @ 0x109D1DB8  (response parse time)
      MAPSClientLatency    @ 0x109D1D4C  (total client time)
```

---

## MAPS Configuration and Policy

### SpyNet Reporting Levels

MAPS behavior is controlled by the SpyNet reporting level:

```
SpyNet Levels:
+-------+-------------------------------------------+
| Level | Behavior                                  |
+-------+-------------------------------------------+
| 0     | MAPS Off (MAPSOff @ 0x10A08980)           |
|       | No cloud queries, no sample submission    |
+-------+-------------------------------------------+
| 1     | Basic Membership                          |
|       | Send minimal metadata for lowfi lookups   |
+-------+-------------------------------------------+
| 2     | Advanced Membership                       |
|       | Send full metadata + file samples when    |
|       | requested by cloud                        |
+-------+-------------------------------------------+
```

Registry paths for configuration:
- `SOFTWARE\Microsoft\Windows Defender\Spynet` @ `0x109C6D28`
- `SOFTWARE\Microsoft\Microsoft Antimalware\Spynet` @ `0x109C6CC8`
- `Software\Microsoft\MpScan\Spynet` @ `0x109C4C98`

### Cloud Block Levels

The cloud block level controls detection aggressiveness:

| Level | Value | Behavior |
|-------|-------|----------|
| Off | 0 | MAPS Off (`MAPSOff`) — no cloud queries |
| Default | 0 | Default blocking |
| Moderate | 1 | Moderate blocking |
| High | 2 | High blocking |
| High+ | 4 | High+ — additional protection measures |
| Zero Tolerance | 6 | Block all unknown executables |

- Registry: `MpCloudBlockLevel` / `cloudblocklevel`
- Kill switches: `SpynetKillSwitches`, `SpynetBondKillbit`, `SpynetBondResponseKillbit`

### Sample Submission Consent

| Setting | Behavior |
|---------|----------|
| Send safe samples automatically (default) | Auto-submits `.bat`, `.scr`, `.dll`, `.exe` |
| Send all samples automatically | Auto-submits all file types |
| Always Prompt | Asks user before uploading |
| Do not send | Never uploads samples |

- Registry: `SubmitSamplesConsent`
- Samples uploaded to regional Azure blob endpoints

### Configuration Parameters

| Parameter | Address | Purpose |
|-----------|---------|---------|
| `MpMaxSpynetReports` | `0x10A4EDF4` | Max concurrent reports in-flight |
| `MpDisableSyncSpynetCheck` | `0x10A0875C` | Disable synchronous check |
| `MpDisableOplocksInSpynet` | `0x10A3454C` | Disable file oplocks during report |
| `fastpathcachesize` | `0x109F2A34` | FASTPATH response cache size |
| `MpMapsNumThreads` | — | Thread pool for MAPS queries |
| `MpMapsNumThreadsDss` | — | DSS-specific thread pool |
| `MpAsyncDssQueryTimeout` | — | Async query timeout |
| `MpSyncDssQueryTimeout` | — | Sync lowfi query timeout |

---

## FASTPATH Cache

Cloud responses are cached locally to avoid redundant network requests:

```
FASTPATH Cache:
+-----------------------------------------------+
| fastpathcachesize   @ 0x109F2A34 (UTF-16)     |
| metastorelowficache @ 0x109C8CB0 (ASCII)      |
+-----------------------------------------------+
| Key:   SHA-256 of scanned file                |
| Value: FASTPATH_SDN/TDN/DATA from cloud       |
| TTL:   MP_FASTPATH_LOWFI_LIFETIME             |
|        @ 0x1098C998                            |
+-----------------------------------------------+
| On cache hit:                                 |
|   - Apply cached FASTPATH sigs directly       |
|   - Skip network request                      |
|   - "Defender_Engine_CachedSDN" @ 0x10A53BA8  |
+-----------------------------------------------+
```

---

## Sample Submission

When the cloud requests a file sample (at SpyNet level 2), the `Bond_SampleRequest` class (RTTI at `0x10C824F8`) handles the request:

```
Sample Request Flow:
+-----------------------------------------------+
| Cloud Response includes SampleRequest         |
| (Bond_SampleRequest @ 0x10C824F8)             |
+-----------------------------------------------+
              |
              v
+-----------------------------------------------+
| Check SpyNet reporting level                  |
| Level 2 required for sample submission        |
+-----------------------------------------------+
              |
              v
+-----------------------------------------------+
| Upload file content to MAPS                   |
| (encrypted, compressed)                       |
+-----------------------------------------------+
```

Related strings:
- `"SIGNATURE_TYPE_SAMPLE_REQUEST"` @ `0x10986EA0`
- `"SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME"` @ `0x10986408`

---

## MpCommu.dll HTTP Transport

The actual HTTP transport for MAPS queries is handled by a companion DLL — `MpCommu.dll` — located alongside mpengine.dll. The engine uses this DLL for all network communication:

```
Network Stack:
+--------------------------------------------------+
| mpengine.dll                                     |
|   Build SpynetReport                             |
|   Bond serialize → CompactBinaryV1 blob          |
|   Call MpCommu.dll transport functions            |
+--------------------------------------------------+
              |
              v
+--------------------------------------------------+
| MpCommu.dll                                      |
|   TLS/HTTPS connection management                |
|   Certificate pinning                            |
|   Connection pooling                             |
|   Retry logic with backoff                       |
|   POST to fastpath.wdcp.microsoft.com            |
+--------------------------------------------------+
              |
              v
+--------------------------------------------------+
| Network → Microsoft MAPS backend                 |
| fastpath.wdcp.microsoft.com                      |
+--------------------------------------------------+
```

---

## Error Handling and Resilience

### MAPS Failure Handling

```
Error Handling:
+-----------------------------------------------+
| Network failure                               |
|   - Record LastMAPSFailureTime @ 0x109D24E8   |
|   - Keep lowfi detection as-is                |
|   - Do NOT upgrade to full detection          |
+-----------------------------------------------+
| Deserialization failure                       |
|   - "BondDeserializationFailure" @ 0x109D9A70 |
|   - "Engine.Maps.BondDeserializationFailure"   |
|     @ 0x109D9A47                               |
|   - Drop response, keep lowfi                 |
+-----------------------------------------------+
| MAPS disabled                                 |
|   - "MAPSOff" @ 0x10A08980                    |
|   - "Spynet is off when trying to generate    |
|      AzSubmit feedback report" @ 0x10A08988    |
|   - Skip entire Stage 12                      |
+-----------------------------------------------+
| Success                                       |
|   - Record LastMAPSSuccessTime @ 0x109D24C0   |
|   - Apply FASTPATH signatures                 |
|   - Cache response                            |
+-----------------------------------------------+
```

---

## Detection Log Strings

Strings related to detection management during MAPS processing:

| String | Address | Description |
|--------|---------|-------------|
| `An SDN signature was received` | `0x10A0CBD0` | SDN received confirmation (UTF-16) |
| `BM detection upgraded to threat detection.` | `0x10A66498` | BM lowfi → real threat (UTF-16) |
| `BM detection NOT upgraded to threat detection.` | `0x10A664F0` | BM lowfi stays lowfi (UTF-16) |
| `BM detection suppressed due to friendlyness.` | `0x10A666C0` | Friendly suppression (UTF-16) |
| `BM detection suppressed due to exclusion.` | `0x10A66880` | Exclusion suppression (UTF-16) |
| `BM detection suppressed due to cache.` | `0x10A668F0` | Cache suppression (UTF-16) |
| `Queueing detection.` | `0x10A6671C` | Detection queued (UTF-16) |
| `unable to find detection details.` | `0x10A66450` | Detection details missing (UTF-16) |

*(from RE of mpengine.dll — detection log string references)*

---

## Additional Report Types

Beyond lowfi reports, the MAPS protocol supports several other report types:

### Heartbeat Reports

Periodic health check reports sent at configurable intervals:
- `Engine.Maps.Heartbeat` event
- Source: `SCANSOURCE_HEARTBEAT`
- Configurable: `MpMapsHeartbeatRate`, `MpMapsHeartbeatDelay`, `MpMapsHeartbeatDetectionInterval`
- Heartbeat variants: Setup, Mpsigstub, Test, Uninstall, DefenderDisable, MapsDisable, Error, Exclusions, RtpChange, Enhanced, OfflineEnhanced, PaidEnhanced
- Each variant has a killswitch (`SpynetKillSwitches`)

### URL Reputation Queries

- Class: `UrlReputationMaps` (RTTI: `.?AVUrlReputationMaps@@`)
- Traces: `Engine.Maps.UrlRepParseFailure`, `Engine.Maps.UrlRepTimeout`, `Engine.Maps.UrlRepSendLatency`
- Config: `MpDisableUrlReputationMaps`, `MpDisableUrlReputationMapsCache`

### WDO (Windows Defender Offline) Reports

- Trace: `Engine.Maps.SendWdoReport`
- Throttled: `MpMapsWdoDetectionThrottlingInterval`

### Sync vs Async Lowfi

- **Async lowfi** (`TYPE_ASYNC_LOWFI`): Non-blocking — scan continues while report uploads
- **Sync lowfi** (`TYPE_SYNC_LOWFI`): Blocking — waits for cloud verdict before returning result, timeout configurable via `MpSyncDssQueryTimeout`
- **Telemetry-only**: No action taken — data collection only (`telemetryonly=1`)

---

## Certificate Pinning

The MAPS TLS connection uses certificate pinning for security:

| Parameter | Description |
|-----------|-------------|
| `MpPublicRootThumbs` | SHA-1 thumbprints of trusted root CA certificates |
| `MpPublicDisallowedThumbs` | Denylist of rejected certificate thumbprints |
| `MpPublicKeys` | SHA-256 of SPKI public key hashes |

### SSLOptions Registry Configuration

Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SSLOptions` (DWORD)

| Value | Meaning |
|-------|---------|
| 0 | Disable pinning AND revocation checks |
| 1 | Disable pinning only |
| 2 | Disable revocation checks only |
| 3 | Enable both (default) |

CRL infrastructure uses AME root CAs:
- `http://crl.microsoft.com/pkiinfra/crl/ameroot.crl`
- Backup CRLs: `crl1.ame.gbl`, `crl2.ame.gbl`, `crl3.ame.gbl`

---

## SpynetReport Metadata Fields

The SpynetReport includes multiple hash types and metadata:

### File Hash Fields

| Hash | Description |
|------|-------------|
| `Sha256` | Full file SHA-256 |
| `Sha1` | Full file SHA-1 |
| `ClusterHash` | MpInternal cluster hash |
| `Crc16` | 16-bit CRC |
| `Ctph` | Context-triggered piecewise hash (fuzzy hash) |
| `ImpHash` | Import hash (PE import table) |
| `Lshash` | Locality-sensitive hash |
| `PartialCrc1/2/3` | Partial CRC values (section-based) |
| `AuthentiCodeHash` | Authenticode hash |

### STREAM_ATTRIBUTE Types (selected)

72 STREAM_ATTRIBUTE types control report content, including 8 AMSI-specific:

| Attribute | Description |
|-----------|-------------|
| `STREAM_ATTRIBUTE_URL` | URL being scanned |
| `STREAM_ATTRIBUTE_THREAT_ID` | Matched threat ID |
| `STREAM_ATTRIBUTE_LOFI` | Lowfi detection data |
| `STREAM_ATTRIBUTE_SCANREASON` | Reason for the scan |
| `STREAM_ATTRIBUTE_HAS_MOTW_ADS` | Mark-of-the-Web alternate data stream |
| `STREAM_ATTRIBUTE_TRUST_LEVEL` | Trust level |
| `STREAM_ATTRIBUTE_AMSI_SESSION_ID` | AMSI session ID |
| `STREAM_ATTRIBUTE_AMSI_APP_ID` | AMSI app ID |
| `STREAM_ATTRIBUTE_AMSI_CONTENT_NAME` | AMSI content name |
| `STREAM_ATTRIBUTE_AMSI_REDIRECT_CHAIN` | AMSI redirect chain |

---

## Cross-References

- **Stage 3-11 (All Prior Stages)** — Lowfi detections from any stage can trigger MAPS lookup
- **Stage 10 (Lua Scripts)** — `mp.setlowfi()` can explicitly trigger MAPS lookup
- **Stage 11 (AAGGREGATOR)** — AAGGREGATOR lowfi detections also trigger MAPS
- **Stage 13 (Verdict Resolution)** — FASTPATH results merged into final verdict
- **MpCommu.dll** — HTTP transport companion DLL

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Production endpoint | `fastpath.wdcp.microsoft.com` @ `0x10A09EC0` |
| PPE endpoint | `fastpath.wdcpppe.microsoft.com` @ `0x10A09EF8` |
| Serialization format | Bond CompactBinaryV1 @ `0x10C823C4` |
| FASTPATH sig types | 4 (SDN, SDN_EX, TDN, DATA) |
| Report types | 7 (Async Lowfi, Sync Lowfi, Telemetry, Sample, Heartbeat, URL Rep, WDO) |
| Latency telemetry fields | 20+ |
| Bond RTTI classes | 100+ entity types |
| STREAM_ATTRIBUTE types | 72 (8 AMSI-specific) |
| SpyNet report strings | 17+ |
| Cloud block levels | 5 (Off, Moderate, High, High+, Zero Tolerance) |
| Configuration parameters | 15+ |
| Certificate pinning | SHA-1 root thumbs + SHA-256 SPKI pins |
