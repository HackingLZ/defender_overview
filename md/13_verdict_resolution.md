# Stage 13 — Verdict Resolution

> Reverse engineering documentation for the verdict resolution stage inside `mpengine.dll`.
> All addresses, strings, and structures from RE of mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 13 is the **final stage** of the scan pipeline — **verdict resolution**. After all 12 prior stages have produced their detections, attributes, and cloud results, the verdict resolver takes the complete set of accumulated `ThreatRecord` entries and produces a single, definitive answer: is this file malicious, and if so, what is it?

The verdict resolution process involves:

1. **Merging** detections from all stages into a single list
2. **Filtering** infrastructure markers (! prefix) that are never reported to the user
3. **Deduplicating** overlapping detections
4. **Ranking** by severity to select the highest-priority threat
5. **Resolving** the final threat name, severity, category, and recommended action
6. **Returning** the result to the caller (MpSvc, AMSI client, etc.)

---

## Entry Conditions

Stage 13 executes after all prior stages have completed, including the optional MAPS cloud lookup:

```
                All Stages Complete
              (Stages 1-12 finished)
                        |
                        v
            +-----------------------+
            | Collect all detections|
            | from threat_list      |
            +-----------------------+
                        |
                        v
            +-----------------------+
            | Filter infra markers  |
            | (remove !-prefixed)   |
            +-----------------------+
                        |
                        v
            +-----------------------+
            | Deduplicate           |
            | (merge overlapping)   |
            +-----------------------+
                        |
                        v
            +-----------------------+
            | Rank by severity      |
            | Severe > High >       |
            | Medium > Low          |
            +-----------------------+
                        |
                        v
            +-----------------------+
            | Resolve final verdict |
            | threat_name, severity |
            | category, action      |
            +-----------------------+
                        |
                        v
            +-----------------------+
            | Return to caller      |
            | (MpSvc / AMSI / API)  |
            +-----------------------+
```

---

## Key Strings from mpengine.dll

### Threat Identification Strings

| String | Address | Section | Type | Description |
|--------|---------|---------|------|-------------|
| `threatname` | `0x109D44AC` | .rdata | UTF-16 | Threat name field |
| `threatname` | `0x109DA6AC` | .rdata | ASCII | Threat name field |
| `threatid` | `0x109DA464` | .rdata | UTF-16 | Threat ID field |
| `threatid` | `0x109DA6B8` | .rdata | ASCII | Threat ID field |
| `threatidex` | `0x109E68EC` | .rdata | UTF-16 | Extended threat ID |
| `originalthreatid` | `0x109E7A2C` | .rdata | UTF-16 | Original threat ID |
| `threatseverity` | `0x109DA50C` | .rdata | UTF-16 | Threat severity field |
| `threatseverity` | `0x109DA6D4` | .rdata | ASCII | Threat severity field |
| `threatcategory` | `0x109DA478` | .rdata | UTF-16 | Threat category field |
| `threatcategory` | `0x109DA688` | .rdata | ASCII | Threat category field |
| `threatadvice` | `0x109DA554` | .rdata | UTF-16 | Recommended action |
| `threatadvice` | `0x109DA664` | .rdata | ASCII | Recommended action |
| `threatadviceinfoid` | `0x109DA5EC` | .rdata | UTF-16 | Action info ID |
| `threatadviceinfoid` | `0x109DA698` | .rdata | ASCII | Action info ID |
| `threatlevel` | `0x109E4380` | .rdata | UTF-16 | Threat level |
| `threatlevel` | `0x109E4470` | .rdata | ASCII | Threat level |

*(from RE of mpengine.dll — threat field string references)*

### Severity/Severity Strings

| String | Address | Section | Type |
|--------|---------|---------|------|
| `severity` | `0x109E5450` | .rdata | UTF-16 |
| `severity` | `0x109E54CC` | .rdata | ASCII |
| `threatseverity` | `0x109DA50C` | .rdata | UTF-16 |
| `threatseverity` | `0x109DA6D4` | .rdata | ASCII |

*(from RE of mpengine.dll — severity string references)*

### Tracking Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `threattrackingid` | `0x109D3DD0` | UTF-16 | Per-detection tracking ID |
| `threattrackingid` | `0x109DD570` | ASCII | Per-detection tracking ID |
| `consolidatedthreattrackingids` | `0x109D3E20` | UTF-16 | Merged tracking IDs |
| `consolidatedthreattrackingids` | `0x109DD458` | ASCII | Merged tracking IDs |

*(from RE of mpengine.dll — threat tracking string references)*

### Detection Management Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `detectionname` | `0x109DD874` | UTF-16 | Detection name field |
| `detectionname` | `0x109DD92C` | ASCII | Detection name field |
| `detections.log` | `0x109C5F10` | UTF-16 | Detection log file |
| `detections-%d.log` | `0x109C5EEC` | UTF-16 | Numbered detection log |
| `trustdetections.log` | `0x109C5FD8` | UTF-16 | Trust detection log |
| `trustdetections-%d.log` | `0x109C5FA8` | UTF-16 | Numbered trust log |
| `excludedthreats` | `0x109E4380` | UTF-16 | Excluded threats list |
| `excludedthreats` | `0x109E24A0` | ASCII | Excluded threats list |
| `currentqsdetectioncount` | `0x109F0F18` | UTF-16 | Quick scan detection count |

*(from RE of mpengine.dll — detection management string references)*

### Verdict/Detection Event Strings

| String | Address | Description |
|--------|---------|-------------|
| `verdict:%d;codesigningflags:%u,signer:%s,cdhash:%s,teamid:%s` | `0x10A662A0` | Verdict format string (macOS-style codesign) |
| `changedetectionname` | `0x1097ED34` | Change detection name command |
| `changedetectionrecid` | `0x1097ED48` | Change detection record ID |
| `get_detectionstatus` | `0x1097EEB4` | Get detection status command |

*(from RE of mpengine.dll — verdict/detection event strings)*

### Detection Upgrade/Suppression Strings

| String | Address | Type | Description |
|--------|---------|------|-------------|
| `BM detection upgraded to threat detection.` | `0x10A66498` | UTF-16 | BM → threat upgrade |
| `BM detection NOT upgraded to threat detection.` | `0x10A664F0` | UTF-16 | BM stays as-is |
| `BM detection suppressed due to friendlyness.` | `0x10A666C0` | UTF-16 | Friendly file suppression |
| `BM detection suppressed due to exclusion.` | `0x10A66880` | UTF-16 | Exclusion suppression |
| `BM detection suppressed due to cache.` | `0x10A668F0` | UTF-16 | Cache-based suppression |
| `Queueing detection.` | `0x10A6671C` | UTF-16 | Detection queued |
| `unable to find detection details.` | `0x10A66450` | UTF-16 | Missing details error |
| `Lowfi detection supressed` | `0x10A536B0` | ASCII | Lowfi suppression |

*(from RE of mpengine.dll — detection management strings)*

### Engine.Det Event Strings

| String | Address | Description |
|--------|---------|-------------|
| `Engine.Det.PuaDetection` | `0x10A34170` | PUA (Potentially Unwanted Application) detection |
| `Engine.Det.BMLuaSigattr` | `0x10A49468` | BM Lua signature attribute detection |
| `Engine.Det.MoacNotSigned` | `0x10A4B490` | MOAC not-signed detection |
| `Engine.Det.AutoFolderLatent` | `0x10A4D7FC` | Auto-folder latent detection |
| `Engine.Det.LowfiNonInt` | `0x10A53670` | Non-interactive lowfi |
| `Engine.Det.LowfiTrusted` | `0x10A536E0` | Trusted lowfi |
| `Engine.Det.InsideTxf` | `0x10A54498` | Inside TxF (transactional NTFS) |
| `Engine.Det.ExhaustiveScriptScan` | `0x10A77F28` | Exhaustive script scan |
| `Engine.Det.PythonInfected` | `0x10A78300` | Python infection |
| `Engine.Det.JsEmuEval` | `0x10A784CC` | JavaScript emulation eval |
| `Engine.Det.TokenizerError` | `0x10A78668` | Tokenizer error |
| `Engine.Det.ScriptDetError` | `0x10A78690` | Script detection error |
| `Engine.Det.ChainedObjectCount` | `0x10A78738` | Chained object count |
| `Engine.Det.LuaFolderLatent` | `0x10B6B598` | Lua folder latent detection |

*(from RE of mpengine.dll — Engine.Det ETW event strings)*

---

## Severity Levels

The threat severity is a numeric value that determines priority during verdict resolution. The highest severity among all detections wins:

```
Severity Hierarchy (highest wins):
+-------+----------+-------------------------------------+
| Value | Level    | Description                         |
+-------+----------+-------------------------------------+
|   5   | Severe   | Worms, ransomware, rootkits        |
|       |          | Immediate action required            |
+-------+----------+-------------------------------------+
|   4   | High     | Trojans, backdoors, exploits        |
|       |          | Significant threat to system         |
+-------+----------+-------------------------------------+
|   2   | Medium   | Spyware, browser modifiers          |
|       |          | Privacy/security impact              |
+-------+----------+-------------------------------------+
|   1   | Low      | Adware, potentially unwanted apps   |
|       |          | Minor impact, may be intentional    |
+-------+----------+-------------------------------------+
|   0   | Unknown  | Severity not yet determined          |
|       |          | (pre-cloud lookup)                   |
+-------+----------+-------------------------------------+
```

Note: There is no severity level 3 — the scale jumps from 2 (Medium) to 4 (High). This mirrors the Windows Defender threat severity model exposed through WMI and the Security Center.

---

## Threat Categories

Each detection carries a category that classifies the type of threat:

```
Threat Categories:
+----------+-----------------------+-------------------------------+
| Category | Name                  | Examples                      |
+----------+-----------------------+-------------------------------+
| 0        | Invalid/Unknown       |                               |
| 1        | Adware                | BrowserModifier:Win32/...     |
| 2        | Spyware               | Spyware:Win32/...             |
| 3        | Password Stealer      | PWS:Win32/...                 |
| 4        | Trojan Downloader     | TrojanDownloader:Win32/...    |
| 5        | Worm                  | Worm:Win32/...                |
| 6        | Backdoor              | Backdoor:Win32/...            |
| 7        | Remote Access Trojan  | RemoteAccess:Win32/...        |
| 8        | Trojan                | Trojan:Win32/...              |
| 9        | Email Flooder         | EmailFlooder:Win32/...        |
| 10       | Keylogger             | Keylogger:Win32/...           |
| 11       | Dialer                | Dialer:Win32/...              |
| 12       | Monitoring Software   | MonitoringTool:Win32/...      |
| 13       | Browser Modifier      | BrowserModifier:Win32/...     |
| 14       | Cookie                | Cookie:Win32/...              |
| 19       | Software Bundler      | SoftwareBundler:Win32/...     |
| 21       | Exploit               | Exploit:Win32/...             |
| 27       | Trojan (FTP)          | TrojanFTP:Win32/...           |
| 30       | Virus                 | Virus:Win32/...               |
| 34       | Tool                  | HackTool:Win32/...            |
| 36       | Trojan Dropper        | TrojanDropper:Win32/...       |
| 37       | Remote Exploit        | Exploit:Win32/...             |
| 40       | Ransomware            | Ransom:Win32/...              |
| 42       | PUA (PUP)             | PUA:Win32/...                 |
| 43       | Potentially Unwanted  | PUA:Win32/...                 |
+----------+-----------------------+-------------------------------+
```

*(categories inferred from threat naming conventions and Engine.Det strings)*

---

## Threat Name Format

Defender threat names follow a standardized format:

```
Threat Name Format:
    [Category]:[Platform]/[Family].[Variant]![Suffix]

Examples:
    Trojan:Win32/Emotet.RPX!MTB
    Virus:Win32/Virut.CE
    Ransom:Win32/WannaCrypt.A
    PUA:Win32/Softcnapp
    HackTool:Win64/Mimikatz.A!dha
    Backdoor:MSIL/Bladabindi!pz

Components:
    Category  = Threat classification (Trojan, Virus, Ransom, etc.)
    Platform  = Target platform (Win32, Win64, MSIL, JS, VBS, etc.)
    Family    = Malware family name
    Variant   = Specific variant letter/identifier
    Suffix    = Detection method (!MTB=ML, !dha=dynamic heuristic, etc.)
```

### Detection Suffixes

| Suffix | Meaning |
|--------|---------|
| `!MTB` | Machine Learning / Tree-Based model — produced by SigTree decision tree ensemble. See [SigTree ML (SS14)](14_sigtree_ml_classification.md) |
| `!ml` | Machine Learning detection — produced by SigTree classification. See [SS14](14_sigtree_ml_classification.md) |
| `!dha` | Dynamic Heuristic Analysis |
| `!pz` | Pattern-based heuristic |
| `!rfn` | Real-time File Notification |
| `!cl` | Cloud-delivered detection |
| (none) | Traditional signature match |

---

## Infrastructure Marker Filtering

The most critical step in verdict resolution is filtering out infrastructure markers — detections with the `!` prefix that were used as AAGGREGATOR building blocks but must never be reported to the user:

```c
// Pseudocode: Infrastructure marker filtering
// Reconstructed from decompilation

void FilterInfraMarkers(ThreatList* threats) {
    for (int i = threats->count - 1; i >= 0; i--) {
        ThreatRecord* rec = &threats->entries[i];

        // Check if threat name starts with '!'
        if (rec->threat_name[0] == '!') {
            rec->is_infra = true;
            // Mark for removal from final output
            // These are NEVER reported to the user
        }
    }
}
```

### Example

```
Before Filtering (from ScanContext.threat_list):
+------+--------------------------------------------+----------+
| #    | Threat Name                                | Is Infra |
+------+--------------------------------------------+----------+
| 1    | !SuspiciousImportTable                     | YES      |
| 2    | !HighEntropyText                           | YES      |
| 3    | !NotSignedByTrustedPub                     | YES      |
| 4    | Trojan:Win32/AgentTesla.RPX!MTB            | NO       |
| 5    | !PESmallFile                               | YES      |
| 6    | TrojanDownloader:Win32/AgentTesla.DA       | NO       |
+------+--------------------------------------------+----------+

After Filtering:
+------+--------------------------------------------+----------+
| #    | Threat Name                                | Severity |
+------+--------------------------------------------+----------+
| 4    | Trojan:Win32/AgentTesla.RPX!MTB            | 4 (High) |
| 6    | TrojanDownloader:Win32/AgentTesla.DA       | 4 (High) |
+------+--------------------------------------------+----------+

After Severity Ranking:
    Winner: Trojan:Win32/AgentTesla.RPX!MTB (or first with highest severity)
```

---

## Detection Deduplication

When the same file produces multiple detections (from different stages or different signatures targeting the same family), the resolver deduplicates:

```
Deduplication Rules:
+-----------------------------------------------+
| 1. Same threat name from different stages     |
|    → Keep the one with highest confidence     |
+-----------------------------------------------+
| 2. Same family, different variants            |
|    → Keep the highest-severity variant        |
+-----------------------------------------------+
| 3. Cloud-upgraded detection vs local lowfi    |
|    → Cloud result supersedes local            |
|    → "SDN/TDN matched, dropped detection"     |
|      @ 0x10A53EB0                             |
+-----------------------------------------------+
| 4. BM detection vs static detection           |
|    → Merge tracking IDs:                      |
|      consolidatedthreattrackingids            |
|      @ 0x109D3E20                             |
+-----------------------------------------------+
```

---

## Detection Suppression

Before finalizing the verdict, several suppression checks are applied:

```
Suppression Pipeline:
+-----------------------------------------------+
| 1. Exclusion Check                            |
|    "BM detection suppressed due to exclusion" |
|    @ 0x10A66880                               |
|    - User-configured exclusion paths/types    |
|    - excludedthreats @ 0x109E4380             |
+-----------------------------------------------+
| 2. Friendly File Check                        |
|    "BM detection suppressed due to friendlyness"|
|    @ 0x10A666C0                               |
|    - File is in trusted publisher list        |
|    - File is known-friendly (Stage 2 cache)   |
+-----------------------------------------------+
| 3. Cache Check                                |
|    "BM detection suppressed due to cache"     |
|    @ 0x10A668F0                               |
|    - Previous scan already resolved this file |
+-----------------------------------------------+
| 4. Lowfi Suppression                          |
|    "Lowfi detection supressed" @ 0x10A536B0   |
|    "Supressed lowfi per named attribute"      |
|    @ 0x10A53FE8                               |
|    - Cloud said file is clean                 |
|    - Named attribute indicates false positive |
+-----------------------------------------------+
```

---

## Verdict Data Structure

The final verdict is a structured result returned to the scan caller:

```c
// Reconstructed from analysis of verdict-related fields

struct ScanVerdict {
    // Primary result
    uint32_t  threat_id;         // "threatid" @ 0x109DA464
    uint32_t  threat_id_ex;      // "threatidex" @ 0x109E68EC
    uint32_t  original_threat_id;// "originalthreatid" @ 0x109E7A2C
    wchar_t*  threat_name;       // "threatname" @ 0x109D44AC
    wchar_t*  detection_name;    // "detectionname" @ 0x109DD874

    // Classification
    uint8_t   severity;          // "threatseverity" @ 0x109DA50C
    uint8_t   category;          // "threatcategory" @ 0x109DA478
    uint8_t   threat_level;      // "threatlevel" @ 0x109E4380

    // Recommended action
    wchar_t*  threat_advice;     // "threatadvice" @ 0x109DA554
    uint32_t  advice_info_id;    // "threatadviceinfoid" @ 0x109DA5EC

    // Tracking
    GUID      tracking_id;       // "threattrackingid" @ 0x109D3DD0
    wchar_t*  consolidated_ids;  // "consolidatedthreattrackingids" @ 0x109D3E20
};
```

*(structure reconstructed from RE of mpengine.dll — field name strings and access patterns)*

---

## Verdict Resolution Pseudocode

```c
// Pseudocode

ScanVerdict ResolveVerdict(ScanContext* ctx) {
    ThreatList* threats = &ctx->threat_list;

    // Step 1: Filter infrastructure markers
    FilterInfraMarkers(threats);

    // Step 2: Apply suppression rules
    for (int i = threats->count - 1; i >= 0; i--) {
        ThreatRecord* rec = &threats->entries[i];

        // Check exclusion list
        // "excludedthreats" @ 0x109E4380
        if (IsExcludedThreat(rec->threat_name, ctx->excluded_threats)) {
            // "BM detection suppressed due to exclusion." @ 0x10A66880
            RemoveThreat(threats, i);
            continue;
        }

        // Check friendly status
        if (ctx->is_friendly && rec->source == BM_DETECTION) {
            // "BM detection suppressed due to friendlyness." @ 0x10A666C0
            RemoveThreat(threats, i);
            continue;
        }

        // Check cache
        if (IsCachedClean(rec->file_hash)) {
            // "BM detection suppressed due to cache." @ 0x10A668F0
            RemoveThreat(threats, i);
            continue;
        }
    }

    // Step 3: Deduplicate
    DeduplicateThreats(threats);

    // Step 4: If no threats remain, return clean
    if (threats->count == 0) {
        return (ScanVerdict){ .threat_id = 0, .severity = 0 };
    }

    // Step 5: Select highest severity threat
    ThreatRecord* winner = NULL;
    for (int i = 0; i < threats->count; i++) {
        ThreatRecord* rec = &threats->entries[i];
        if (rec->is_infra) continue; // Skip infra markers

        if (!winner || rec->severity > winner->severity) {
            winner = rec;
        }
    }

    if (!winner) {
        return (ScanVerdict){ .threat_id = 0, .severity = 0 };
    }

    // Step 6: Build final verdict
    ScanVerdict verdict;
    verdict.threat_id     = winner->threat_id;
    verdict.threat_name   = winner->threat_name;
    verdict.severity      = winner->severity;
    verdict.category      = winner->category;
    verdict.threat_advice = GetAdviceForCategory(winner->category);
    verdict.tracking_id   = GenerateTrackingId();

    // Step 7: Consolidate tracking IDs from all merged detections
    // "consolidatedthreattrackingids" @ 0x109D3E20
    verdict.consolidated_ids = ConsolidateTrackingIds(threats);

    return verdict;
}
```


---

## Detection Upgrade Path

Detections can be upgraded during verdict resolution:

```
Detection Upgrade Flow:
+----------------------------------------------------+
| BM (Behavior Monitoring) Detection                 |
|                                                    |
| Local lowfi from BM →                              |
|   Check: is it backed by threat detection?         |
|                                                    |
|   YES: "BM detection upgraded to threat detection" |
|         @ 0x10A66498                               |
|         → Upgrade to full detection                |
|                                                    |
|   NO:  "BM detection NOT upgraded to threat        |
|         detection." @ 0x10A664F0                   |
|         → Stays as lowfi / dropped                 |
+----------------------------------------------------+
```

```
Cloud-Delivered Upgrade:
+----------------------------------------------------+
| Local lowfi detection                              |
|   + MAPS cloud returns FASTPATH_SDN                |
|     with full detection name                       |
|   → Lowfi upgraded to full detection               |
|   → Original lowfi entry removed                   |
|   → "SDN/TDN matched, dropped detection            |
|      for %ls (ThreatID=0x%08lx, SigSeq=0x%llx)"   |
|      @ 0x10A53EB0                                  |
+----------------------------------------------------+
```

---

## PUA (Potentially Unwanted Application) Handling

PUA detections have special handling in verdict resolution:

```
PUA Handling:
+----------------------------------------------------+
| Engine.Det.PuaDetection @ 0x10A34170               |
+----------------------------------------------------+
| PUA detections are subject to:                     |
|   1. PUA protection mode (block/audit/off)         |
|   2. Enterprise exclusion policies                 |
|   3. User-accepted PUA list                        |
|   4. Lower severity (typically Level 1)            |
+----------------------------------------------------+
| PUA verdict may be:                                |
|   - Blocked (if PUA protection = Block)            |
|   - Audited (logged but not blocked)               |
|   - Allowed (user chose to allow)                  |
+----------------------------------------------------+
```

---

## Verdict Output Consumers

The final verdict is consumed by multiple components:

```
Verdict Consumers:
+-----------------------------------------------+
| MpSvc (Windows Defender Service)              |
|   → Security Center notification              |
|   → Toast notification to user                |
|   → Action: quarantine / remove / allow       |
+-----------------------------------------------+
| AMSI Client                                   |
|   → Script host (PowerShell, WSH, etc.)       |
|   → Block/allow script execution              |
+-----------------------------------------------+
| WMI / ETW                                     |
|   → SIEM integration                          |
|   → Defender for Endpoint telemetry           |
+-----------------------------------------------+
| Detection Log                                 |
|   → detections.log @ 0x109C5F10              |
|   → trustdetections.log @ 0x109C5FD8         |
+-----------------------------------------------+
```

---

## Recommended Actions

The `threatadvice` field determines what action Defender recommends:

```
Recommended Actions:
+----------+------------------+----------------------------------+
| Action   | When             | Description                      |
+----------+------------------+----------------------------------+
| Remove   | Severity >= 4    | Delete the file entirely         |
|          | (High/Severe)    |                                  |
+----------+------------------+----------------------------------+
| Quarantine| Severity >= 2   | Move to quarantine folder        |
|          | (Medium+)        | (reversible)                     |
+----------+------------------+----------------------------------+
| Allow    | User override    | User chose to keep the file      |
|          | or PUA audit     |                                  |
+----------+------------------+----------------------------------+
| Clean    | Virus infection  | Remove malicious code, preserve  |
|          |                  | original file (disinfection)     |
+----------+------------------+----------------------------------+
```

---

## Signature Type Context

The verdict resolver understands which signature type produced each detection, which affects confidence and priority:

### Key Signature Types Relevant to Verdict

| Signature Type | Address | Priority |
|----------------|---------|----------|
| `SIGNATURE_TYPE_THREAT_BEGIN` | `0x10986DC0` | Marks start of threat definitions |
| `SIGNATURE_TYPE_THREAT_UPDATE_STATUS` | `0x10986F5C` | Threat update tracking |
| `SIGNATURE_TYPE_LATENT_THREAT` | `0x10986E48` | Latent (not-yet-confirmed) threat |
| `SIGNATURE_TYPE_FASTPATH_SDN` | `0x109869AC` | Cloud-delivered detection (highest confidence) |
| `SIGNATURE_TYPE_FASTPATH_TDN` | `0x1098647C` | Cloud-delivered threat name |
| `SIGNATURE_TYPE_AAGGREGATOR` | `0x10986B3C` | Boolean aggregation result |
| `SIGNATURE_TYPE_LUASTANDALONE` | `0x10987058` | Lua script detection |

*(from RE of mpengine.dll — SIGNATURE_TYPE string table)*

---

## Error Handling

| Error Condition | String | Address | Behavior |
|-----------------|--------|---------|----------|
| Missing detection details | `unable to find detection details.` | `0x10A66450` | Skip detection |
| Detection queue overflow | `Queueing detection.` | `0x10A6671C` | Queue for later processing |
| Tokenizer error | `Engine.Det.TokenizerError` | `0x10A78668` | Log and skip |
| Script detection error | `Engine.Det.ScriptDetError` | `0x10A78690` | Log and skip |

---

## End-to-End Pipeline Summary

```
Complete Pipeline Flow with Verdict:

  File/Buffer Input
        |
        v
  +--Stage 1--+   +--Stage 2--+   +--Stage 3--+   +--Stage 4--+
  |  Entry     |-->| FRIENDLY  |-->| Static    |-->| Attribute |
  |  Point     |   | FILE      |   | Cascade   |   | Collection|
  +------------+   +-----------+   +-----------+   +-----------+
                                        |                |
                                   Detections       Attributes
                                        |                |
                                        v                v
  +--Stage 5--+   +--Stage 6--+   +--Stage 7--+   +--Stage 8--+
  |  PE        |-->| Unpack    |-->| Container |-->| Script    |
  |  Emulation |   | Scan      |   | Extract   |   | Deob      |
  +------------+   +-----------+   +-----------+   +-----------+
       |                                                |
  FOP/TUNNEL                                     Deobfuscated
  Attributes                                        Content
       |                                                |
       v                                                v
  +--Stage 9--+   +--Stage 10-+   +--Stage 11-+   +--Stage 12-+
  |  BRUTE     |-->| Lua       |-->| AAGGREGATOR|-->| MAPS      |
  |  Force     |   | Scripts   |   | Evaluate  |   | Cloud     |
  +------------+   +-----------+   +-----------+   +-----------+
       |                |               |               |
   Detections      Attributes      Detections      FASTPATH
   Attributes      Detections      (composite)     Signatures
       |                |               |               |
       +-------+--------+-------+-------+-------+------+
               |                                 |
               v                                 v
        +----------------------------------------------+
        |           Stage 13: Verdict Resolution       |
        |                                              |
        | 1. Merge all detections                      |
        | 2. Filter infra markers (!)                  |
        | 3. Apply suppressions & exclusions           |
        | 4. Deduplicate                               |
        | 5. Rank by severity (5 > 4 > 2 > 1)         |
        | 6. Select winner                             |
        | 7. Return: name, severity, category, action  |
        +----------------------------------------------+
                            |
                            v
                    Final Verdict
              "Trojan:Win32/Foo.A"
              Severity: 4 (High)
              Action: Quarantine
```

---

## Cross-References

- **Stage 2 (FRIENDLY_FILE)** — Files passing friendly check skip directly to clean verdict
- **Stage 3-9** — All static and dynamic stages produce detections merged here
- **Stage 10 (Lua Scripts)** — `mp.fire()` detections merged into verdict
- **Stage 11 (AAGGREGATOR)** — Composite boolean detections and infra markers
- **Stage 12 (MAPS Cloud)** — FASTPATH SDN/TDN can override local detections
- **threatmgr** @ `0x109C7E58` — Threat manager orchestrates verdict resolution

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Severity levels | 5 (Severe=5, High=4, Medium=2, Low=1, Unknown=0) |
| Threat categories | 20+ |
| Suppression checks | 4 (exclusion, friendly, cache, lowfi) |
| Threat field strings | 16+ (name, id, severity, category, advice, tracking) |
| Detection log files | 4 (detections.log, trustdetections.log, numbered variants) |
| Engine.Det event types | 14+ |
