# Windows Defender Scan Pipeline — Master Overview

> Complete end-to-end walkthrough of the 13-stage scan pipeline inside `mpengine.dll`.
> All data from reverse engineering mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

> **Note:** If it wasn't obvious, this knowledge base was created as an LLM-driven experiment — the documentation, slide decks, and structural analysis were generated with significant AI assistance. The content will be iterated on and improved over time as findings are validated and refined through hands-on reverse engineering.

---

## Architecture Summary

Windows Defender's scan engine is a single monolithic DLL — `mpengine.dll` (14.3 MB) — that processes every file, script, and buffer scanned on a Windows machine. The scan pipeline is a sequential 13-stage architecture where each stage can produce detections, collect attributes for later stages, or recursively invoke the entire pipeline on extracted/unpacked content.

### Key Data Structures

```
ScanContext {
    file_data:     &[u8],              // Raw file bytes
    file_path:     Option<&str>,       // Original file path
    file_size:     u64,                // File size
    content_type:  ContentType,        // Detected content type
    scan_depth:    u32,                // Recursion depth counter
    attributes:    HashSet<String>,    // Collected AAGGREGATOR attributes
    threat_list:   Vec<ThreatRecord>,  // Accumulated detections
    pe_info:       Option<PeMetadata>, // Parsed PE header data
    emulator_ctx:  Option<EmuContext>, // Emulation results
    scan_flags:    u32,                // Scan configuration flags
}

ThreatRecord {
    threat_id:     u64,     // Unique threat identifier
    threat_name:   String,  // e.g. "Trojan:Win32/Emotet.RPX!MTB"
    severity:      u8,      // 1=Low, 2=Medium, 4=High, 5=Severe
    category:      u8,      // Virus, Trojan, Worm, etc.
    is_infra:      bool,    // !-prefix = infrastructure marker
}
```

---

## Entry Points

mpengine.dll exposes a small set of exported functions that serve as the API for the scan pipeline:

| Export | Address | Purpose |
|--------|---------|---------|
| `__rsignal` | `0x10133CD0` | Primary scan dispatch (command router) |
| `rsignal` | `0x102BF000` | Secondary scan dispatch (newer API) |
| `MpBootStrap` | `0x102BD660` | Engine initialization |
| `MpContainerOpen` | `0x102BCF00` | Container analysis API |
| `MpContainerAnalyze` | `0x102BCB80` | Container scan entry |
| `MpContainerRead` | `0x102BD120` | Container data read |
| `GetSigFiles` | `0x102BEE10` | Signature file enumeration |
| `FreeSigFiles` | `0x102BEDD0` | Signature file cleanup |

### __rsignal Command Router (0x10133CD0)

The `__rsignal` export is the primary entry point. It receives a command code in `[ebp+0xc]` and dispatches:

```asm
; __rsignal @ 0x10133CD0
push  ebp
mov   ebp, esp
and   esp, 0xFFFFFFF8       ; Align stack to 8
mov   eax, [ebp+0xc]       ; Command code
cmp   eax, 0x4003           ; BOOT_ENGINE
je    dispatch_handler
cmp   eax, 0x400B           ; SCAN_BUFFER
je    dispatch_handler
cmp   eax, 0x4019           ; SCAN_AMSI
je    dispatch_handler
; ... (other commands fall through to sub-dispatch at 0x10133D35)
```
Key command codes:
- `0x4003` — Boot engine (initialize VDM database, load signatures)
- `0x400B` — Scan buffer (primary scan API)
- `0x4019` — Scan AMSI content
- `0x4036` — Scan file (newer rsignal path)
- `0x4047` — Extended scan with options
- `0x4052` — Direct scan dispatch via rsignal
- `0x4059` — Initialize/reset engine state

### rsignal Dispatch (0x102BF000)

The `rsignal` export provides additional command routing:

```asm
; rsignal @ 0x102BF000
push  ebp
mov   ebp, esp
and   esp, 0xFFFFFFF8
cmp   byte [0x10CA5654], 0  ; Engine initialized flag
push  esi
mov   esi, [ebp+8]          ; Command code
push  edi
je    init_first             ; Jump to init if not yet booted
mov   edx, 0x4052           ; SCAN_DISPATCH
cmp   esi, edx
jne   check_other_cmds
; ... dispatch to scan handler at 0x102BEF4D
```
---

## The 13-Stage Pipeline

```
File/Buffer Input
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 1: Entry Point (§01)                                      │
│  __rsignal / rsignal dispatch → command routing → scan init      │
│  Addresses: 0x10133CD0 (__rsignal), 0x102BF000 (rsignal)        │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 2: FRIENDLY_FILE Whitelist Bypass (§02)                   │
│  SHA-256 hash → whitelist lookup → skip scanning if clean        │
│  Strings: "SIGNATURE_TYPE_FRIENDLYFILE_SHA256" @ 0x10986BE4      │
│           "isfriendlyscan" @ 0x1097ECFC                          │
└────────┬─────────────────────────────────────────────────────────┘
         │ (not whitelisted)
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 3: Static Engine Cascade (§03)                            │
│  11 engines in speed order: FILENAME → STATIC → SNID → KCRCE →  │
│  PE_STATIC → NID → BM_STATIC → PE_BM_PAT → PEHSTR → IL → KPAT  │
│  String: "SIGNATURE_TYPE_STATIC" @ 0x109860DC                    │
│          "SIGNATURE_TYPE_PEHSTR" @ 0x109869C8                    │
│          "SIGNATURE_TYPE_KCRCE" @ 0x109868B4                     │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 4: AAGGREGATOR Attribute Collection (§04)                 │
│  Engines deposit attributes into a HashSet as they run.          │
│  !-prefixed names = infrastructure markers (never standalone).   │
│  String: "SIGNATURE_TYPE_AAGGREGATOR" @ 0x10986B3C               │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 5: PE Emulation (§05)                                     │
│  x86/x64 CPU emulator with 198 WinAPI handlers.                 │
│  Maps PE sections, resolves imports via 973 VDLLs.               │
│  Records FOP (opcode trace) and APICLOG (API behavior).          │
│  500K instruction limit per execution.                           │
│  RTTI: ".?AVx86_IL_emulator@@" @ 0x10C748CC                     │
│  String: "reemulate" @ 0x10981878                                │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 6: Unpacked Content Scanning (§06)                        │
│  Scan modified PE sections and VFS-dropped files post-emulation. │
│  Recursively feeds unpacked content through the full pipeline.   │
│  String: "Engine.Scan.Unpacker" @ 0x109C6068                    │
│          "dt_continue_after_unpacking" @ 0x10984D1C              │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 7: Container Extraction (§07)                             │
│  Detect format via magic bytes → extract children → recurse.     │
│  25+ formats: ZIP, RAR, 7z, OLE2, PDF, CAB, ISO, CHM, etc.     │
│  Depth-limited via DBVAR configuration.                          │
│  RTTI: ".?AVIL_container@@" @ 0x10C7A778                        │
│  String: "containertype" @ 0x109E7CA8                            │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 8: Script Deobfuscation (§08)                             │
│  4 languages: PowerShell, VBScript, JScript, Batch               │
│  Multi-pass fixed-point iteration (up to 32 passes).             │
│  Each deobfuscated layer scanned through all static engines.     │
│  String: "NScript:ForceTypePS" @ 0x10A7813C                     │
│          "NScript:ForceTypeVBS" @ 0x10A781C8                     │
│          "NScript:ForceTypeJS" @ 0x10A781F8                      │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 9: BRUTE Matching (§09)                                   │
│  Format-agnostic HSTR matching for polymorphic/encrypted malware.│
│  BRUTE results are made available to Lua scripts.                │
│  String: "SIGNATURE_TYPE_BRUTE" @ 0x10986D8C                    │
│          "SIGNATURE_TYPE_NSCRIPT_BRUTE" @ 0x10986AB0             │
│          "BRUTE:PDF:Feature:" @ 0x10A54CC8                       │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 10: Lua Script Engine (§10)                               │
│  59,415 Lua 5.1 detection scripts from VDM.                     │
│  106 mp.* API functions + 14 MpCommon.* functions.               │
│  Scripts can read files, check attributes, set detections.       │
│  String: "Lua 5.1" @ 0x1098C124                                 │
│          "LuaStandalone" @ 0x109C806C                            │
│          "Engine.Scan.LuaExecute" @ 0x10A33930                   │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 11: AAGGREGATOR Evaluation (§11)                          │
│  Boolean expression evaluator over collected attributes.         │
│  Operators: & (AND), | (OR), ! (NOT), parentheses.              │
│  String: "SIGNATURE_TYPE_AAGGREGATOR" @ 0x10986B3C               │
│          "SIGNATURE_TYPE_AAGGREGATOREX" @ 0x10986E28              │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  CROSS-CUTTING: SigTree ML Classification (§14)                  │
│  33,428 decision trees evaluate sigattr boolean features.        │
│  JIT-compiled into native x86 for speed. Produces !ml/!MTB.     │
│  String: "sigtree" @ 0x109C80B0                                 │
│          "SIGNATURE_TYPE_SIGTREE" @ 0x10986C88                   │
│          "sigattr_head" @ 0x1097D710                              │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 12: MAPS Cloud Lookup (§12)                               │
│  Lowfi match → Bond serialize → HTTPS POST → parse response.    │
│  Delivers FASTPATH dynamic signatures (SDN, TDN, DATA).         │
│  String: "MAPS" @ 0x109C546C                                    │
│          "BondSerializer" @ 0x109C80E0                           │
│          "fastpath" @ 0x109C8D38                                 │
│          "MAPSURL" @ 0x109CB000                                  │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  STAGE 13: Verdict Resolution (§13)                              │
│  Merge multiple detections → select highest severity →           │
│  produce final threat name and action recommendation.            │
│  Priority: Severe(5) > High(4) > Medium(2) > Low(1)             │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
    Final Verdict: Clean / Malware / PUA / Lowfi
```

---

## Pipeline Statistics

| Metric | Value | Source |
|--------|-------|--------|
| Total exports | 90 | export table |
| FPU emulation functions | 66 | `FPU_*` exports |
| Binary size | 14.3 MB | PE header |
| Total threats defined | 358,756 | VDM TLV index |
| PEHSTR rules | 117,563 | VDM index |
| KCRCE entries | 691,145 | VDM index |
| MD5 static hashes | 2,433,812 | VDM index |
| Lua detection scripts | 59,415 | VDM LUASTANDALONE |
| Virtual DLLs | 973 | VDM VDLL entries |
| Virtual files | 144 | VDM VFILE entries |
| DBVARs (config entries) | 547 | VDM DBVAR entries |
| FOP behavioral rules | 4,601 | VDM FOP entries |
| SIG_TREE ML trees | 33,428 | VDM SIG_TREE + EXT + BM |
| Threat name prefixes | 504 | VDM prefix table |
| TLV entries | 9.3M | Across 4 VDM files |
| Signature types | 158+ | TLV type constants |
| WinAPI handlers | 198 | Emulator dispatch |
| Container formats | 25+ | Extraction framework |
| Script languages | 4 | PS, VBS, JS, Batch |
| Deobfuscation transforms | 1,358 | Across 4 languages |

---

## Stage Interaction Map

```
                              ┌──────────────────────────────────────┐
                              │       VDM Signature Database          │
                              │  (mpavbase.vdm + mpasbase.vdm)       │
                              │  9.3M TLV → indexed lookup tables    │
                              └────────┬──────────────┬──────────────┘
                                       │              │
                    ┌──────────────────┘              └──────────┐
                    │                                             │
                    ▼                                             ▼
        ┌───────────────────┐                         ┌──────────────────┐
        │  Static Engines    │                         │  Lua Scripts      │
        │  (Stage 3)         │──── attributes ────────▶│  (Stage 10)       │
        └───────────────────┘                         └──────────────────┘
                    │                                             │
                    │ attributes                                  │ attributes
                    ▼                                             ▼
        ┌───────────────────────────────────────────────────────────────┐
        │                  AAGGREGATOR Attribute Set                     │
        │            HashSet<String> — all engines contribute           │
        └───────────────────────────┬───────────────────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  AAGGREGATOR Eval      │
                        │  (Stage 11)            │
                        │  Boolean expressions   │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  MAPS Cloud            │
                        │  (Stage 12)            │
                        │  Lowfi → Cloud verdict │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  Final Verdict         │
                        │  (Stage 13)            │
                        └───────────────────────┘
```

### Recursive Scan Paths

Three stages can trigger recursive re-scanning through the entire pipeline:

1. **Stage 6 (Unpacked Content)** — Modified PE sections and VFS-dropped files after emulation are fed back through the full pipeline starting at Stage 2.

2. **Stage 7 (Container Extraction)** — Each extracted child file from a container (ZIP entry, OLE2 stream, etc.) is scanned recursively. Depth is controlled by DBVAR settings.

3. **Stage 8 (Script Deobfuscation)** — Each deobfuscated layer is scanned through Stages 3-10 independently. Up to 32 deobfuscation passes per script.

---

## Decision Points

### When does PE emulation trigger?
- Only when the input is detected as a PE file (MZ header + valid PE signature)
- Configurable via `pea_disable_static_unpacking` and `pea_force_unpacking` attributes
- Can be re-triggered via `reemulate` flag after initial scan

### When does cloud lookup happen?
- Only when a "lowfi" detection is produced (heuristic match, not high-confidence)
- Only when MAPS is enabled (requires `--maps` flag or Group Policy)
- Sends file hashes + scan metadata to `fastpath.wdcp.microsoft.com`
- Response can upgrade verdict with FASTPATH dynamic signatures

### When do containers get extracted?
- When format detection identifies a supported archive/document format
- Controlled by `containertype` attribute and magic byte detection
- Depth limited by DBVAR `max_depth` (default varies by scan type)
- AMSI scans use shallow extraction (depth 1, max 50 items, 10MB)

### Short-circuit behavior
- FRIENDLY_FILE match → skip entire pipeline
- High-confidence static detection → may skip emulation (configurable)
- Container extraction errors → logged but scanning continues
- Script deobfuscation fixed-point → stops when output stabilizes

---

## Cross-Reference Index

| Section | Document | Slides |
|---------|----------|--------|
| 01 — Entry Point | [01_entry_point.md](01_entry_point.md) | [01_entry_point_slides.html](../slides/01_entry_point_slides.html) |
| 02 — FRIENDLY_FILE | [02_friendly_file.md](02_friendly_file.md) | [02_friendly_file_slides.html](../slides/02_friendly_file_slides.html) |
| 03 — Static Engine Cascade | [03_static_engine_cascade.md](03_static_engine_cascade.md) | [03_static_engine_cascade_slides.html](../slides/03_static_engine_cascade_slides.html) |
| 04 — AAGGREGATOR Collection | [04_aaggregator_collection.md](04_aaggregator_collection.md) | [04_aaggregator_collection_slides.html](../slides/04_aaggregator_collection_slides.html) |
| 05 — PE Emulation | [05_pe_emulation.md](05_pe_emulation.md) | [05_pe_emulation_slides.html](../slides/05_pe_emulation_slides.html) |
| 06 — Unpacked Content | [06_unpacked_content.md](06_unpacked_content.md) | [06_unpacked_content_slides.html](../slides/06_unpacked_content_slides.html) |
| 07 — Container Extraction | [07_container_extraction.md](07_container_extraction.md) | [07_container_extraction_slides.html](../slides/07_container_extraction_slides.html) |
| 08 — Script Deobfuscation | [08_script_deobfuscation.md](08_script_deobfuscation.md) | [08_script_deobfuscation_slides.html](../slides/08_script_deobfuscation_slides.html) |
| 09 — BRUTE Matching | [09_brute_matching.md](09_brute_matching.md) | [09_brute_matching_slides.html](../slides/09_brute_matching_slides.html) |
| 10 — Lua Scripts | [10_lua_scripts.md](10_lua_scripts.md) | [10_lua_scripts_slides.html](../slides/10_lua_scripts_slides.html) |
| 11 — AAGGREGATOR Evaluation | [11_aaggregator_evaluation.md](11_aaggregator_evaluation.md) | [11_aaggregator_evaluation_slides.html](../slides/11_aaggregator_evaluation_slides.html) |
| 12 — MAPS Cloud Lookup | [12_maps_cloud_lookup.md](12_maps_cloud_lookup.md) | [12_maps_cloud_lookup_slides.html](../slides/12_maps_cloud_lookup_slides.html) |
| 13 — Verdict Resolution | [13_verdict_resolution.md](13_verdict_resolution.md) | [13_verdict_resolution_slides.html](../slides/13_verdict_resolution_slides.html) |

---

## Global Data References

| Global Variable | Address | Purpose |
|----------------|---------|---------|
| Engine context pointer | `0x10C707B0` | Points to main engine state structure |
| Engine initialized flag | `0x10CA5654` | Byte flag: 0=not init, 1=initialized |
| Stack cookie | `0x10C6F880` | Security cookie for stack protection |

---

*Generated from reverse engineering of mpengine.dll v1.1.24120.x*
