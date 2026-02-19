# Stage 9: BRUTE Matching

## Overview

BRUTE (Broad Raw Universal Threat Extraction) is the format-agnostic hash-string
matching engine that operates on the raw byte content of scanned objects. Unlike
PEHSTR (which targets specific PE sections like `.text`, `.data`, and imports),
BRUTE matches against the entire raw data stream regardless of file format.

This makes BRUTE essential for detecting polymorphic, encrypted, and packed malware
where the threat indicators exist in the raw byte stream rather than in structured
file format sections. BRUTE results are also the primary input for Lua scripts
(Stage 10) that implement complex multi-condition detection logic.

**Position in Pipeline:** Stage 9 -- after script deobfuscation (Stage 8), before
Lua script evaluation (Stage 10).

**Key Insight:** BRUTE is designed to work on content that has already been through
all prior stages: PE emulation, container extraction, and script deobfuscation. It
therefore matches against unpacked, extracted, and deobfuscated content -- the
"final form" of the data before behavioral/heuristic analysis.

---

## Entry Conditions

BRUTE matching runs on every scan object that reaches Stage 9. There is no format
filter -- BRUTE is intentionally format-agnostic. It processes:

1. Raw file data (any format)
2. Deobfuscated script content from NScript (Stage 8)
3. Unpacked PE content from emulation (Stage 6)
4. Extracted container children (Stage 7)
5. AMSI buffer content

The only gate is whether BRUTE signatures exist in the loaded VDM
(Virus Definition Module) for the current scan context.

---

## Key String References

### Signature Types

| String | Address | Purpose |
|--------|---------|---------|
| `SIGNATURE_TYPE_BRUTE` | `0x10986D8C` | Primary BRUTE signature type |
| `SIGNATURE_TYPE_NSCRIPT_BRUTE` | `0x10986AB0` | BRUTE sigs for NScript output |

### Feature Extraction Prefixes

| String | Address | Purpose |
|--------|---------|---------|
| `BRUTE:PDF:Feature:` | `0x10A54CC8` | PDF-specific feature extraction |
| `BRUTE:VBS:Feature:` | `0x10A54D08` | VBScript-specific features |
| `BRUTE:JS:Feature:` | `0x10A54D1C` | JScript-specific features |

### HSTR (Hash String) Infrastructure

| String | Address | Purpose |
|--------|---------|---------|
| `HSTR_WEIGHT` | `0x1097C6D0` | Weight value for HSTR match scoring |
| `GetHSTRCallerId` | `0x1097F460` | Function: identify HSTR caller context |
| `NID_ENABLE_HSTR_EXHAUSTIVE` | `0x10980A50` | Config: enable exhaustive HSTR matching |

### HSTR Caller Identifiers

| String | Address | Purpose |
|--------|---------|---------|
| `HSTR_CALLER_UNKNOWN` | `0x109812AC` | Unknown/default caller |
| `HSTR_CALLER_FILE` | `0x109812C0` | Called from file scan |
| `HSTR_CALLER_EMS` | `0x109812D4` | Called from EMS (emulator) |
| `HSTR_CALLER_HOOKWOW` | `0x109812F8` | Called from WoW64 hook |
| `HSTR_CALLER_SMS` | `0x10981308` | Called from SMS (system monitor) |
| `HSTR_CALLER_CMDLINE` | `0x1098131C` | Called from command line scan |
| `HSTR_CALLER_TSKSCHED_CMDLINE` | `0x1098133C` | Called from task scheduler cmdline |
| `HSTR_CALLER_BITS_CMDLINE` | `0x10981350` | Called from BITS cmdline |

### Related Signature Types

| String | Address | Purpose |
|--------|---------|---------|
| `SIGNATURE_TYPE_PEHSTR` | `0x109869C8` | PE-specific HSTR (contrast: PE-only) |
| `SIGNATURE_TYPE_PEHSTR_EXT` | `0x10986618` | Extended PE HSTR |
| `SIGNATURE_TYPE_PEHSTR_EXT2` | `0x109863EC` | PE HSTR extension v2 |
| `SIGNATURE_TYPE_MACHOHSTR_EXT` | `0x109861D8` | Mach-O HSTR matching |
| `SIGNATURE_TYPE_DEXHSTR_EXT` | `0x10986430` | DEX (Android) HSTR matching |
| `SIGNATURE_TYPE_SWFHSTR_EXT` | `0x10986DF8` | SWF (Flash) HSTR matching |
| `SIGNATURE_TYPE_MACROHSTR_EXT` | `0x109870A0` | Office macro HSTR matching |
| `SIGNATURE_TYPE_JAVAHSTR_EXT` | `0x109870EC` | Java class HSTR matching |
| `SIGNATURE_TYPE_ARHSTR_POSIX_EXT` | `0x10986F20` | POSIX archive HSTR |
| `SIGNATURE_TYPE_ASCRIPTHSTR_EXT` | `0x109864D4` | AutoScript HSTR matching |

---

## BRUTE vs. PEHSTR: Architecture Comparison

```
+---------------------------------------------+---------------------------------------------+
|              PEHSTR                          |              BRUTE                          |
+---------------------------------------------+---------------------------------------------+
| Format-aware: PE sections only               | Format-agnostic: raw bytes                  |
| Targets .text, .data, imports, exports       | Targets the entire data stream               |
| SIGNATURE_TYPE_PEHSTR @ 0x109869C8           | SIGNATURE_TYPE_BRUTE @ 0x10986D8C           |
| Fast: searches structured regions            | Thorough: searches everything               |
| Cannot see packed/encrypted content          | Works on unpacked/deobfuscated content      |
| Primary for known PE malware                 | Primary for polymorphic/script malware      |
| Results: direct detection                    | Results: often input to Lua scripts         |
+---------------------------------------------+---------------------------------------------+
```

PEHSTR operates early in the pipeline (Stage 3) on structured PE data. BRUTE
operates late (Stage 9) on the raw content after all transformations. They are
complementary: PEHSTR catches known PE malware quickly, while BRUTE catches
the variants that evade structural matching.

---

## HSTR Matching Engine

BRUTE uses the HSTR (Hash String) matching engine, which is the core string
matching infrastructure shared across multiple signature types. The HSTR engine:

1. Computes rolling hashes over the input data
2. Matches against a precompiled hash table from VDM signatures
3. On hash hit, performs full string comparison to confirm
4. Records match position, length, and signature ID
5. Computes a weighted score based on `HSTR_WEIGHT` (`0x1097C6D0`)

### HSTR Caller Context

The `GetHSTRCallerId` function (`0x1097F460`) determines which pipeline context
is invoking HSTR matching. This allows the same HSTR engine to be used by
multiple stages with different matching profiles:

```
Caller ID                    Context                    Matching Profile
---------                    -------                    ----------------
HSTR_CALLER_FILE             File scan (Stage 3)        PE-structured matching
HSTR_CALLER_EMS              Emulator (Stage 5)         Post-emulation matching
HSTR_CALLER_HOOKWOW          WoW64 hook                 Process memory matching
HSTR_CALLER_SMS              System monitor             Behavioral event matching
HSTR_CALLER_CMDLINE          Command line               Command string matching
HSTR_CALLER_TSKSCHED_CMDLINE Task scheduler             Scheduled task cmdline
HSTR_CALLER_BITS_CMDLINE     BITS jobs                  BITS job cmdline
HSTR_CALLER_UNKNOWN          Default                    Generic matching
```

When BRUTE invokes HSTR, it uses context-specific caller IDs so the engine
can select the appropriate signature subset and matching parameters.

### Exhaustive Mode

The `NID_ENABLE_HSTR_EXHAUSTIVE` flag at `0x10980A50` enables exhaustive
matching mode where:
- ALL possible matches are found (not just the first)
- Overlapping matches are recorded
- Match positions are tracked precisely
- Higher computational cost but complete coverage

This is used when Lua scripts need to analyze the distribution or count
of specific patterns in the data.

---

## Per-Format Feature Extraction

BRUTE includes specialized feature extraction for specific content types.
These features are deposited as attributes that Lua scripts can evaluate:

### PDF Features

```
"BRUTE:PDF:Feature:" @ 0x10A54CC8
```

PDF features extracted include:
- JavaScript presence and size
- Embedded file presence
- Suspicious action chains (`/OpenAction`, `/AA`)
- Unusual filter chains
- Object stream anomalies
- XFA form presence

### VBScript Features

```
"BRUTE:VBS:Feature:" @ 0x10A54D08
```

VBScript features extracted include:
- Shell execution patterns (`WScript.Shell`, `Shell.Application`)
- File system access patterns (`FileSystemObject`)
- Network access patterns (`XMLHTTP`, `WinHTTP`)
- Registry access patterns (`RegRead`, `RegWrite`)
- Obfuscation indicators (Chr() density, string operations)

### JScript Features

```
"BRUTE:JS:Feature:" @ 0x10A54D1C
```

JScript features extracted include:
- `ActiveXObject` creation patterns
- `eval()` usage frequency
- `WScript.Shell` invocations
- DOM manipulation patterns
- Encoded content detection
- Base64 pattern density

---

## Matching Algorithm

### High-Level Flow

```
 +-------------------+
 |  Input Data       |
 |  (raw bytes)      |
 +-------------------+
         |
         v
 +-------------------+
 |  HSTR Hash Table  |  Precompiled from SIGNATURE_TYPE_BRUTE entries
 |  Lookup           |  in the VDM (Virus Definition Module)
 +-------------------+
         |
         v
 +-------------------+
 |  Rolling Hash     |  Slide window over input, compute hash
 |  Computation      |  at each position
 +-------------------+
         |
         v
 +-------------------+
 |  Hash Hit?        |---no---> Continue sliding
 |                   |
 +-------------------+
         | yes
         v
 +-------------------+
 |  Full String      |  Verify hash collision is a real match
 |  Comparison       |
 +-------------------+
         |
         v
 +-------------------+
 |  Record Match     |  Store: (sig_id, offset, length, weight)
 |  + Score          |
 +-------------------+
         |
         v
 +-------------------+
 |  Weight           |  Accumulate HSTR_WEIGHT scores per
 |  Accumulation     |  signature group
 +-------------------+
         |
         v
 +-------------------+
 |  Threshold Check  |  If accumulated weight >= threshold:
 |                   |  deposit attribute or trigger detection
 +-------------------+
         |
         v
 +-------------------+
 |  Feature Extract  |  For PDF/VBS/JS content, extract
 |  (per-format)     |  BRUTE:*:Feature: attributes
 +-------------------+
         |
         v
 +-------------------+
 |  Results to Lua   |  All BRUTE matches available to
 |  (Stage 10)       |  Lua scripts for complex logic
 +-------------------+
```

### Pseudocode

```c
// BRUTE matching engine

int brute_match(SCAN_REPLY *reply, SCAN_CONTEXT *ctx) {
    // 1. Load BRUTE signature hash table
    HSTR_TABLE *table = load_sig_table(SIGNATURE_TYPE_BRUTE);
                                    // ^ @ 0x10986D8C
    if (!table) return SCAN_CONTINUE;

    // 2. Also load NScript-specific BRUTE table if applicable
    HSTR_TABLE *nscript_table = NULL;
    if (ctx->is_nscript_output) {
        nscript_table = load_sig_table(SIGNATURE_TYPE_NSCRIPT_BRUTE);
                                    // ^ @ 0x10986AB0
    }

    // 3. Initialize HSTR matcher
    HSTR_CONTEXT hstr;
    hstr_init(&hstr, table, ctx->scan_depth);

    // 4. Determine caller ID for context
    int caller_id = get_hstr_caller_id(ctx);
                                    // ^ GetHSTRCallerId @ 0x1097F460

    // 5. Check for exhaustive mode
    bool exhaustive = get_nid_flag(NID_ENABLE_HSTR_EXHAUSTIVE);
                                    // ^ @ 0x10980A50

    // 6. Perform rolling hash matching over raw data
    uint8_t *data = ctx->file_data;
    uint32_t size = ctx->file_size;

    MATCH_LIST matches;
    match_list_init(&matches);

    for (uint32_t offset = 0; offset < size; offset++) {
        // 6a. Compute rolling hash at current position
        uint32_t hash = rolling_hash(data, offset, size);

        // 6b. Lookup in BRUTE hash table
        HSTR_ENTRY *entry = hstr_lookup(&hstr, hash);
        if (!entry) continue;

        // 6c. Full string comparison to confirm
        if (memcmp(data + offset, entry->pattern, entry->pattern_len) != 0)
            continue;

        // 6d. Record the match
        MATCH_RECORD match = {
            .sig_id  = entry->sig_id,
            .offset  = offset,
            .length  = entry->pattern_len,
            .weight  = entry->weight,    // HSTR_WEIGHT @ 0x1097C6D0
        };
        match_list_add(&matches, &match);

        // 6e. Accumulate weight for this signature group
        hstr_accumulate_weight(&hstr, entry->sig_group, entry->weight);

        // 6f. In non-exhaustive mode, skip past this match
        if (!exhaustive) {
            offset += entry->pattern_len - 1;
        }
    }

    // 7. Also match against NScript BRUTE table if present
    if (nscript_table) {
        hstr_match_all(&hstr, nscript_table, data, size, &matches);
    }

    // 8. Evaluate weight thresholds
    for (int g = 0; g < hstr.group_count; g++) {
        if (hstr.group_weights[g] >= hstr.group_thresholds[g]) {
            // Threshold met: deposit detection or attribute
            deposit_brute_result(reply, ctx, hstr.groups[g]);
        }
    }

    // 9. Per-format feature extraction
    extract_brute_features(reply, ctx, &matches);
    // Sets BRUTE:PDF:Feature:*, BRUTE:VBS:Feature:*, BRUTE:JS:Feature:*

    // 10. Make all matches available to Lua (Stage 10)
    ctx->brute_matches = matches;

    return reply->threat_found ? SCAN_DETECTED : SCAN_CONTINUE;
}
```

---

## Weight-Based Scoring

BRUTE uses a weighted scoring system rather than simple pattern presence/absence.
Each HSTR entry has an associated weight (`HSTR_WEIGHT` at `0x1097C6D0`), and
matches are accumulated per signature group.

### Scoring Model

```
Signature Group: "TrojanDropper:Script/Obfuse"
  Pattern                     Weight
  -------------------------   ------
  "WScript.Shell"             +30
  "ActiveXObject"             +20
  "eval(unescape"             +40
  "fromCharCode"              +15
  "XMLHTTP"                   +10
  "%TEMP%"                    +5
  -------------------------   ------
  Threshold:                  >= 80

  If a script contains WScript.Shell (+30), eval(unescape (+40),
  and fromCharCode (+15) = 85 >= 80 threshold => MATCH
```

This weighted approach:
- Reduces false positives from single-string matches
- Handles polymorphic variants that change some but not all indicators
- Allows graduated confidence levels
- Enables complex "if 3 of these 7 patterns" logic without Lua

---

## BRUTE for Script Content (NSCRIPT_BRUTE)

The `SIGNATURE_TYPE_NSCRIPT_BRUTE` (`0x10986AB0`) is a specialized BRUTE variant
that operates specifically on NScript-normalized content. The difference from
standard BRUTE:

| Aspect | SIGNATURE_TYPE_BRUTE | SIGNATURE_TYPE_NSCRIPT_BRUTE |
|--------|---------------------|----------------------------|
| Input | Raw file bytes | Deobfuscated script text |
| Timing | After all transforms | After NScript Stage 8 |
| Target | Any format | Script content only |
| Patterns | Binary patterns | Text/string patterns |
| Use case | Polymorphic malware | Obfuscated scripts |

NSCRIPT_BRUTE runs after deobfuscation ensures the patterns match the
cleaned-up script rather than the obfuscated form. This is essential because:
- Obfuscated scripts have no stable byte patterns
- After normalization, the underlying API calls and strings are exposed
- The same malware family always normalizes to similar patterns

---

## Format-Specific HSTR Variants

The binary contains HSTR matching variants for multiple file formats, each
operating on format-specific data regions:

```
Format-Specific HSTR Hierarchy:

HSTR (base matching engine)
  |
  +-- SIGNATURE_TYPE_BRUTE          @ 0x10986D8C   (format-agnostic, raw bytes)
  |
  +-- SIGNATURE_TYPE_NSCRIPT_BRUTE  @ 0x10986AB0   (script content)
  |
  +-- SIGNATURE_TYPE_PEHSTR         @ 0x109869C8   (PE: .text/.data)
  |     +-- PEHSTR_EXT              @ 0x10986618   (PE: extended sections)
  |     +-- PEHSTR_EXT2             @ 0x109863EC   (PE: additional regions)
  |
  +-- SIGNATURE_TYPE_MACHOHSTR_EXT  @ 0x109861D8   (Mach-O binaries)
  |
  +-- SIGNATURE_TYPE_DEXHSTR_EXT    @ 0x10986430   (Android DEX)
  |
  +-- SIGNATURE_TYPE_SWFHSTR_EXT    @ 0x10986DF8   (Flash SWF)
  |
  +-- SIGNATURE_TYPE_MACROHSTR_EXT  @ 0x109870A0   (Office macros)
  |
  +-- SIGNATURE_TYPE_JAVAHSTR_EXT   @ 0x109870EC   (Java classes)
  |
  +-- SIGNATURE_TYPE_ARHSTR_POSIX_EXT @ 0x10986F20 (POSIX archives)
  |
  +-- SIGNATURE_TYPE_ASCRIPTHSTR_EXT  @ 0x109864D4 (AutoScript)
```

BRUTE is distinguished from these format-specific variants by its
**universal application** -- it runs on ALL content types and matches
against the complete raw byte stream.

---

## Integration with Lua Scripts (Stage 10)

BRUTE match results are the primary mechanism by which Lua scripts implement
complex detection logic. The flow:

```
Stage 9 (BRUTE)                    Stage 10 (Lua)
+------------------+               +---------------------------+
| Match pattern A  |               | if mp.bcrp_match("A") and |
| Match pattern C  |  ------>      |    mp.bcrp_match("C") and |
| Match pattern F  |   results     |    not mp.bcrp_match("D") |
+------------------+               |    then DETECT            |
                                   +---------------------------+
```

Lua scripts use the BRUTE match API to:
- Check if specific patterns were found
- Get match counts for frequency analysis
- Get match offsets for positional analysis
- Combine BRUTE results with attributes from other stages
- Implement complex boolean logic beyond what AAGG can express

---

## Data Structures

### HSTR Table Entry

```c
// Hash string table entry (reconstructed)
struct HSTR_ENTRY {
    uint32_t hash;              // Precomputed hash of pattern
    uint32_t sig_id;            // Signature identifier
    uint32_t sig_group;         // Signature group (for weight accumulation)
    uint8_t  *pattern;          // Raw pattern bytes
    uint16_t pattern_len;       // Pattern length
    uint16_t weight;            // Match weight (HSTR_WEIGHT)
    uint16_t flags;             // Match flags (case-insensitive, etc.)
};
```

### HSTR Context

```c
// HSTR matching context (reconstructed)
struct HSTR_CONTEXT {
    HSTR_TABLE  *table;             // Loaded signature table
    uint32_t    group_count;        // Number of signature groups
    uint32_t    *group_weights;     // Accumulated weight per group
    uint32_t    *group_thresholds;  // Threshold per group
    void        **groups;           // Group metadata
    int         caller_id;          // HSTR_CALLER_* value
    bool        exhaustive;         // NID_ENABLE_HSTR_EXHAUSTIVE
};
```

### Match Record

```c
// Individual match record
struct MATCH_RECORD {
    uint32_t sig_id;            // Which signature matched
    uint32_t offset;            // Offset in data where match occurred
    uint32_t length;            // Length of match
    uint16_t weight;            // Weight of this match
    uint16_t flags;             // Match flags
};
```

### Match List

```c
// Collected matches from a BRUTE scan
struct MATCH_LIST {
    MATCH_RECORD *records;      // Array of match records
    uint32_t     count;         // Number of matches
    uint32_t     capacity;      // Allocated capacity
    uint32_t     total_weight;  // Sum of all match weights
};
```

---

## Performance Characteristics

### Complexity

BRUTE matching has O(n * m) worst-case complexity where:
- n = input data size
- m = number of patterns in the hash table

However, the rolling hash approach provides amortized O(n) performance for
typical inputs, since hash table lookups are O(1) and collisions are rare
with a well-designed hash function.

### Optimization Strategies

1. **Rolling hash:** Avoid recomputing the full hash at each position
2. **Hash table sizing:** Power-of-2 tables for fast modulo via bitmask
3. **Bloom filter pre-check:** Quick rejection of positions that cannot match
4. **Early termination:** Stop after high-confidence detection (configurable)
5. **Region skipping:** Skip known-clean regions (e.g., PE header) for BRUTE
6. **Caller-specific tables:** Only load relevant signature subsets

---

## The Full SIGNATURE_TYPE Taxonomy

The binary contains 162 distinct `SIGNATURE_TYPE_*` strings, representing the
complete taxonomy of signature matching approaches. BRUTE and NSCRIPT_BRUTE
are positioned among them as:

```
Signature Type Categories:
  1. Hash-based:        KCRCE, LOCALHASH, BLOOM_FILTER
  2. Structure-based:   PEHSTR, PESTATIC, PEBMPAT, IL_PATTERN
  3. Format-specific:   MACHOHSTR, DEXHSTR, SWFHSTR, JAVAHSTR, MACROHSTR
  4. Behavior-based:    FOP, THREAD_X86, TUNNEL_X86, VBFOP
  5. Script-based:      NSCRIPT_SP, NSCRIPT_BRUTE, NSCRIPT_CURE
  6. Universal:         BRUTE (format-agnostic raw matching) <<<
  7. Infrastructure:    DBVAR, VDLL_X86, VDLL_MSIL, VDLL_SYMINFO
  8. Cloud:             FASTPATH_SDN_EX, FASTPATH_TDN
  9. Policy:            REMOVAL_POLICY, REMOVAL_POLICY64, DEFAULTS
  10. Metadata:         VDM_METADATA, DATABASE_CATALOG, RESEARCH_TAG
```

BRUTE occupies category 6 as the universal matching engine that complements
all format-specific matchers.

---

## Cross-References

### Inputs from Stage 8 (Script Deobfuscation)

NScript-normalized script content is the primary input for NSCRIPT_BRUTE:
- Deobfuscated PowerShell commands
- Resolved VBScript function calls
- Unwrapped JScript eval() chains
- Expanded Batch variable substitutions

### Outputs to Stage 10 (Lua Scripts)

BRUTE match results power Lua-based detection:
- Match lists (pattern ID, offset, weight)
- Feature attributes (`BRUTE:PDF:Feature:*`, etc.)
- Accumulated weight scores per signature group

### Outputs to Stage 11 (AAGG Evaluation)

BRUTE-deposited attributes participate in AAGG boolean expressions:
- `SIGNATURE_TYPE_AAGGREGATOREX` at `0x10986E28`
- BRUTE match presence can be a term in aggregation rules

### Relationship with Stage 3 (Static Engines)

BRUTE complements the static engines by providing:
- Raw-data matching that static engines skip
- Post-transformation matching
- Feature extraction for ML classification (BRUTE:*:Feature:* attributes feed into SigTree decision trees — see [SigTree ML (SS14)](14_sigtree_ml_classification.md))

---

## Summary

BRUTE matching is the format-agnostic safety net in the Defender scan pipeline.
While format-specific engines (PEHSTR, MACHOHSTR, DEXHSTR) provide fast targeted
matching for known file types, BRUTE ensures that no content passes through the
pipeline without thorough raw-byte pattern analysis.

Key takeaways:
- **Format-agnostic:** Matches against raw bytes regardless of file type
- **Weight-based scoring:** Multiple weak indicators combine to threshold
- **HSTR engine:** Rolling hash with full confirmation on hash hits
- **8 caller contexts:** Different matching profiles per pipeline stage
- **NSCRIPT_BRUTE variant:** Specialized for deobfuscated script content
- **Feature extraction:** Per-format features (PDF, VBS, JS) for ML
- **Lua integration:** Primary data source for complex Lua detection logic
- **10+ format-specific siblings:** Part of a family of HSTR matchers
- **162 total signature types** in the complete Defender taxonomy
