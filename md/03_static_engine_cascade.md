# Stage 03 -- Static Engine Cascade

> Reverse engineering documentation for **mpengine.dll** v1.1.24120.x
> Source of truth: the actual binary at `engine/mpengine.dll`
---

## 1. Overview

The Static Engine Cascade is the **core signature matching stage** of the scan pipeline.
After a file passes the FRIENDLY_FILE whitelist check (Stage 02), it enters a cascade of
**11 distinct signature engines**, each specialized for a different matching strategy.

These engines run in a defined order, sharing a common scan context. Each engine deposits
**attributes** (string tags) into the context, which downstream engines and the AAGGREGATOR
(Stage 11) can reference. A match at any stage can produce a detection, but the pipeline
continues to accumulate attributes for the aggregator's boolean evaluation.

The engine cascade is entirely **static** -- it operates on the raw file bytes without
emulation, script deobfuscation, or container extraction. Those dynamic stages come later.

---

## 2. Entry Conditions

The static cascade fires when:

1. The file failed the FRIENDLY_FILE check (not in the SHA-256/SHA-512 whitelist).
2. The scan context is initialized with file data, size, and content type.
3. The engine has loaded the corresponding VDM signature databases at boot time.

---

## 3. The 11 Static Engines

### 3.1 Engine Execution Order

| Order | Engine Name           | Signature Type String                  | Address       | Strategy                              |
|-------|-----------------------|----------------------------------------|---------------|---------------------------------------|
| 1     | **STATIC**            | `SIGNATURE_TYPE_STATIC`                | `0x109860DC`  | Legacy byte-pattern signatures        |
| 2     | **PEHSTR**            | `SIGNATURE_TYPE_PEHSTR`                | `0x109869C8`  | PE header string matching             |
| 3     | **PEHSTR_EXT**        | `SIGNATURE_TYPE_PEHSTR_EXT`            | `0x10986618`  | Extended PE header string matching    |
| 4     | **PEHSTR_EXT2**       | `SIGNATURE_TYPE_PEHSTR_EXT2`           | `0x109863EC`  | Second-gen extended PE header strings |
| 5     | **KCRCE**             | `SIGNATURE_TYPE_KCRCE`                 | `0x109868B4`  | Kernel CRC-based entry detection      |
| 6     | **KCRCEX**            | `SIGNATURE_TYPE_KCRCEX`                | `0x109871A4`  | Extended kernel CRC detection         |
| 7     | **PESTATIC**          | `SIGNATURE_TYPE_PESTATIC`              | `0x1098718C`  | PE static analysis rules              |
| 8     | **PESTATICEX**        | `SIGNATURE_TYPE_PESTATICEX`            | `0x10987210`  | Extended PE static analysis           |
| 9     | **BM_STATIC**         | `SIGNATURE_TYPE_BM_STATIC`             | `0x10986AE4`  | Behavioral monitoring static rules    |
| 10    | **BRUTE**             | `SIGNATURE_TYPE_BRUTE`                 | `0x10986D8C`  | Polymorphic / brute-force matching    |
| 11    | **NSCRIPT_BRUTE**     | `SIGNATURE_TYPE_NSCRIPT_BRUTE`         | `0x10986AB0`  | NScript brute-force matching          |

### 3.2 Supporting Engines (Run as Sub-Components)

These signature types are checked as part of the cascade but are sub-components
of the primary engines rather than standalone stages:

| Engine Name           | Signature Type String                  | Address       | Role                                  |
|-----------------------|----------------------------------------|---------------|---------------------------------------|
| **AAGGREGATOR**       | `SIGNATURE_TYPE_AAGGREGATOR`           | `0x10986B3C`  | Boolean expression evaluator          |
| **AAGGREGATOREX**     | `SIGNATURE_TYPE_AAGGREGATOREX`         | `0x10986E28`  | Extended boolean expression evaluator |
| **NID**               | `SIGNATURE_TYPE_NID`                   | `0x10986AD0`  | Network Inspection Detection          |
| **NID64**             | `SIGNATURE_TYPE_NID64`                 | `0x10987174`  | 64-bit NID variant                    |
| **BM_INFO**           | `SIGNATURE_TYPE_BM_INFO`               | `0x10986C58`  | Behavioral monitoring info records    |
| **SIGTREE**           | `SIGNATURE_TYPE_SIGTREE`               | `0x10986C88`  | ML decision tree classifier (~14,926 trees). See [SigTree ML (SS14)](14_sigtree_ml_classification.md) |
| **SIGTREE_EXT**       | `SIGNATURE_TYPE_SIGTREE_EXT`           | `0x10987008`  | Extended ML decision tree (~3,771 trees). See [SS14](14_sigtree_ml_classification.md) |
| **SIGTREE_BM**        | `SIGNATURE_TYPE_SIGTREE_BM`            | `0x109871D4`  | Behavioral monitoring ML trees (~14,731 trees). See [SS14](14_sigtree_ml_classification.md) |

---

## 4. Engine Details

### 4.1 STATIC Engine (Order 1)

**Signature Type**: `SIGNATURE_TYPE_STATIC` @ `0x109860DC`

The STATIC engine is the **oldest and most fundamental** matching engine. It performs
direct byte-pattern matching against the file content using pre-compiled pattern sets.

- **Input**: Raw file bytes.
- **Matching**: Multi-pattern matching (Aho-Corasick or similar compiled automaton).
- **Output**: Matched pattern IDs deposited as attributes.

This engine handles the classic "virus signature" use case: fixed byte sequences at
known offsets within the file.

Related configuration:
- `NID_DT_DISABLE_STATIC_UNPACKING` @ `0x10980C30`
- `NID_DT_ENABLE_STATIC_UNPACKING` @ `0x10980C50`

### 4.2 PEHSTR Engine (Order 2)

**Signature Type**: `SIGNATURE_TYPE_PEHSTR` @ `0x109869C8`

The PEHSTR (PE Header String) engine specializes in matching strings found within
PE (Portable Executable) headers. It extracts strings from:

- Import table (DLL names, function names)
- Export table
- Resource section strings
- Version information
- Debug directory paths

Each extracted string is matched against the PEHSTR signature database. Matches
produce `HSTR:` prefixed attributes.

### 4.3 PEHSTR_EXT Engine (Order 3)

**Signature Type**: `SIGNATURE_TYPE_PEHSTR_EXT` @ `0x10986618`

The extended PEHSTR engine adds:

- Wider string extraction (deeper section scanning)
- Regex-like pattern support for header strings
- Cross-section string correlation

### 4.4 PEHSTR_EXT2 Engine (Order 4)

**Signature Type**: `SIGNATURE_TYPE_PEHSTR_EXT2` @ `0x109863EC`

Second-generation extended header string matching. Adds:

- Unicode string extraction from PE sections
- Demangled C++ symbol matching
- Manifest and SxS assembly string matching

### 4.5 KCRCE Engine (Order 5)

**Signature Type**: `SIGNATURE_TYPE_KCRCE` @ `0x109868B4`

The KCRCE (Kernel CRC Entry) engine computes rolling CRC checksums over sections
of the file and matches them against a database of known-malicious CRC values.

- **Algorithm**: CRC-32 variants with different polynomial seeds.
- **Sections**: Code sections (.text), entry point region, header region.
- **Database**: Pre-computed CRC values for known malware entry point code.

The FileHashes table (@ `0x10A5B4A0`) stores KCRC1, KCRC2, KCRC3, and KCRC3n
values per file, corresponding to different CRC computation windows.

### 4.6 KCRCEX Engine (Order 6)

**Signature Type**: `SIGNATURE_TYPE_KCRCEX` @ `0x109871A4`

Extended kernel CRC detection. Uses larger CRC windows and additional hash
combinations to reduce false positives while maintaining detection of polymorphic
variants that share entry-point code patterns.

### 4.7 PESTATIC Engine (Order 7)

**Signature Type**: `SIGNATURE_TYPE_PESTATIC` @ `0x1098718C`

PE-specific static analysis rules that go beyond string and CRC matching:

- Section entropy analysis
- Import table anomaly detection
- PE header field validation (suspicious timestamp, section alignment)
- Overlay detection (data appended after last section)
- Rich header analysis

### 4.8 PESTATICEX Engine (Order 8)

**Signature Type**: `SIGNATURE_TYPE_PESTATICEX` @ `0x10987210`

Extended PE static analysis with additional checks:

- Authenticode signature validation
- Resource section anomaly detection
- Certificate chain analysis
- Manifest anomalies
- .NET metadata analysis (for MSIL binaries)

### 4.9 BM_STATIC Engine (Order 9)

**Signature Type**: `SIGNATURE_TYPE_BM_STATIC` @ `0x10986AE4`

Static rules for the Behavioral Monitoring subsystem. These detect patterns that
are precursors to malicious behavior without requiring actual runtime execution:

- Known packer signatures
- Anti-debug technique byte patterns
- Process injection shellcode patterns
- Suspicious API import combinations

Related strings:
- `BUILTIN:STATIC_MATCH_REPORT_AS_FRIENDLY` @ `0x10A4B4C0`

### 4.10 BRUTE Engine (Order 10)

**Signature Type**: `SIGNATURE_TYPE_BRUTE` @ `0x10986D8C`

The BRUTE engine handles **polymorphic** and **obfuscated** malware detection using
feature-based matching. Rather than fixed byte patterns, it extracts statistical
features from the file and matches against feature vectors.

Known BRUTE prefix strings from the binary:
- `BRUTE:PDF:Feature:` @ `0x10A54CC8`
- `BRUTE:VBS:Feature:` @ `0x10A54D08`
- `BRUTE:JS:Feature:` @ `0x10A54D1C`

The BRUTE engine operates on multiple file types:
- **PDF**: Extracts PDF structure features (stream counts, JavaScript presence, etc.)
- **VBS**: Extracts VBScript code features (obfuscation patterns, API calls)
- **JS**: Extracts JavaScript features (eval usage, string concatenation patterns)

### 4.11 NSCRIPT_BRUTE Engine (Order 11)

**Signature Type**: `SIGNATURE_TYPE_NSCRIPT_BRUTE` @ `0x10986AB0`

NScript-specific brute-force detection. Combines the BRUTE feature extraction
with the NScript engine's script analysis capabilities for detecting obfuscated
scripts that evade pattern-based detection.

Related signature types:
- `SIGNATURE_TYPE_NSCRIPT_NORMAL` @ `0x109865F8`
- `SIGNATURE_TYPE_NSCRIPT_SP` @ `0x10986328`
- `SIGNATURE_TYPE_NSCRIPT_CURE` @ `0x10986F40`

---

## 5. Additional Signature Types (Full Catalog)

The binary contains over 160 distinct `SIGNATURE_TYPE_*` strings. Here are additional
types relevant to static analysis, grouped by category:

### 5.1 File Format-Specific String Matchers

| Signature Type                         | Address       | Target Format        |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_MACHOHSTR_EXT`         | `0x109861D8`  | macOS Mach-O         |
| `SIGNATURE_TYPE_MACROHSTR_EXT`         | `0x109870A0`  | Office Macros        |
| `SIGNATURE_TYPE_JAVAHSTR_EXT`          | `0x109870EC`  | Java class files     |
| `SIGNATURE_TYPE_SWFHSTR_EXT`           | `0x10986DDC`  | Flash SWF            |
| `SIGNATURE_TYPE_DMGHSTR_EXT`           | `0x10986D58`  | macOS DMG            |
| `SIGNATURE_TYPE_INNOHSTR_EXT`          | `0x10986D20`  | Inno Setup           |
| `SIGNATURE_TYPE_DEXHSTR_EXT`           | `0x10986430`  | Android DEX          |
| `SIGNATURE_TYPE_ARHSTR_EXT`            | `0x10986978`  | Archive headers      |
| `SIGNATURE_TYPE_ARHSTR_POSIX_EXT`      | `0x10986F20`  | POSIX archive        |
| `SIGNATURE_TYPE_MDBHSTR_EXT`           | `0x10986B98`  | MDB database         |
| `SIGNATURE_TYPE_ASCRIPTHSTR_EXT`       | `0x109864D4`  | AutoScript           |

### 5.2 Behavioral and Emulation Support

| Signature Type                         | Address       | Purpose              |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_FOP`                   | `0x10986C44`  | Function-op patterns |
| `SIGNATURE_TYPE_FOPEX`                 | `0x10986514`  | Extended FOP         |
| `SIGNATURE_TYPE_FOP64`                 | `0x109871BC`  | 64-bit FOP           |
| `SIGNATURE_TYPE_VBFOP`                 | `0x10986074`  | VB function-op       |
| `SIGNATURE_TYPE_VBFOPEX`              | `0x109869F8`  | Extended VB FOP      |
| `SIGNATURE_TYPE_MSILFOP`              | `0x10986BCC`  | MSIL function-op     |
| `SIGNATURE_TYPE_PEPCODE`              | `0x10986994`  | PE p-code matching   |

### 5.3 Virtual DLL / Emulation Infrastructure

| Signature Type                         | Address       | Target Arch          |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_VDLL_X86`             | `0x10986360`  | x86 virtual DLLs     |
| `SIGNATURE_TYPE_VDLL_X64`             | `0x10986CF4`  | x64 virtual DLLs     |
| `SIGNATURE_TYPE_VDLL_ARM`             | `0x10986D74`  | ARM virtual DLLs     |
| `SIGNATURE_TYPE_VDLL_ARM64`           | `0x10986D3C`  | ARM64 virtual DLLs   |
| `SIGNATURE_TYPE_VDLL_MSIL`            | `0x10986F04`  | MSIL virtual DLLs    |
| `SIGNATURE_TYPE_VDLL_META`            | `0x10986648`  | DLL metadata         |
| `SIGNATURE_TYPE_VDLL_META_X64`        | `0x1098669C`  | x64 DLL metadata     |
| `SIGNATURE_TYPE_VDLL_META_MSIL`       | `0x109864B4`  | MSIL DLL metadata    |
| `SIGNATURE_TYPE_VDLL_CHECKSUM`        | `0x10986568`  | DLL checksum sigs    |
| `SIGNATURE_TYPE_VDLL_SYMINFO`         | `0x10986130`  | DLL symbol info      |

### 5.4 Thread / Tunnel Emulation Targets

| Signature Type                         | Address       | Target Arch          |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_THREAD_X86`           | `0x109860F4`  | x86 thread sigs      |
| `SIGNATURE_TYPE_THREAD_X64`           | `0x1098703C`  | x64 thread sigs      |
| `SIGNATURE_TYPE_THREAD_ARM`           | `0x10986B00`  | ARM thread sigs      |
| `SIGNATURE_TYPE_THREAD_ARM64`         | `0x10986B58`  | ARM64 thread sigs    |
| `SIGNATURE_TYPE_TUNNEL_X86`           | `0x109860A4`  | x86 tunnel sigs      |
| `SIGNATURE_TYPE_TUNNEL_X64`           | `0x10986344`  | x64 tunnel sigs      |
| `SIGNATURE_TYPE_TUNNEL_ARM`           | `0x10986460`  | ARM tunnel sigs      |
| `SIGNATURE_TYPE_TUNNEL_ARM64`         | `0x1098713C`  | ARM64 tunnel sigs    |

### 5.5 Infrastructure and Metadata

| Signature Type                         | Address       | Purpose              |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_THREAT_BEGIN`          | `0x10986DC0`  | Threat record start  |
| `SIGNATURE_TYPE_THREAT_UPDATE_STATUS`  | `0x10986F5C`  | Threat update status |
| `SIGNATURE_TYPE_LATENT_THREAT`         | `0x10986E48`  | Latent threat marker |
| `SIGNATURE_TYPE_VOLATILE_THREAT_INFO`  | `0x10986A48`  | Volatile threat info |
| `SIGNATURE_TYPE_PROPERTY_BAG`          | `0x10986DA4`  | Property bag data    |
| `SIGNATURE_TYPE_SIGFLAGS`              | `0x10986BB4`  | Signature flags      |
| `SIGNATURE_TYPE_DEFAULTS`              | `0x10986F80`  | Default settings     |
| `SIGNATURE_TYPE_VDM_METADATA`          | `0x109862D8`  | VDM metadata         |
| `SIGNATURE_TYPE_DATABASE_CATALOG`      | `0x109861B8`  | DB catalog           |
| `SIGNATURE_TYPE_DATABASE_CERT`         | `0x10986230`  | DB certificate       |
| `SIGNATURE_TYPE_DATABASE_CERT2`        | `0x1098667C`  | DB certificate v2    |
| `SIGNATURE_TYPE_DATABASE_CERT3`        | `0x109865A0`  | DB certificate v3    |
| `SIGNATURE_TYPE_UNKNOWN`               | `0x10986C2C`  | Unknown/fallback     |
| `SIGNATURE_TYPE_RESERVED`              | `0x10986184`  | Reserved             |

### 5.6 Cloud / Network Signatures

| Signature Type                         | Address       | Purpose              |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_FASTPATH_SDN`          | `0x109869AC`  | Fastpath SDN sigs    |
| `SIGNATURE_TYPE_FASTPATH_SDN_EX`       | `0x10986110`  | Extended SDN sigs    |
| `SIGNATURE_TYPE_FASTPATH_TDN`          | `0x1098647C`  | Fastpath TDN sigs    |
| `SIGNATURE_TYPE_BLOOM_FILTER`          | `0x10987108`  | Bloom filter sigs    |
| `SIGNATURE_TYPE_NISBLOB`               | `0x10987024`  | NIS blob data        |

### 5.7 Policy and Remediation

| Signature Type                         | Address       | Purpose              |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_REMOVAL_POLICY`        | `0x109871F0`  | Removal policy       |
| `SIGNATURE_TYPE_REMOVAL_POLICY64`      | `0x10986CBC`  | 64-bit removal       |
| `SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME`| `0x109862B0`  | Named removal policy |
| `SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME`| `0x10987078` | Named 64-bit removal|
| `SIGNATURE_TYPE_CLEANSCRIPT`           | `0x10986168`  | Cleanup script       |
| `SIGNATURE_TYPE_CLEANSTORE_RULE`       | `0x109863CC`  | Cleanup store rule   |
| `SIGNATURE_TYPE_MAC_CURE`              | `0x10986664`  | macOS remediation    |

### 5.8 File System and Path Matching

| Signature Type                         | Address       | Purpose              |
|----------------------------------------|---------------|----------------------|
| `SIGNATURE_TYPE_FILENAME`              | `0x10986D08`  | File name matching   |
| `SIGNATURE_TYPE_FILEPATH`              | `0x109870D4`  | File path matching   |
| `SIGNATURE_TYPE_FOLDERNAME`            | `0x10986E84`  | Folder name matching |
| `SIGNATURE_TYPE_ASEP_FILEPATH`         | `0x10986A90`  | ASEP file path       |
| `SIGNATURE_TYPE_ASEP_FOLDERNAME`       | `0x109866D4`  | ASEP folder name     |
| `SIGNATURE_TYPE_REGKEY`                | `0x10987124`  | Registry key check   |
| `SIGNATURE_TYPE_HIDDEN_FILE`           | `0x10986498`  | Hidden file detect   |

---

## 6. Detection Events

The binary contains ETW trace strings for detection events:

| Address        | String                                | Purpose                           |
|----------------|---------------------------------------|-----------------------------------|
| `0x10A34170`   | `Engine.Det.PuaDetection`             | PUA (Potentially Unwanted App)    |
| `0x10A4B490`   | `Engine.Det.MoacNotSigned`            | MOAC unsigned detection           |
| `0x10A4D7FC`   | `Engine.Det.AutoFolderLatent`         | Auto-folder latent detection      |
| `0x10A53670`   | `Engine.Det.LowfiNonInt`              | Low-fi non-interactive            |
| `0x10A536E0`   | `Engine.Det.LowfiTrusted`             | Low-fi trusted detection          |
| `0x10A54498`   | `Engine.Det.InsideTxf`                | Inside TxF detection              |
| `0x10A77F28`   | `Engine.Det.ExhaustiveScriptScan`     | Exhaustive script scan            |
| `0x10A78300`   | `Engine.Det.PythonInfected`           | Python malware detection          |
| `0x10A784CC`   | `Engine.Det.JsEmuEval`                | JS emulation eval                 |
| `0x10A78668`   | `Engine.Det.TokenizerError`           | Tokenizer error event             |
| `0x10A78690`   | `Engine.Det.ScriptDetError`           | Script detection error            |
| `0x10A78738`   | `Engine.Det.ChainedObjectCount`       | Chained object counting           |
| `0x10A49468`   | `Engine.Det.BMLuaSigattr`             | BM Lua sig attribute              |
| `0x10B6B598`   | `Engine.Det.LuaFolderLatent`          | Lua folder latent detection       |

---

## 7. Cascade Flow Diagram

```
                    ┌──────────────────────────────┐
                    │  File data from Stage 02     │
                    │  (not friendly)              │
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │         STATIC ENGINE CASCADE           │
              │                                         │
              │  ┌──────────────────────────────────┐   │
              │  │ 1. STATIC @ 0x109860DC           │   │
              │  │    Legacy byte-pattern matching   │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 2. PEHSTR @ 0x109869C8           │   │
              │  │    PE header string matching      │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 3. PEHSTR_EXT @ 0x10986618       │   │
              │  │    Extended PE header strings     │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 4. PEHSTR_EXT2 @ 0x109863EC      │   │
              │  │    Second-gen PE header strings   │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 5. KCRCE @ 0x109868B4            │   │
              │  │    Kernel CRC entry detection     │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 6. KCRCEX @ 0x109871A4           │   │
              │  │    Extended kernel CRC            │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 7. PESTATIC @ 0x1098718C         │   │
              │  │    PE static analysis rules       │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 8. PESTATICEX @ 0x10987210       │   │
              │  │    Extended PE static analysis    │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 9. BM_STATIC @ 0x10986AE4        │   │
              │  │    Behavioral monitoring static   │   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 10. BRUTE @ 0x10986D8C           │   │
              │  │    Feature-based polymorphic match│   │
              │  └──────────────┬───────────────────┘   │
              │                 ▼                        │
              │  ┌──────────────────────────────────┐   │
              │  │ 11. NSCRIPT_BRUTE @ 0x10986AB0   │   │
              │  │    NScript brute-force detection  │   │
              │  └──────────────┬───────────────────┘   │
              │                                         │
              └────────────────┬────────────────────────┘
                               │
                               ▼
                    ┌──────────────────────────────┐
                    │  Accumulated Attributes:      │
                    │  - HSTR: patterns             │
                    │  - SIGATTR: flags             │
                    │  - KCRCE: checksums           │
                    │  - BRUTE: features            │
                    │                               │
                    │  Detections added to          │
                    │  threat_list if high-conf     │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Stage 04: Attribute          │
                    │  Collection & PE Analysis     │
                    └──────────────────────────────┘
```

---

## 8. Attribute Deposition

Each engine in the cascade deposits attributes into the shared scan context.
These attributes follow naming conventions:

| Prefix       | Source Engine      | Example                          |
|--------------|--------------------|----------------------------------|
| `HSTR:`      | PEHSTR / PEHSTR_EXT| `HSTR:Win32/Rbot.gen!dll`        |
| `SIGATTR:`   | Various            | `SIGATTR:PE:UPXPacked`           |
| `KCRCE:`     | KCRCE / KCRCEX     | `KCRCE:0x1a2b3c4d`              |
| `BRUTE:`     | BRUTE              | `BRUTE:PDF:Feature:JsPresent`    |
| `STATIC:`    | STATIC             | `STATIC:Win32/Virut.A`          |
| `BM:`        | BM_STATIC          | `BM:SuspiciousImports`          |

These attributes are consumed by:
- **AAGGREGATOR** (Stage 11): Boolean expressions over attribute sets.
- **Lua scripts** (Stage 10): Programmatic attribute evaluation.
- **Cloud/MAPS** (Stage 12): Attribute bundles sent to cloud for ML classification.

---

## 9. BRUTE Feature Strings

The BRUTE engine extracts features and records them as attributes with specific
prefixes. From the binary:

```
Address       String
──────────────────────────────────────
0x10A54CC8    BRUTE:PDF:Feature:
0x10A54D08    BRUTE:VBS:Feature:
0x10A54D1C    BRUTE:JS:Feature:
```

These feature strings are followed by specific feature names (e.g., `JsPresent`,
`ObfuscatedStrings`, `HighEntropy`) to form complete attribute names that the
AAGGREGATOR can evaluate.

---

## 10. Data Structures

### 10.1 StaticEngineResult (Reconstructed)

```c
// Reconstructed from decompilation
struct StaticEngineResult {
    uint32_t sig_type;          // SIGNATURE_TYPE enum value
    uint64_t sig_sequence;      // Sequence number from VDM
    uint32_t match_offset;      // Offset in file where match occurred
    uint32_t match_length;      // Length of matched region
    uint32_t confidence;        // 0-100 confidence score
    char     attribute[256];    // Deposited attribute string
    uint32_t threat_id;         // Non-zero if this is a detection
};
```

### 10.2 CascadeContext (Reconstructed)

```c
// Reconstructed from context accesses across all 11 engines
struct CascadeContext {
    uint8_t  *file_data;        // Raw file bytes
    uint32_t  file_size;        // File size in bytes
    uint32_t  content_type;     // Detected content type (PE, script, etc.)

    // PE-specific (populated if content_type == PE)
    uint32_t  pe_entry_point;   // AddressOfEntryPoint
    uint32_t  pe_image_base;    // ImageBase
    uint16_t  pe_subsystem;     // Subsystem field
    uint16_t  pe_num_sections;  // NumberOfSections
    uint32_t  pe_timestamp;     // TimeDateStamp
    uint8_t   pe_is_64bit;      // Is PE32+?
    uint8_t   pe_is_dotnet;     // Has CLR header?

    // Hash cache
    uint8_t   md5[16];
    uint8_t   sha256[32];
    uint32_t  kcrc1;
    uint32_t  kcrc2;
    uint32_t  kcrc3;

    // Results
    uint32_t  num_attributes;
    char    **attributes;       // Dynamic array of attribute strings
    uint32_t  num_detections;
    void    **detections;       // Array of StaticEngineResult*
};
```

---

## 11. Performance Considerations

The cascade order is optimized for early termination:

1. **STATIC** runs first because it is the fastest (pre-compiled automaton).
2. **PEHSTR** variants run next because they only scan PE headers (small region).
3. **KCRCE** is fast (CRC computation over small windows).
4. **PESTATIC** does deeper analysis but only for PE files.
5. **BRUTE** runs last because feature extraction is the most expensive.

High-confidence detections from early engines can potentially short-circuit later
engines, though this depends on engine configuration (controlled by `SIGNATURE_TYPE_SIGFLAGS`
@ `0x10986BB4` entries in the VDM).

---

## 12. Cross-References

- **Previous stage**: [02 -- FRIENDLY_FILE Check](02_friendly_file.md)
- **Next stage**: [04 -- AAGGREGATOR Attribute Collection](04_aaggregator_collection.md)
- **Pipeline overview**: [00 -- Master Overview](00_overview.md)
- **AAGGREGATOR**: Stage 11 (evaluates boolean expressions over attributes from this stage)

---

*All addresses are from the actual binary image base 0x10001000.*
