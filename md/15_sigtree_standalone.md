# SigTree Standalone Extraction & Evaluation (Work Log)

This document tracks ongoing work to extract Windows Defender's SIG_TREE ML model
from VDMs and run it standalone, plus the reverse engineering needed to map
SigTree node fields to real attribute signals and to capture ground-truth
attribute vectors from mpengine.dll.

## Goals

1. Extract SIG_TREE / SIG_TREE_EXT / SIG_TREE_BM models from VDM and serialize.
2. Map numeric SigTree attribute IDs to real attribute names or deterministic IDs.
3. Capture mpengine attribute vectors for PEs (ground truth) to validate mapping.
4. Implement standalone SigTree evaluator (using mapped attributes).

## Current Status (as of 2026-02-19)

### Model Extraction (Complete)
- Extracted from VDM TLV entries (types 0x40, 0x41, 0xB3)
- Output size: 137 MB JSON
- Total trees: 33,428
  - SIG_TREE (0x40): 14,926
  - SIG_TREE_EXT (0x41): 3,771
  - SIG_TREE_BM (0xB3): 14,731
- Total nodes: 408,708
- Trees with inline strings: 13,793
- Parser reads 5-byte header + 16-byte nodes per entry

### 🔍 Active RE Focus
We need to map SigTree node fields to real attribute signals:

- The 32-byte in-memory node layout is partially known.
- `node_to_lua_table` (0x100f208d) pulls:
  - `word [node + 0x00]` (flags?)
  - `word [node + 0x02]` as the **attribute ID** (u16)
- The node's children are at `node + 0x10` and `node + 0x18`.

This suggests the on-disk 16-byte node layout is:
- `u16 @ +0x00` flags / match info
- `u16 @ +0x02` **attribute_id** (not the byte at +0x04)
- remaining bytes likely include mode/hash/extra data

We need to confirm the full mapping and how attribute IDs are computed.

### 🧪 Attribute-ID Mapping Strategy (in-progress)
We suspect attribute IDs are computed from attribute strings or are fixed indices
in an internal table. Options:

1. **Hash-based** (CRC16 / CRC32-trunc):
   - Try matching node `field_02` values against hashes of known attribute names
   - Candidate sources: `Nscript:js_*`, `BRUTE:*`, `SIGATTR:*`, PE attrs
2. **Table-based** (static array):
   - Find in mpengine.dll the attribute-name table and index mapping
   - Look for xrefs to `.?AVSigattr_AttributeNotifier@@`
   - Search for pointer arrays near the `Nscript:js_*` strings

### 🧪 Ground-Truth Attribute Vector (planned)
To validate mapping we want to capture attribute vectors from mpengine:
- Locate where sigattr events are pushed to `[edi + 0x82ee4]`
- Instrument that code path to dump the word IDs per scan
- Alternatively: hook `sigattrevents=` builder or post-emu log accessors

## Next Steps

1. **Reverse attribute ID mapping**
   - Use r2/ghidra to find:
     - Sigattr notifier / attribute table
     - hash function (if any) from attr name -> id

2. **Attribute vector capture**
   - Identify sigattr log write point
   - Dump array of event IDs for a controlled scan input

3. **Standalone evaluator**
   - Implement tree walker that accepts:
     - attribute ID set
     - SigTree JSON
   - Output the matched detection

## Open Questions

- Is `node + 0x02` a 16-bit attribute ID (likely), or a packed struct?
- What is the exact on-disk → in-memory node expansion?
- What function assigns sigattr IDs (hash vs. table index)?
- Which features are actually used by SigTree vs. broader SIGATTR?


## 2026-02-19 Update: RTTI + Ghidra Headless Pass

### RTTI / Vtable Hunt (r2 + manual)
- Found RTTI name string for `Sigattr_AttributeNotifier`:
  - `0x10c8d4a0` in `.data` (string: `.?AVSigattr_AttributeNotifier@@`)
- TypeDescriptor = name - 8 = `0x10c8d498`
- Found two references to `0x10c8d498` in `.rdata`:
  - `0x10bbcf7c`
  - `0x10bbcfa8`
- At `0x10bbcf7c` the structure looks like:
  - `[0x10bbcf7c] = 0x10c8d498` (TypeDescriptor)
  - `[0x10bbcf80] = 0x10bbce9c`
  - `[0x10bbcf84] = 0x10bbcfa8`
  - plus terminators
  This is likely MSVC RTTI (CompleteObjectLocator + ClassHierarchyDescriptor).

### Ghidra Headless (in progress)
- Running headless analysis with custom script to locate:
  - RTTI COL
  - vtable pointer(s)
  - first ~8 virtual function pointers
- Command:
  - `/opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp/ghidra_sigattr_proj sigattr_analysis -import engine/mpengine.dll -postScript /tmp/ghidra_sigattr_rtti.py`
- Status: analysis ongoing; awaiting script output in `/tmp/ghidra_sigattr_log.txt`


## 2026-02-19 Update: SigAttr Event Insertion + Attribute ID Shape

### SigAttr Event Insertion (mpengine.dll)
We found the **write site** for sigattrevents (the array used by SIG_TREE).
This is key for mapping IDs.

- Function: `fcn.10052100` (identified by search for constant `0x82ee4`)
- Behavior:
  - Reads current event count at `[esi + 0x836e4]`
  - Writes **word** at `[esi + (count * 2) + 0x82ee4]`
  - Increments count
  - The **word value** comes from `[edi + 0x12]`

Disassembly excerpt:
```
0x10052118  mov ecx, dword [esi + 0x836e4]      ; event_count
0x1005211e  cmp ecx, 0x400                      ; max 1024 events
0x10052126  mov ax, word [edi + 0x12]           ; attribute_id
0x1005212a  mov word [esi + ecx*2 + 0x82ee4], ax
0x10052132  inc dword [esi + 0x836e4]
```

**Interpretation:** the SigTree attribute ID is stored at **offset +0x12**
inside a 0x20-byte struct (likely `SigAttrEntry`). This confirms the attribute
ID is **precomputed** before insertion into the log (not hashed at insertion).

### Attribute ID Shape in SIG_TREE Dump
Using `/tmp/sigtree.json`:
- `field_02` has **16,271 unique values**
- `attr_index` has **256 unique values**
- Only ~29% of nodes have `(field_02 & 0xff) == attr_index`

This strongly suggests:
- `field_02` is the **real 16-bit attribute ID**
- `attr_index` is a separate 8-bit field (role still unknown)

### Hashing Hypothesis Check
I tested whether `field_02` matches common hashes of known attribute strings
from `mpengine.dll` (`Nscript:*`, `BRUTE:*`, `SIGATTR:*`, `HSTR:*`, `FOP:*`, `pea_*`).

- CRC16-IBM: 85 matches
- CRC16-CCITT: 92 matches
- CRC32-low16: 75 matches

Expected random intersection for 329 strings vs 16k IDs is ~82, so this
**looks like noise**, not a real mapping.

### Next
We need to identify where `[edi + 0x12]` is populated (the ID generator).
Possible next steps:
- Find callers of `fcn.10052100` (likely vtable/dispatch)
- Trace upstream structure creation and ID assignment
- Locate the attribute ID table or hash function in mpengine.dll


## 2026-02-19 Update: AAGGREGATOR Attribute Name Extraction (Planned)

### Goal
Extract AAGGREGATOR attribute names from VDM to cross-correlate with SIG_TREE
attribute IDs. A VDM TLV parser can decode AAGGREGATOR rule expressions and
extract the attribute name tokens used in boolean expressions.

---

## 2026-02-19 Update: r2 Search for `[+0x12]` Attribute ID Writers

### Pattern scan
Searched for `mov word [reg+0x12], ax` (opcode `66 89 ?? 12`) in `mpengine.dll`:

Hits (opcode `66 89 47 12`):
- `0x1023fc31`
- `0x1024077a`
- `0x10851a7c`
- `0x108bb117`

### Quick triage
- `0x1023fc31` and `0x1024077a` both write **zero** to `[edi+0x12]` (immediately after `xor eax, eax`). These look like **struct init** paths.
- `0x10851a7c` is inside a larger loop but still appears to write a value derived from an already‑initialized `[edi+0x12]` (likely an internal counter/limit update), not a string→ID mapper.
- `0x108bb117` appears in a bulk struct copy/constructor path (copying many fields from `esi` into `edi`), likely **propagating** an ID rather than generating it.

### Conclusion
No direct string→ID generator found yet in this opcode sweep. Need to locate:
- the **call site** where attribute strings are turned into an ID
- or a lookup table / hash function that produces the 16‑bit ID stored at `+0x12`


## 2026-02-19 Update: Ghidra Headless Trace for mpattribute Bindings

### Objective
Locate the **Lua binding functions** for `set_mpattribute` and friends to trace
how attribute strings are mapped to the 16‑bit ID stored at `+0x12`.

### Script
Created `tools/ghidra/trace_mpattribute.py`:
- Finds string data for:
  - `get_mpattribute`, `set_mpattribute`, `set_mpattributeex`, `clear_mpattribute`, etc.
- Prints xrefs to those strings and the containing functions
- Decompiles a small subset for quick inspection

### Headless Run
Command (with `JAVA_HOME` and `XDG_CONFIG_HOME` overrides):
```
XDG_CONFIG_HOME=/tmp/ghidra_user JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
  /opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp/ghidra_attr_proj attr_trace \
  -import engine/mpengine.dll \
  -postScript tools/ghidra/trace_mpattribute.py
```

Status:
- Initial failures: missing project dir + JDK prompt in headless mode
- Resolved by creating `/tmp/ghidra_attr_proj` and setting env vars
- **Currently running analysis** (mpengine.dll is large; expect a while)
- Log: `/tmp/ghidra_attr_trace.log`


## 2026-02-19 Update: r2 Found Lua mpattribute Binding Table

Using r2 string + xref search for `set_mpattribute` strings, located a table of
`(string_ptr, function_ptr)` pairs in `.rdata`:

At `0x1097c7a0` (also mirrored at `0x109bd960`):
- `get_mpattribute`      -> `0x1072ed00`
- `get_mpattributevalue` -> `0x1072ee20`
- `get_mpattributesubstring` -> `0x1072ed90`
- `enum_mpattributesubstring` -> `0x1072ebd0`
- `set_mpattribute`      -> `0x1072fb00`
- `set_mpattributeex`    -> `0x1072fea0`
- `clear_mpattribute`    -> `0x1072eb50`
- `aggregate_mpattribute`-> `0x1072e620`
- extra entry: `0x1097ece8 -> 0x1072f180` (unknown name)

This confirms the Lua binding functions and gives concrete addresses to trace
for the attribute‑ID mapping.


## 2026-02-19 Update: Ghidra Headless Completed (Script Failed)

Ghidra headless analysis finished (~1081s total). However, the post-script
`trace_mpattribute.py` failed to execute because **PyGhidra is not available**
in this headless setup:

```
ERROR ... Ghidra was not started with PyGhidra. Python is not available
```

**Impact:** No script output captured. Need to rerun using a **Java GhidraScript**
(or confirm Jython support), then re-run headless with that script.


## 2026-02-19 Update: Headless Re-run With Java Script + -scriptPath

Per request, re-ran `analyzeHeadless` with `-scriptPath tools/ghidra` and a
Java GhidraScript (`tools/ghidra/TraceMpattribute.java`).

Attempts:
1) `-import engine/mpengine.dll` failed due to existing program in the project:
   `Found conflicting program file in project: /mpengine.dll`
2) Re-ran with `-process mpengine.dll` (no import). This run is **currently
   analyzing** and will execute the script after analysis completes.

Log: `/tmp/ghidra_attr_trace.log`

