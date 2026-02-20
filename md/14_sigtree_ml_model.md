# SigTree — On-Device ML Classification (Decision Trees)

> Reverse engineering documentation for the **SIG_TREE** on-device machine learning system
> inside `mpengine.dll` v1.1.24120.x (14.3 MB, PE32 x86).
> All addresses, strings, and structures from RE of mpengine.dll binary.

---

## Overview

SIG_TREE is Windows Defender's **on-device machine learning classification system**. It implements
a **decision tree ensemble** that evaluates boolean predicates over accumulated signature attributes
(sigattr) to produce ML-based detections with `!MTB` (Machine Learning / Tree-Based) and `!ml`
(Machine Learning) suffixes.

Unlike cloud-based ML (MAPS/SpyNet), SIG_TREE runs entirely locally using decision trees shipped
in the VDM (Virus Definition Module) signature databases. This is a critical detection layer —
**33,428 tree entries** exist across 3 signature types:

| Signature Type | Byte Code | VDM Count | Address | Purpose |
|----------------|-----------|-----------|---------|---------|
| `SIG_TREE` | `0x40` | 14,926 | `0x10986C88` | Standard decision trees |
| `SIG_TREE_EXT` | `0x41` | 3,771 | `0x10987008` | Extended decision trees |
| `SIG_TREE_BM` | `0xB3` | 14,731 | `0x109871D4` | Behavioral monitoring trees |

### Detection Output

SIG_TREE evaluations produce detections with these suffixes (see Stage 13):

| Suffix | Full Name | Example |
|--------|-----------|---------|
| `!MTB` | Machine Learning / Tree-Based model | `Trojan:Win32/Emotet.RPX!MTB` |
| `!ml` | Machine Learning detection | `Trojan:Win32/AgentTesla!ml` |

---

## Architecture

### Data Flow

```
                    VDM Signature Database
                           |
                           v
          +----------------------------------+
          | Parse SIG_TREE TLV entries       |
          | (0x40, 0x41, 0xB3)              |
          | 5-byte header + 16-byte nodes   |
          | Expanded to 32 bytes in memory  |
          +----------------------------------+
                           |
                           v
    +--------------------------------------------+
    | Pipeline stages accumulate sigattr events: |
    |   Stage 3:  PEHSTR, STATIC matches         |
    |   Stage 5:  PE emulation attributes        |
    |   Stage 8:  NScript JS features            |
    |   Stage 9:  BRUTE features                 |
    |   Stage 10: Lua mp.setattribute()          |
    +--------------------------------------------+
                           |
                           v
          +----------------------------------+
          | sigattr_head / sigattr_tail      |
          | Circular log of boolean attrs    |
          | 32 bytes per log entry           |
          +----------------------------------+
                           |
                           v
          +----------------------------------+
          | SIG_TREE Evaluation              |
          | - Load tree from node array      |
          | - JIT compile to native x86      |
          | - Evaluate predicates over       |
          |   sigattr log entries            |
          +----------------------------------+
                           |
                           v
          +----------------------------------+
          | Result: !MTB / !ml detection     |
          | + metadata (peattributes,        |
          |   imphash, clusterhash, etc.)    |
          +----------------------------------+
```

### Key Insight

SIG_TREE is NOT a separate pipeline stage. It runs as a **supporting engine** within the
Static Engine Cascade (Stage 03) and during BM (Behavioral Monitoring) evaluation. The trees
evaluate over the accumulated sigattr log — a running record of boolean feature attributes
set by all prior pipeline stages.

---

## VDM Binary Format (On-Disk)

### TLV Entry Header (5 bytes)

Each SIG_TREE TLV entry in the VDM starts with a 5-byte header:

```
Offset  Size  Field
------  ----  -----
0x00    2     node_count (uint16 LE)
0x02    1     version (0x01 = standard, 0x02 = extended)
0x03    1     tree_type (0x03 = SIG_TREE/SIG_TREE_EXT, 0x02 = SIG_TREE_BM)
0x04    1     flags
```

**Confirmed from VDM dumps:**
- `05 00 01 03 00` → 5 nodes, version 1, type 3, flags 0 (SIG_TREE for Agent)
- `09 00 01 03 00` → 9 nodes, version 1, type 3, flags 0 (SIG_TREE for Agent)
- `02 00 01 02 00` → 2 nodes, version 1, type 2, flags 0 (SIG_TREE_BM for ModifiedAutoRunInf)

### Fixed-Length Nodes (16 bytes each)

For standard SIG_TREE (0x40) and most SIG_TREE_BM (0xB3) entries, each node
after the header is **16 bytes**:

```
total_size = 5 + (node_count * 16)   // for fixed-length entries

Example: SIG_TREE #1 (Agent) = 5 + (5 * 16) = 85 bytes ✓
Example: SIG_TREE_BM #1 (ModifiedAutoRunInf) = 5 + (2 * 16) = 37 bytes ✓
Example: SIG_TREE_BM #3 (ModifiedBootRecord) = 5 + (1 * 16) = 21 bytes ✓
```

16-byte VDM node structure (partial RE):
```
Offset  Size  Field
------  ----  -----
0x00    2     flags / child_info (u16 LE)
0x02    2     secondary data (u16 LE)
0x04    1     attribute_index (u8 — sigattr feature reference)
0x05    1     node_type_marker (0x30 for SIG_TREE, 0x40 for SIG_TREE_BM)
0x06    1     mode/subtype
0x07    4     hash/CRC value (u32 LE)
0x0B    5     secondary data / padding
```

### Variable-Length Nodes (SIG_TREE_EXT and some BM)

SIG_TREE_EXT (0x41) entries and some SIG_TREE_BM entries contain **embedded
inline strings** (file paths, registry paths, URLs) making nodes variable-length.

Example strings found in SIG_TREE_EXT entries:
- `c:\windows\system32\*.dll` (with `0x90` wildcard escape byte)
- `c:\windows\temp\*.exe`
- `http://*.hotmail.ru/flashcard/*.iso`

Example strings found in SIG_TREE_BM entries (UTF-16LE):
- `%system%\spool\prtprocs\w32x86\*.dll`
- `hklm\system\controlset*\control\session manager\\pendingfilerenameoperations`
- `taskkill /f /pid `

The `0x90` byte serves as a **wildcard escape** in path patterns:
- `0x90 0x02 0x08` → wildcard of 8-char minimum match
- `0x90 0x02 0x10` → wildcard of 16-char minimum match
- `0x90 0x00` → end-of-pattern marker

### In-Memory Expansion (32 bytes per node)

When loaded into memory, each VDM node (16 bytes on-disk) is expanded to **32 bytes**
(confirmed by `sar eax, 5` at `0x1012b05d`). The tree data loader at `0x1012b02a`
computes:
```
node_count = (end_ptr - start_ptr) >> 5   // divide by 32
```

This expansion likely adds resolved pointers, child node addresses, and pre-computed
evaluation state that doesn't exist in the packed VDM format.

---

## Tree Node Semantics

### Node Types

The node type string table at `0x10987530`-`0x10987558` defines six node types:

| Address | String | Role |
|---------|--------|------|
| `0x10987530` | `"attribute"` | Leaf node — checks a specific sigattr feature |
| `0x1098753c` | `"matched"` | Terminal node — indicates a match result |
| `0x10987548` | `"np2"` | Negated Predicate 2 — NOT of predicate child |
| `0x1098754c` | `"p1"` | Predicate 1 — first boolean child branch |
| `0x10987550` | `"p2"` | Predicate 2 — second boolean child branch |
| `0x10987558` | `"np1"` | Negated Predicate 1 — NOT of predicate child |

### Tree Structure

The tree is a **binary decision tree** with boolean logic:

```
                    [attribute: js_hasBigString?]
                   /                              \
            [p1: yes]                         [np1: no]
               |                                  |
    [attribute: highEntropy?]           [matched: clean]
       /                  \
  [p2: yes]           [np2: no]
     |                    |
 [matched: Trojan]   [matched: clean]
```

Each internal node tests a boolean attribute (from the sigattr log). The two children
are addressed as p1/p2 (predicate, matching the `true` branch) and np1/np2 (negated
predicate, matching the `false` branch).

### Node Field Layout (Partial RE)

Based on the node evaluator at `0x100f208d`:

```
Offset  Size   Field
------  ----   -----
0x00    2      match_status (bit 0 = matched flag)
0x02    2      attribute_id (sigattr feature index)
0x04    4      [data field A — used in XOR hash check]
0x08    4      [data field B — used in XOR hash check]
0x10    4      p1_child (pointer/offset to predicate-1 child)
0x14    4      [p1 metadata — length/capacity when type=1]
0x18    1      child_type (0=string, 1=inline, 2=vector, 3=subtree)
0x19-0x1F      [remaining fields TBD]
```

**child_type byte at offset 0x18** (from Ghidra decompilation):
- `0` — Null/empty child (leaf/terminal) — calls `FUN_1004b843` for string resolution
- `1` — Inline string data (length at +0x14, data pointer computed from node)
- `2` — Vector/buffer reference (size = `node[1] - node[0]`, start = `node[0]`)
- `3` — Sub-tree reference (recursive tree node, copies value directly)

**Lua value stack type tags** (16-byte slots at `param_1+8`):
- `1` — boolean (used for "matched" field)
- `2` — lightuserdata (used for node pointer pushes)
- `3` — number (used for attribute ID and node count)

---

## Evaluation Engine

### Entry Point: `fcn.1073fe00` (SigTree Dispatch)

**Address**: `0x1073fe00` (130 bytes)
**Called via**: Indirect dispatch table (vtable — no direct xrefs found)

```
fcn.1073fe00(lua_state):
    index = lua_tointeger(lua_state, 1)        // sigattr head index
    context = resolve_context(lua_state)        // fcn.1072e33f
    tree_data = context + 0x2240                // tree data pointer offset
    {node_count, base_ptr} = load_tree(tree_data, dl=1)  // fcn.1012b02a

    if base_ptr == NULL or node_count == 0:
        error("sigtree log is not valid")       // 0x10b52130
        return

    if index == 0 or index > node_count:
        error("Invalid sigattr_head index")     // 0x10b5214c
        return

    entry_ptr = base_ptr - 0x20 + (index << 5)  // 1-based index, 32-byte stride
    lfence()                                     // Spectre mitigation
    push_node_as_lua_table(lua_state, entry_ptr) // fcn.100f208d
    return 1
```

### Tree Data Loader: `fcn.1012b02a`

**Address**: `0x1012b02a`
**Purpose**: Loads tree node array from container object

Two paths based on a boolean flag (`dl` register):

| Flag | Source Offset | Description |
|------|---------------|-------------|
| `dl=1` | `[esi + 0x32c]` | Active tree — primary evaluation path |
| `dl=0` | `[esi + 0x330]` | Alternate tree — secondary/backup path |

**Active path** (`dl=1`):
```
container = [esi + 0x32c]
base_ptr  = *container         // start of node array
end_ptr   = *(container + 4)   // end of node array
node_count = (end_ptr - base_ptr) >> 5  // divide by 32
output = {node_count, base_ptr}
```

The container uses a "circular_buffer" (string ref at `0x1012b0b3`) for bounds checking.

### Node Evaluator: `fcn.100f208d` (SigTree Node → Lua Table)

**Address**: `0x100f208d` (192 bytes)
**Purpose**: Converts a 32-byte tree node into a Lua table structure

```
fcn.100f208d(lua_state, node_ptr):
    // Push a new Lua table
    lua_createtable(lua_state, 0, 8)

    // Set "matched" field (boolean)
    matched = node_ptr[0] & 1
    set_match_state(lua_state, matched)         // fcn.100f2255
    lua_setfield(lua_state, -2, "matched")      // fcn.1008c2fb

    // Set "attribute" field (integer — sigattr index)
    attr_id = *(uint16*)(node_ptr + 2)
    push_integer(lua_state, attr_id)
    lua_setfield(lua_state, -2, "attribute")

    // Set child "p1"/"np1" (predicate branches)
    push_child(lua_state, node_ptr + 0x10, dl=1)   // fcn.100f214d, p1 branch
    push_child(lua_state, node_ptr + 0x18, dl=0)   // fcn.100f214d, np1 branch

    // Set __index metamethod for lazy evaluation
    lua_pushcfunction(lua_state, 0x1073a970)
    lua_setfield(lua_state, -2, "__index")      // at 0x1097c770

    return
```

### XOR-Based Node Hash Evaluator: `fcn.100f2354`

**Address**: `0x100f2354` (94 bytes)
**Purpose**: CRC/parity check for tree node integrity or attribute matching

```
fcn.100f2354(this, node_struct):
    // node_struct: [0]=output, [4]=ptr_A, [8]=ptr_B
    xor_result = *ptr_B ^ *ptr_A
    *output = xor_result

    low_byte = xor_result & 0xFF
    high_nibble = low_byte >> 4
    low_nibble  = low_byte & 0x0F

    hash = TABLE_2[high_nibble] ^ TABLE_1[low_nibble]
    mask = ~(this->field_0c) & *(this->field_04)
    result = hash | mask

    // Check bit 31 of XOR result
    if xor_result & 0x80000000:
        result |= 0x80

    // If XOR == 0, set flag 0x40
    if xor_result == 0:
        result |= 0x40

    *node_struct = result
```

**Nibble Lookup Tables** (parity computation):

| Table | Address | Values (hex) |
|-------|---------|--------------|
| TABLE_1 | `0x10b69564` | `04 00 00 04 00 04 04 00 00 04 04 00 04 00 00 04` |
| TABLE_2 | `0x10b69590` | `00 04 04 00 04 00 00 04 04 00 00 04 00 04 04 00` |

These are **nibble parity tables**: each entry is either `0x00` (even parity) or `0x04`
(odd parity). XORing both lookups computes a CRC-like check on the low byte of the XOR
result.

### JIT Bytecode Emitter: `fcn.100f226f`

**Address**: `0x100f226f` (216 bytes)
**Purpose**: JIT-compiles tree evaluation into native x86 MOV instructions

The SIG_TREE engine does NOT interpret the decision tree at runtime. Instead, it
**JIT-compiles** the tree nodes into a buffer of native x86 instructions for maximum
evaluation speed.

**JIT Buffer Location**:
```
base   = [esi + 0x37d4]    // JIT buffer base pointer
offset = [esi + 0x37dc]    // current write position
write_ptr = base + offset
```

**Opcode Emission** (4-way switch on operand type):

| Case | Opcode | Operand Size | Total Bytes | x86 Instruction |
|------|--------|-------------|-------------|-----------------|
| 0 | `0xC6` | 1 byte | 3 | `MOV byte [addr], imm8` |
| 1 | `0xC766` | 2 bytes | 5 | `MOV word [addr], imm16` |
| 2 | `0xC7` | 4 bytes | 6 | `MOV dword [addr], imm32` |
| 3 | `0xC7` × 2 | 4+4 bytes | 13 | Two `MOV dword` instructions |

This is genuine JIT compilation: the engine writes x86 `MOV` immediate instructions directly
into an executable buffer. The emitted code materializes tree evaluation results as memory
stores, which are then executed natively.

---

## Signature Attribute (SigAttr) Log System

The sigattr log is the **feature vector** that SIG_TREE evaluates over. It accumulates boolean
attributes from every pipeline stage into a circular head/tail log structure.

### Log Structure

```
SigAttrLog {
    flags:      u32,              // +0x30: bit 2 = log available
    log_data:   *SigAttrLogData,  // +0x44: pointer to log arrays

    // At log_data:
    head_log:   Vec<SigAttrEntry>,  // +0x08: head log (recent events)
    tail_log:   Vec<SigAttrEntry>,  // +0x0C: tail log (older events)
}

SigAttrEntry {                    // 32 bytes per entry (shl edi, 5)
    // Exact field layout TBD
    // Contains boolean attribute state
}
```

**Validation**: Access is gated by `[edx+0x30] & 0x04` (bit 2 flag). If not set,
the log is unavailable (only present for BM sigattr signatures).

**Spectre Mitigation**: Index bounds are validated with `lfence` instructions at
`0x1073fe5f` and `0x1073ff4f` before pointer dereference.

### Lua API

The sigattr log is exposed to Lua scripts (Stage 10) via metamethods registered at
`0x10086bbe` (385-byte Lua registration function):

| Lua Name | Handler Address | Purpose |
|----------|-----------------|---------|
| `sigattr_head` | `0x1073dfe0` (index), `0x1073aca0` | Access head log entries |
| `sigattr_tail` | `0x1073acb0` | Access tail log entries |
| `this_sigattrlog` | `0x1008bc52` | Current signature's attr log |
| `get_sigattr_event_count` | dispatch at `0x1097cb48` | Count of sigattr events |
| `get_postemu_sigattr_log_head` | dispatch at `0x1097dab8` | Post-emulation head log |
| `get_postemu_sigattr_log_tail` | (paired with above) | Post-emulation tail log |

Both `__newindex` and `__index` metamethods are registered, allowing Lua scripts to
read and write sigattr log entries. The aliased field access pattern is:
```lua
this_sigattrlog["alias"].fieldname
```

### Sigattr Event Parser

The signature attribute events parser at `0x10564d00` (320 bytes) parses semicolon-delimited
key=value strings from SIG_TREE evaluation results. The dispatch chain at `0x10564d31` compares
against these attribute prefixes:

| Struct Offset | Attribute Key | Purpose |
|---------------|---------------|---------|
| `+0x00` | (signature match) | Base match result |
| `+0x04` | `peattributes=` | PE header attributes |
| `+0x08` | `sigattrevents=` | Sigattr event list |
| `+0x0c` | `imphash=` | Import hash |
| `+0x10` | `clusterhash=` | Cluster hash |
| `+0x14` | `researchdata=` | Research/telemetry data |
| `+0x18` | `LoopILHash=` | IL loop hash |
| `+0x1c` | `PDBProject=` | PDB project path |

### MpInternal_sigattrevents Builder

Function at `0x107f934f` builds the internal telemetry string:

```
MpInternal_sigattrevents=<hex1>,<hex2>,...
```

- Iterates sigattr events array at `[edi + 0x82ee4]` (word-sized entries)
- Event count bounded by `[edi + 0x836e4]`
- Each event converted to 10-character hex string (base 16)
- Comma-separated, followed by `MpInternal_imphash=` at `0x107f93df`

---

## Feature Sources

SIG_TREE evaluates over features collected from multiple pipeline stages:

### BRUTE Features (Stage 9)

| Feature Prefix | Address | File Type |
|----------------|---------|-----------|
| `BRUTE:PDF:Feature:*` | `0x10A54CC8` | PDF documents |
| `BRUTE:VBS:Feature:*` | `0x10A54D08` | VBScript files |
| `BRUTE:JS:Feature:*` | `0x10A54D1C` | JavaScript files |

### NScript JavaScript Features (Stage 8)

21 boolean feature attributes extracted during JavaScript deobfuscation:

| Attribute | Description |
|-----------|-------------|
| `Nscript:js_highAverageSpaceRunLength` | Unusually long whitespace runs |
| `Nscript:js_hasNoIfs` | No conditional statements |
| `Nscript:js_hasBigString` | Contains very large string literals |
| `Nscript:js_lowAverageWordLength` | Short average token length |
| `Nscript:js_highAverageWordLength` | Long average token length |
| `Nscript:js_hasManySmallFuncs` | Many small function definitions |
| `Nscript:js_hasLongVarNames` | Unusually long variable names |
| `Nscript:js_hasNoLoops` | No loop constructs |
| `Nscript:js_hasNoFuncs` | No function definitions |
| `Nscript:js_lowUniqueWordRatio` | Low lexical diversity |
| `Nscript:js_highUniqueWordRatio` | High lexical diversity |
| `Nscript:js_hasEval` | Uses eval() |
| `Nscript:js_hasExcessiveComments` | Abnormally high comment ratio |
| `Nscript:js_hasBase64` | Contains base64-encoded strings |
| `Nscript:js_hasHexStrings` | Contains hex-encoded strings |
| `Nscript:js_hasDOMAccess` | Accesses DOM APIs |
| `Nscript:js_hasNetworkCalls` | Makes network requests |
| `Nscript:js_hasTimerAbuse` | Excessive setTimeout/setInterval |
| `Nscript:js_hasStringManipulation` | Heavy string manipulation |
| `Nscript:js_hasCryptoOps` | Uses crypto APIs |
| `Nscript:js_hasObfuscatedNames` | Variable names appear obfuscated |

### PE Attributes (Stage 3/5)

PE header metadata collected during static analysis and emulation, reported via
`peattributes=` in the result structure.

### Lua Script Attributes (Stage 10)

Lua scripts can set arbitrary attributes via `mp.setattribute()` which feed into
the sigattr log for SIG_TREE evaluation.

---

## Key Addresses Summary

### Functions

| Address | Size | Function | Role |
|---------|------|----------|------|
| `0x1073fe00` | 130 | `sigtree_dispatch` | Main SigTree dispatch (via vtable) |
| `0x1073fe90` | 83 | `sigtree_eval_entry` | Eval entry point (alt path) |
| `0x1012b02a` | ~100 | `tree_data_loader` | Loads node array from container |
| `0x100f208d` | 192 | `node_to_lua_table` | Converts 32-byte node to Lua table |
| `0x100f214d` | 264 | `child_node_handler` | Processes child nodes recursively |
| `0x100f2255` | 26 | `match_setter` | Sets matched flag in output |
| `0x100f226f` | 216 | `jit_emitter` | JIT compiles tree to x86 code |
| `0x100f2354` | 94 | `xor_node_eval` | XOR/parity node evaluator |
| `0x1073a880` | ~234 | `sigattr_log_accessor` | Accesses head/tail log entries |
| `0x10564d00` | 320 | `sigattr_events_parser` | Parses key=value result strings |
| `0x107f934f` | ~150 | `sigattrevents_builder` | Builds MpInternal telemetry string |
| `0x10086bbe` | 385 | `sigattr_lua_register` | Registers Lua sigattr bindings |

### Data / Strings

| Address | Content |
|---------|---------|
| `0x109c80b0` | `"sigtree"` (engine name) |
| `0x10b52130` | `"sigtree log is not valid"` |
| `0x10b5214c` | `"Invalid sigattr_head index"` |
| `0x1097d710` | `"sigattr_head"` |
| `0x1097d720` | `"sigattr_tail"` |
| `0x1097d74c` | `"this_sigattrlog"` |
| `0x10987530` | `"attribute"` (node type) |
| `0x1098753c` | `"matched"` (node type) |
| `0x10987548` | `"np2"` (node type) |
| `0x1098754c` | `"p1"` (node type) |
| `0x10987550` | `"p2"` (node type) |
| `0x10987558` | `"np1"` (node type) |
| `0x10b69564` | Nibble parity table 1 (16 bytes) |
| `0x10b69590` | Nibble parity table 2 (16 bytes) |

### Object Offsets

| Offset | Context | Description |
|--------|---------|-------------|
| `+0x2240` | Resolved state | Tree data pointer |
| `+0x32c` | Container obj | Active tree vector |
| `+0x330` | Container obj | Alternate tree vector |
| `+0x37d4` | JIT context | JIT buffer base pointer |
| `+0x37dc` | JIT context | JIT buffer write offset |
| `+0x30` | SigAttr log | Flags (bit 2 = available) |
| `+0x44` | SigAttr log | Log data arrays pointer |
| `+0x82ee4` | Global state | Sigattr events array |
| `+0x836e4` | Global state | Sigattr event count |

---

## Evaluation Behavior (Reverse-Engineered)

### Weighted Scoring System (FUN_1007ced5)

The tree evaluator uses weighted scoring over sigattr slots:

- **Node weights**: `sig_flags` bytes 2-3 encode per-node weight (26,165 unique weight values observed)
- **Slot formula**: `base + attr_idx * 0x90 - 0x2C4`
- **Accumulation**: `slot[1] += weight`, high-water mark: `if slot[0] < slot[1] then slot[0] = slot[1]`
- **Weight thresholds**: > `0x10` for "best score" tracking, > `0x13` with category `0x06` for escalation
- **Per-tree totals**: Range from ~1,075 to ~64,256

### Priority Arbitration (FUN_1018d68b)

Detection output uses priority-based arbitration, **not** score aggregation across trees:

- **Level 1** (specific named threat): e.g. `Trojan:Win32/Foo.A!MTB` — highest priority
- **Level 2** (generic heuristic): e.g. `HLL/Generic` — lower priority
- **First level-1 detection wins** and short-circuits evaluation
- **"HLL" prefix** detections are suppressed
- **InfrastructureShared** trees are infrastructure classifiers, not user-visible threat names

### Detection Criteria (0x40 trees)

Three attribute categories determine detection:
1. **Trivial** (16 attrs): Always true for x86 PEs (`no_mipsgp`, `executable_image`, etc.)
2. **Discriminating** (34 attrs): Malware-specific indicators (`packed`, W+X section, etc.)
3. **Nontrivial**: Everything not trivial

### VDM Statistics

| Metric | Value |
|--------|-------|
| Total trees | 33,428 |
| Total nodes | 408,708 |
| Nodes with inline strings | 66,163 |
| Unique inline strings | 35,965 |
| Unique weight values | 26,165 |
| Max nodes per tree | 250 |
| SIG_TREE parse completeness | 100% |
| SIG_TREE_EXT parse completeness | 89% |
| SIG_TREE_BM parse completeness | 47% |

---

## PE Boolean Attribute System

SIG_TREE 0x40 trees use boolean PE attributes indexed by `sig_flags` byte 0. The
peattributes table at mpengine.dll offset **0x00982F30** defines ~300 flags:

| Index | Attribute | Description |
|-------|-----------|-------------|
| `0x00` | `lastscn_writable` | Last section is writable |
| `0x03` | `no_relocs` | No relocation directory |
| `0x08` | `epscn_eqsizes` | EP section virtual = raw size |
| `0x0E` | `epatscnstart` | EP at section start |
| `0x11` | `packed` | File appears packed |
| `0x16` | `isdll` | Is a DLL |
| `0x1E` | `entrybyte55` | EP starts with PUSH EBP |
| `0x1F` | `headerchecksum0` | PE checksum is zero |
| `0x21` | `no_imports` | No imports |
| `0x28` | `issuspicious` | File is suspicious |
| `0x67` | `suspicious_section_characteristics` | W+X section |
| `0x6F` | `no_fixups` | No relocation table |
| `0x72` | `no_mipsgp` | No MIPS GP (true for x86) |
| `0x73` | `no_tls` | No TLS directory |
| `0x7A` | `executable_image` | IMAGE_FILE_EXECUTABLE_IMAGE |
| `0x8D` | `nx_bit_set` | DEP/NX compatible |
| `0x9D` | `aslr_bit_set` | ASLR enabled |
| `0x9F` | `amd64_image` | AMD64 machine type |
| `0xC3` | `ismsil` | .NET MSIL binary |

A separate **PE Header Field Table** at file offset **0x00B516A8** provides 38 entries mapping
PE header field names to indices 0-37, used by the Lua `pehdr.__index` handler.

---

## Tree Type Classification

7 tree_type values are used (set in header byte 3):

| tree_type | Name | Count | With Strings | Description |
|-----------|------|-------|--------------|-------------|
| 0 | UNKNOWN | 196 | 0 | Unknown/legacy |
| 1 | LEAF | 1,264 | 36 | Leaf-only trees |
| 2 | EXT | 14,731 | 10,046 | Extended (BM sig type) |
| 3 | BM | 8,607 | 1,657 | Behavioral monitoring |
| 4 | PEST | 358 | 90 | PE static analysis |
| 5 | NID | 6,961 | 1,059 | Named ID trees |
| 6 | MACRO | 1,311 | 905 | Office macro trees |

---

## Key mpengine.dll Functions

| Address | Name | Description |
|---------|------|-------------|
| `0x104c05a0` | SIG_TREE_Init | Plugin init, registers handlers for 0x40, 0x41, 0xB3 |
| `0x104c03a0` | Handler_0x40 | SIG_TREE handler |
| `0x104c04a0` | Handler_0x41 | SIG_TREE_EXT handler |
| `0x104c0420` | Handler_0xB3 | SIG_TREE_BM handler |
| `0x104bd759` | NodeExpansion | 16-byte VDM → 36-byte intermediate |
| `0x104bdc13` | Finalization | Sort + group + serialize |
| `0x104bab80` | SortComparator | Introsort for node ordering |
| `0x1014bc5f` | Serialization | 36-byte → 32-byte runtime |
| `0x1012b02a` | TreeDataLoader | Reads 32-byte entries at scan time |
| `0x1007ccdd` | NodeDispatcher | Dispatches on marker byte (0x30) |
| `0x1007ce03` | RangeEvaluator | Calls slot comparison |
| `0x1007ced5` | SlotComparison | Weighted scoring in sigattr slots |
| `0x100d3c29` | AttrNameResolver | Binary search name → index |
| `0x1018d68b` | DetectionArbitrator | Priority-based detection selection (L1 > L2) |

---

## Open Questions

1. **Attribute ID mapping** — The `attribute_id` field (u16 at node+0x02 in 32-byte format) indexes
   into the sigattr log, but the mapping from numeric IDs to named features (like
   `Nscript:js_hasBigString`) needs further investigation. CRC16 hashing tests show noise-level
   matches (~85/329), suggesting a table-based rather than hash-based mapping.

2. **SIG_TREE_BM parse completeness** — 47% of BM trees parse correctly. BM uses u8 node_count
   at data[0] (not u16), and data[1] is a separate depth/variant field (values 0x00-0x04).

3. **Simplified tree walk** — The real engine walks one path root-to-leaf with branch/sibling
   fallback and uses accumulated weights to choose paths. Full path-selection logic is partially
   understood but not yet fully reproduced.

4. **Wildcard pattern matching** — The 0x90 escape byte in SIG_TREE_EXT path strings encodes
   wildcard patterns (`0x90 0x02 0xNN` = wildcard with NN min-length). The full pattern matching
   grammar needs further RE.
