# Stage 5: PE Emulation

> How mpengine.dll emulates x86/x64/ARM PE executables to observe runtime behavior, unpack protected code, and extract behavioral signatures.
> All data from reverse engineering mpengine.dll v1.1.24120.x (14.3 MB, PE32 x86).

---

## Overview

Stage 5 is the PE emulation engine -- a full CPU emulator embedded within mpengine.dll that executes PE files in a sandboxed virtual environment. The emulator interprets x86, x64, and ARM instructions, provides 198 emulated Windows API handlers (including CryptAPI and BCrypt), loads 973 virtual DLLs (VDLLs) into a synthetic address space, and records behavioral telemetry (FOP opcode traces and API call logs) for signature matching. The emulator runs with a default budget of **5 million instructions** (configurable), processing in batches of ~1,000.

The emulator's primary purpose is **dynamic unpacking**: many malware samples encrypt or compress their payloads and only reveal the real code at runtime. By emulating execution, Defender can observe the decrypted payload and scan it through the full pipeline recursively (Stage 6). Full exception handling support (VEH, SEH chain walking, x64 table-driven RUNTIME_FUNCTION dispatch) ensures packed malware that uses SEH-based control flow transfer is handled correctly.

### Key RTTI Classes from the Binary

| RTTI Class | Address | Purpose |
|------------|---------|---------|
| `.?AVx86_IL_emulator@@` | `0x10C748CC` | x86 instruction-level emulator |
| `.?AVIL_emulator@@` | `0x10C74B6C` | Base emulator interface |
| `.?AVARM_IL_emulator@@` | `0x10C921C8` | ARM instruction-level emulator |
| `.?AVvdll_data_t@@` | `0x10C7C940` | Virtual DLL data structure |
| `.?AVVirtualProtectCallback@@` | `0x10C7B7B0` | VirtualProtect handler |
| `.?AVPEUnpacker@@` | `0x10C7F6D4` | PE unpacker base class |
| `.?AVUnpackerContext@@` | `0x10C79618` | Unpacker execution context |
| `.?AVUnpackerData@@` | `0x10C852A4` | Unpacker data storage |

*(from RE of mpengine.dll -- `.?AV` RTTI strings in .data section)*

---

## Architecture

### Emulator Class Hierarchy

```
IL_emulator (abstract base)          @ 0x10C74B6C
├── x86_IL_emulator                  @ 0x10C748CC
│   ├── Handles x86 (32-bit) instructions
│   ├── Full FPU emulation via 67 exported FPU_* functions
│   └── SSE conversion via SSE_convert export
├── x86_64_IL_emulator               (inferred from x64 sig types)
│   └── Extends x86 with 64-bit register support
└── ARM_IL_emulator                  @ 0x10C921C8
    └── Handles ARM 32-bit instructions
```

### Virtual Memory Layout

The emulator establishes a synthetic address space for each emulated PE:

```
Virtual Address Map (32-bit PE):
─────────────────────────────────────────────────
0x00010000  ┌─────────────────────────┐
            │  Stack                   │  ← ESP initialized here
            │  (grows downward)        │
0x00020000  ├─────────────────────────┤
            │  TEB / PEB              │  ← Thread/Process Environment
            │                          │     Blocks (synthetic)
0x00030000  ├─────────────────────────┤
            │  LDR Data               │  ← Loader data structures
            │  (module list)           │     (linked list of modules)
0x00400000  ├─────────────────────────┤
            │  PE Image               │  ← Scanned file mapped here
            │  (sections mapped per   │     (at preferred ImageBase)
            │   PE section table)     │
0x10000000  ├─────────────────────────┤
            │  Heap                    │  ← Dynamic allocations
            │  (VirtualAlloc, malloc)  │     from emulated API calls
0x70000000  ├─────────────────────────┤
            │  VDLLs (973 modules)     │  ← Virtual DLLs mapped here
            │  kernel32.dll (vdll)     │     Provide API stubs and
            │  ntdll.dll (vdll)        │     trampoline targets
            │  user32.dll (vdll)       │
            │  ...                     │
0x7FFE0000  ├─────────────────────────┤
            │  API Trampolines        │  ← Transition from emulated
            │                          │     code to WinAPI handlers
0xDEADBEEF  ├─────────────────────────┤
            │  Stop Sentinel           │  ← Execution terminates if
            │                          │     EIP reaches this address
            └─────────────────────────┘
```

*(from RE of mpengine.dll -- memory layout reconstructed from emulator initialization and VDLL mapping logic)*

---

## FPU Emulation

The emulator exports 67 `FPU_*` functions for x87 floating-point instruction emulation. These are real exports from mpengine.dll, callable externally:

### FPU Export Table (67 functions)

| Export | Address | Instruction |
|--------|---------|-------------|
| `FPU_initialize` | `0x10266050` | Initialize FPU state |
| `FPU_finit` | `0x10266020` | FINIT -- reset FPU |
| `FPU_push` | `0x102663B0` | Push value onto FPU stack |
| `FPU_pop` | `0x102663E0` | Pop value from FPU stack |
| `FPU_fld_single` | `0x10266450` | Load 32-bit float |
| `FPU_fld_double` | `0x102664C0` | Load 64-bit float |
| `FPU_fld_ext` | `0x10266530` | Load 80-bit extended |
| `FPU_fst_single` | `0x10266760` | Store 32-bit float |
| `FPU_fst_double` | `0x102667D0` | Store 64-bit float |
| `FPU_fst_ext` | `0x10266840` | Store 80-bit extended |
| `FPU_fadd` | `0x10266C50` | FADD -- addition |
| `FPU_fsub` | `0x10266ED0` | FSUB -- subtraction |
| `FPU_fsubr` | `0x10266F50` | FSUBR -- reverse subtract |
| `FPU_fmul` | `0x102670D0` | FMUL -- multiplication |
| `FPU_fdiv` | `0x10266FD0` | FDIV -- division |
| `FPU_fdivr` | `0x10267050` | FDIVR -- reverse divide |
| `FPU_fcom` | `0x10266CD0` | FCOM -- compare |
| `FPU_fcomi` | `0x10266DD0` | FCOMI -- compare to int |
| `FPU_fucom` | `0x10266D50` | FUCOM -- unordered compare |
| `FPU_fucomi` | `0x10266E50` | FUCOMI -- unordered compare int |
| `FPU_fchs` | `0x102672D0` | FCHS -- change sign |
| `FPU_fabs` | `0x10267340` | FABS -- absolute value |
| `FPU_fsqrt` | `0x10267570` | FSQRT -- square root |
| `FPU_fsin` | `0x10267650` | FSIN -- sine |
| `FPU_fcos` | `0x102676C0` | FCOS -- cosine |
| `FPU_fsincos` | `0x102678D0` | FSINCOS -- sine and cosine |
| `FPU_fptan` | `0x10267500` | FPTAN -- partial tangent |
| `FPU_fpatan` | `0x10267950` | FPATAN -- partial arctangent |
| `FPU_f2xm1` | `0x10267490` | F2XM1 -- 2^x - 1 |
| `FPU_fyl2x` | `0x10267730` | FYL2X -- y * log2(x) |
| `FPU_fyl2xp1` | `0x102677C0` | FYL2XP1 -- y * log2(x+1) |
| `FPU_fscale` | `0x10267250` | FSCALE -- scale by power of 2 |
| `FPU_frndint` | `0x102675E0` | FRNDINT -- round to integer |
| `FPU_fxch` | `0x10266BC0` | FXCH -- exchange registers |
| `FPU_fxtract` | `0x10267850` | FXTRACT -- extract exp/sig |
| `FPU_fprem` | `0x10267150` | FPREM -- partial remainder |
| `FPU_fprem1` | `0x102671D0` | FPREM1 -- IEEE remainder |
| `FPU_ftst` | `0x102673B0` | FTST -- test against 0.0 |
| `FPU_fxam` | `0x10267420` | FXAM -- examine FP value |
| `FPU_fld1` | `0x102679E0` | FLD1 -- load 1.0 |
| `FPU_fldl2t` | `0x10267A50` | FLDL2T -- load log2(10) |
| `FPU_fldl2e` | `0x10267AC0` | FLDL2E -- load log2(e) |
| `FPU_fldpi` | `0x10267B30` | FLDPI -- load pi |
| `FPU_fldlg2` | `0x10267BA0` | FLDLG2 -- load log10(2) |
| `FPU_fldln2` | `0x10267C10` | FLDLN2 -- load ln(2) |
| `FPU_fldz` | `0x10267C80` | FLDZ -- load 0.0 |
| `FPU_fild_s16` | `0x102665A0` | FILD -- load 16-bit int |
| `FPU_fild_s32` | `0x10266610` | FILD -- load 32-bit int |
| `FPU_fild_s64` | `0x10266680` | FILD -- load 64-bit int |
| `FPU_fist_s16` | `0x10266A00` | FIST -- store 16-bit int |
| `FPU_fist_s32` | `0x10266A70` | FIST -- store 32-bit int |
| `FPU_fist_s64` | `0x10266AE0` | FIST -- store 64-bit int |
| `FPU_fistt_s16` | `0x102668B0` | FISTTP -- store truncated 16 |
| `FPU_fistt_s32` | `0x10266920` | FISTTP -- store truncated 32 |
| `FPU_fistt_s64` | `0x10266990` | FISTTP -- store truncated 64 |
| `FPU_fbld` | `0x102666F0` | FBLD -- load BCD |
| `FPU_fbst` | `0x10266B50` | FBST -- store BCD |
| `FPU_fldenv_16` | `0x102661A0` | FLDENV -- load 16-bit env |
| `FPU_fldenv_32` | `0x10266210` | FLDENV -- load 32-bit env |
| `FPU_fstenv_16` | `0x10266270` | FSTENV -- store 16-bit env |
| `FPU_fstenv_32` | `0x102662E0` | FSTENV -- store 32-bit env |
| `FPU_fstsw` | `0x10266090` | FSTSW -- store status word |
| `FPU_ext2double` | `0x10266410` | Convert extended to double |
| `FPU_get_reg` | `0x10266350` | Read FPU register by index |
| `FPU_set_rndprec` | `0x10266150` | Set rounding/precision mode |
| `FPU_save_state` | `0x10266070` | Save entire FPU state |
| `FPU_restore_state` | `0x10266080` | Restore FPU state |

### SSE Support

| Export | Address | Purpose |
|--------|---------|---------|
| `SSE_convert` | `0x10267CF0` | SSE conversion operations |

---

## Emulated Windows API Handlers

The emulator provides 198 Windows API handler functions that intercept calls made by the emulated PE. When emulated code calls a WinAPI function, execution transfers to a trampoline at `0x7FFE0000+`, which routes to the corresponding handler.

### API Categories and Selected Handlers

**Memory Management:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `VirtualAlloc` | `0x10C6B4F6` | Allocate virtual memory |
| `VirtualProtect` | `0x10C6BA2A` | Change memory protection |
| `VirtualProtectEx` | `0x10C6CE14` | Change protection (extended) |

**File Operations:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `CreateFileW` | `0x10C6B562` | Create/open file (VFS write) |
| `CreateFileMappingW` | `0x10C6B710` | Memory-map a file |

**Library Loading:**
| API | String Address | Purpose |
|-----|---------------|---------|
| `LoadLibraryA` | `0x10C6B78E` | Load DLL by ANSI name |
| `LoadLibraryW` | `0x10C6BDA8` | Load DLL by Unicode name |
| `LoadLibraryExW` | `0x10C6B458` | Load DLL with flags |

*(from RE of mpengine.dll -- WinAPI strings in .rdata near emulator dispatch tables)*

### API Handler Architecture

```
Emulated code at 0x00400000+
         │
         │ CALL [IAT entry]  →  resolves to VDLL stub
         │
         ▼
VDLL stub at 0x70000000+
         │
         │ JMP [trampoline]
         │
         ▼
Trampoline at 0x7FFE0000+
         │
         │ Triggers host-side handler dispatch
         │
         ▼
Handler in mpengine.dll (native code)
         │
         │ 1. Read parameters from emulated stack
         │ 2. Simulate API behavior
         │ 3. Record in APICLOG
         │ 4. Write return value to emulated EAX
         │ 5. Return control to emulator
         │
         ▼
Emulated code continues at return address
```

---

## Execution Engine

### Instruction Processing Loop

The core emulation loop processes instructions in batches of approximately 1,000, checking
control conditions between each batch:

```
Pseudocode:
─────────────────────────────────────────────────────────────────────────

emulate_main_loop(ctx):
    insn_count = 0
    max_instructions = 5,000,000    // Default budget (configurable via DBVAR)
    batch_size = 1,000

    loop:
        // Execute a batch of instructions
        execute_batch(ctx, batch_size)
        insn_count += batch_size

        // Check stop sentinel
        if EIP == 0xDEADBEEF:
            break  // Normal termination (return address sentinel)

        // Check instruction budget
        if insn_count >= max_instructions:
            // "abort: execution limit met (%u instructions)"
            //     @ 0x109334D8
            break

        // Check for API trampoline hit (0F FF F0 opcode at current IP)
        if [EIP] == 0x0F 0xFF 0xF0:
            api_id = EAX
            dispatch_api_handler(ctx, api_id)

        // Check for direct syscall (0F 05 = SYSCALL, 0F 34 = SYSENTER)
        if [EIP] == 0x0F 0x05 or [EIP] == 0x0F 0x34:
            dispatch_syscall(ctx, EAX)

        // Self-modifying code: flush translation cache if code regions were written
        if code_region_written:
            flush_translation_cache()

        // FPU instruction: route to exported FPU_* handler
        if opcode_type == DASM_OPTYPE_FPU_RM:
            // "DASM_OPTYPE_FPU_RM" @ 0x109815DC
            execute_fpu_instruction(ctx, insn)
```

### Execution Limits

| Limit | Value | String/Source |
|-------|-------|---------------|
| Max instructions per run | 5,000,000 | `"abort: execution limit met (%u instructions)"` @ `0x109334D8` |
| Instruction batch size | ~1,000 | Between-batch control checks |
| Fopclog max entries | 8,192 | First-opcode-byte recording cap |
| Max SEH dispatches | 64 | Prevents infinite exception loops |
| TLS callback budget | 50,000 per callback | Budget before main entry point |
| DllMain budget | 10,000 per VDLL | Budget for VDLL initialization |
| Tight loop detection | 50,000 insns without API call | Anti-analysis delay loop detection |
| Consecutive error limit | 3 | Unhandled exception termination |

*(from RE of mpengine.dll -- execution limit strings and emulator control flow)*

---

## Exception Handling

The emulator supports three exception handling mechanisms, checked in priority order:

### VEH (Vectored Exception Handlers)

VEH handlers registered via `AddVectoredExceptionHandler` are checked **before** the SEH chain
on x86. Dispatch builds `EXCEPTION_POINTERS { ExceptionRecord*, ContextRecord* }` on the emulated
stack and calls the handler. Return value `0xFFFFFFFF` (`EXCEPTION_CONTINUE_EXECUTION`) resumes
execution; `0` (`EXCEPTION_CONTINUE_SEARCH`) tries the next handler.

### SEH (x86 Structured Exception Handling)

The SEH chain is walked from `TEB[0x00]` (FS:[0]). Up to 32 frames are walked. For each handler:
1. Builds `EXCEPTION_RECORD` (80 bytes) and `CONTEXT` (716 bytes) on the emulated stack
2. Calls handler with arguments: `(ExceptionRecord*, EstablisherFrame*, ContextRecord*, DispatcherContext*)`
3. Sets return address to SEH return sentinel (`0xDEADC0DE`)
4. Handler return value `0` = continue execution; `1` = continue search

### x64 Table-Driven Exception Handling

x64 uses `RUNTIME_FUNCTION` entries parsed from the PE's exception directory (data directory 3):
1. Binary-searches the sorted `RUNTIME_FUNCTION` table for the faulting RIP
2. Reads `UNWIND_INFO` at the entry's `UnwindInfoAddress`
3. Checks for `UNW_FLAG_EHANDLER` (1) or `UNW_FLAG_UHANDLER` (2) flags
4. Reads handler RVA from after the unwind codes array
5. Sets up x64 fastcall call: RCX=ExceptionRecord*, RDX=EstablisherFrame, R8=ContextRecord*

---

## TEB/PEB Environment Setup

The emulator constructs a realistic Windows process environment that defeats common sandbox
detection techniques used by malware.

### Segment Configuration

- **x86**: FS segment base → TEB at `0x00020000`
- **x64**: GS segment base → TEB at `0x00020000`

### Process Parameters (Fake Environment)

```
Key TEB/PEB fields:
  FS:[0x18] / GS:[0x30]  Self-pointer (TEB address)
  FS:[0x30] / GS:[0x60]  PEB pointer
  PEB.BeingDebugged       = 0 (anti-debug)
  PEB.NtGlobalFlag        = 0 (anti-debug)
  PEB.ImageBaseAddress     = loaded PE base
  PEB.Ldr                  = PEB_LDR_DATA (module list)
  PEB.ProcessParameters    = RTL_USER_PROCESS_PARAMETERS

Process Parameters:
  ComputerName:  HAL9TH          (not "DESKTOP-...", matches mpengine default)
  UserName:      JohnDoe         (not "admin" or "malware")
  ImagePath:     C:\Users\JohnDoe\Desktop\target.exe
  CurrentDir:    C:\Windows\System32\
  SystemRoot:    C:\Windows
  TEMP:          C:\Windows\Temp
```

The PEB_LDR_DATA maintains three doubly-linked module lists (`InLoadOrderModuleList`,
`InMemoryOrderModuleList`, `InInitializationOrderModuleList`) populated with the target PE
and loaded VDLLs. Malware that walks these lists for DLL enumeration sees a realistic module chain.

---

## Cryptographic API Emulation

### CryptAPI (ADVAPI32.DLL)

The emulator tracks cryptographic state (hash objects, key objects) for operations including:
- `CryptAcquireContext` / `CryptReleaseContext` -- provider management
- `CryptCreateHash` / `CryptHashData` / `CryptGetHashParam` -- MD5, SHA-1, SHA-256 hashing
- `CryptDeriveKey` / `CryptGenKey` / `CryptImportKey` -- key management
- `CryptDecrypt` / `CryptEncrypt` -- RC4 stream cipher, AES-CBC/ECB block cipher
- `CryptSetKeyParam` -- IV and cipher mode configuration

### BCrypt (BCRYPT.DLL)

Modern CNG API support:
- `BCryptOpenAlgorithmProvider` -- AES, RC4, SHA-256, etc.
- `BCryptGenerateSymmetricKey` -- key import/generation
- `BCryptDecrypt` / `BCryptEncrypt` -- block/stream cipher operations

This enables the emulator to observe malware that decrypts its payload using Windows crypto APIs
before executing it.

---

## Memory Tracking and Content Extraction

### Dirty Page Tracking

A memory write hook records every written page address (page-aligned) during emulation. This
identifies which memory regions were modified by the emulated code.

### Self-Modifying Code Detection

PE section address ranges are registered as "code regions." When a write targets any of these
ranges, the translation block cache is invalidated at the next batch boundary, ensuring
self-modified code executes correctly.

### Unpacked Content Extraction

After emulation completes, modified memory is collected:
1. **PE sections**: All sections are read back; sections with >16 non-zero bytes are included
2. **Dirty pages outside PE**: Pages not in PE sections, stack, TEB, or trampoline regions
   are coalesced into contiguous regions (capped at 1MB per region)
3. **Embedded PE scan**: Extracted data is scanned for `MZ` + `PE\0\0` signatures to find
   unpacked PE payloads

### Dropped File Collection

Files created during emulation are collected from two sources:
1. **VFS write tracking**: Files added via `CreateFileW` / `WriteFile` during emulation
2. **Object manager**: Writable file handles with non-empty data

All extracted content is fed back through the full scan pipeline at Stage 6 (Unpacked Content).

---

## APC Draining

When `NtQueueApcThread` is called during emulation, APC routines are queued. When the main
emulation loop reaches the stop sentinel or instruction budget, any pending APCs are drained
(each queued routine is called with its arguments) before termination. This handles malware
that uses APC injection to execute unpacking code.

---

## Behavioral Recording

### FOP (First Opcode Profile)

FOP signatures capture the first N unique opcode sequences at the entry point. This creates a behavioral fingerprint independent of data values:

```
Signature types for FOP:
  SIGNATURE_TYPE_FOP            @ 0x10986C44
  SIGNATURE_TYPE_FOP64          @ 0x109871BC
  SIGNATURE_TYPE_FOPEX          @ 0x10986514
  SIGNATURE_TYPE_FOPEX64        @ 0x10986C70
  SIGNATURE_TYPE_VBFOP          @ 0x10986074
  SIGNATURE_TYPE_VBFOPEX        @ 0x109869F8
  SIGNATURE_TYPE_MSILFOP        @ 0x10986BCC
  SIGNATURE_TYPE_MSILFOPEX      @ 0x10986710
```

FOP rules in the VDM: **4,601** rules across all architectures.

### TUNNEL Signatures

TUNNEL signatures detect patterns in the code flow between the entry point and the first API call:

```
Signature types for TUNNEL:
  SIGNATURE_TYPE_TUNNEL_X86     @ 0x109860A4
  SIGNATURE_TYPE_TUNNEL_X64     @ 0x10986344
  SIGNATURE_TYPE_TUNNEL_ARM     @ 0x10986460
  SIGNATURE_TYPE_TUNNEL_ARM64   @ 0x1098713C
```

### THREAD Signatures

THREAD signatures detect patterns in multi-threaded behavior during emulation:

```
Signature types for THREAD:
  SIGNATURE_TYPE_THREAD_X86     @ 0x109860F4
  SIGNATURE_TYPE_THREAD_X64     @ 0x1098703C
  SIGNATURE_TYPE_THREAD_ARM     @ 0x10986B00
  SIGNATURE_TYPE_THREAD_ARM64   @ 0x10986B58
```

---

## Virtual DLL System

### VDLL Architecture

973 virtual DLLs are loaded into the emulated address space at `0x70000000+`. Each VDLL provides:
- Export stubs that route to API handler trampolines
- Symbolic information for import resolution (`SIGNATURE_TYPE_VDLL_SYMINFO` @ `0x1098614C`)
- Realistic PE structure for malware that validates loaded modules

### VDLL-Related Strings

| String | Address | Purpose |
|--------|---------|---------|
| `isvdllbase` | `0x109819CC` | Check if address is VDLL base |
| `isvdllimage` | `0x109819D8` | Check if address is in VDLL range |
| `reads_vdll_code` | `0x10985924` | VDLL code section reads |
| `dynmem_reads_vdll_code` | `0x10984F48` | Dynamic mem reads VDLL |
| `verbose_vdll_reads` | `0x10985DE8` | Verbose VDLL read logging |
| `NDAT_VFS_LINK` | `0x109811F8` | VFS link for VDLL data |

*(from RE of mpengine.dll -- VDLL strings in .rdata)*

### Import Resolution

When the emulated PE imports a function from e.g. `kernel32.dll`:

1. The emulator finds the corresponding VDLL for `kernel32.dll` in the 973-module list.
2. Resolves the export by name from the VDLL's export table.
3. Patches the Import Address Table (IAT) entry to point to the VDLL export stub.
4. When the emulated code calls through the IAT, it hits the VDLL stub, which jumps to a trampoline, which dispatches to the native handler.

---

## Re-emulation

The emulator supports re-emulation -- running a PE through the emulator again after initial analysis:

```
Key strings:
  "reemulate"     @ 0x10981878
  "MpReemulate"   @ 0x10B76A08
```

Re-emulation can be triggered by:
- Lua scripts requesting deeper analysis
- AAGGREGATOR rules that need post-emulation attributes
- Cloud-returned directives requesting re-analysis with different parameters

---

## Emulation Control Attributes

These attributes (set by static engine matches or DBVAR configuration) control emulation behavior:

| Attribute | Address | Effect |
|-----------|---------|--------|
| `force_unpacking` | `0x109852D4` | Force dynamic unpacking |
| `disable_static_unpacking` | `0x10984AE8` | Disable static unpackers |
| `dt_continue_after_unpacking` | `0x10984D1C` | Continue after unpack |
| `dt_continue_after_unpacking_damaged` | `0x10984D38` | Continue if damaged |
| `pea_force_unpacking` | `0x10A11570` | PE-specific force unpack |
| `pea_disable_static_unpacking` | `0x10A110B8` | PE-specific disable static |

### NID Control Tokens

NID (Named IDentifier) tokens in the VDM database provide engine-level control:

| Token | Address | Purpose |
|-------|---------|---------|
| `NID_DT_CONTINUE_AFTER_UNPACKING` | `0x10980A7C` | Continue post-unpack |
| `NID_DT_CONTINUE_AFTER_DAMAGED_UNPACKING` | `0x10980B5C` | Continue if damaged |
| `NID_DT_DISABLE_STATIC_UNPACKING` | `0x10980C30` | Disable static unpackers |
| `NID_DT_ENABLE_STATIC_UNPACKING` | `0x10980C50` | Enable static unpackers |
| `NID_DT_SKIP_UNIMPLEMENTED_OPCODES` | `0x10980A9C` | Skip unimplemented ops |
| `NID_DT_DISABLE_SKIP_UNIMPLEMENTED_OPCODES` | `0x10980AC0` | Force fail on unimpl ops |
| `NID_DT_DISABLE_MICROCODE` | `0x10980C8C` | Disable microcode engine |
| `NID_DT_ENABLE_MICROCODE` | `0x10980CA8` | Enable microcode engine |
| `NID_DISABLE_THREAD_API_LIMITS` | `0x10980CDC` | Remove thread API limits |

*(from RE of mpengine.dll -- NID_DT strings in .rdata)*

---

## PE Analysis Attributes (set_peattribute)

The `set_peattribute` function at string address `0x10981988` deposits structural attributes during PE header parsing, before emulation begins. These 302 `pea_*` attributes describe the static structure of the PE.

See [Stage 4 -- AAGGREGATOR Collection](04_aaggregator_collection.md) for the full list of PE attributes.

---

## VFS (Virtual File System) for Dropped Files

During emulation, when the emulated code calls `CreateFileW` / `WriteFile`, the emulator intercepts these and writes to a Virtual File System:

```
VFS-related strings:
  "NDAT_VFS_LINK"        @ 0x109811F8
  "VFSParams"            @ 0x10B76888
  "(VFS:%ls#%zd)"        @ 0x10B87920
  "(VFS:...%ls#%zd)"     @ 0x10B8790C
  "(VFS:#%zd)"           @ 0x10B87900
  "->(VFS:hosts)"        @ 0x10A4AE44
```

VFS-dropped files are extracted after emulation and fed back through the scan pipeline in Stage 6 (Unpacked Content Scanning).

---

## Emulator Statistics

| Metric | Value |
|--------|-------|
| FPU export functions | 67 |
| SSE export functions | 1 (SSE_convert) |
| Emulated WinAPI handlers | 198 |
| Virtual DLLs (VDLLs) | 973 (750 x86 + 195 x64 + 18 ARM + 10 MSIL) |
| Max instructions per run | 5,000,000 (configurable via DBVAR) |
| Instruction batch size | ~1,000 |
| Fopclog max entries | 8,192 |
| Max SEH dispatches | 64 |
| TLS callback budget | 50,000 per callback |
| DllMain budget | 10,000 per VDLL |
| FOP behavioral rules | 4,601 |
| TUNNEL signature variants | 4 (x86, x64, ARM, ARM64) |
| THREAD signature variants | 4 (x86, x64, ARM, ARM64) |
| PE analysis attributes | 302 (`pea_*`) |
| Emulator RTTI classes | 3 (x86, base, ARM) |
| Crypto support | CryptAPI (MD5/SHA/AES/RC4) + BCrypt |

---

## Cross-References

- **Previous stage**: [Stage 4 -- AAGGREGATOR Collection](04_aaggregator_collection.md) (PE attributes deposited here)
- **Next stage**: [Stage 6 -- Unpacked Content](06_unpacked_content.md) (unpacked PE and VFS files scanned)
- **Behavioral signatures**: Used by [Stage 9 -- BRUTE Matching](09_brute_matching.md) and [Stage 10 -- Lua Scripts](10_lua_scripts.md)
- **Attribute evaluation**: [Stage 11 -- AAGGREGATOR Evaluation](11_aaggregator_evaluation.md) (FOP/TUNNEL/THREAD attributes consumed)
- **Pipeline overview**: [Master Overview](00_overview.md)

---

*Generated from reverse engineering of mpengine.dll v1.1.24120.x*
