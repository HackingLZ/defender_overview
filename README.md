# Windows Defender Scan Pipeline — Reverse Engineering Reference

A reverse engineering breakdown of the 13-stage scan pipeline inside **mpengine.dll** (v1.1.24120.x, 14.3 MB, PE32 x86) — the core engine DLL behind Windows Defender / Microsoft Defender Antivirus. Every file, script, and memory buffer scanned on a Windows machine flows through this single monolithic binary.

Each stage is documented with reconstructed data structures, pseudocode, address-level references, RTTI class hierarchies, and string table extractions from the binary itself.

**Note:** If it wasn't obvious, this knowledge base was created as an LLM-driven experiment — the documentation, slide decks, and structural analysis were generated with significant AI assistance. The content will be iterated on and improved over time as findings are validated and refined through hands-on reverse engineering.

## Disclaimer

This material is provided for educational and research purposes only.
All findings and technical claims should be independently validated in your own environment before you rely on them.

## Repository Structure

```
├── master_slide.html          # Slide launcher — links to all 14 decks
├── md/                        # Detailed written docs (one per stage)
│   ├── 00_overview.md         # Master overview, data structures, entry points
│   ├── 01_entry_point.md      # through
│   └── 13_verdict_resolution.md
├── slides/                    # HTML slide decks (one per stage)
│   ├── 00_overview_slides.html
│   ├── ...
│   ├── 13_verdict_resolution_slides.html
│   └── deck_master_nav.js     # Shared nav controls (Back, Master, Prev/Next Deck)
```

Each stage has two artifacts:

| Format | Path pattern | Content |
|--------|--------------|---------|
| Markdown | `md/NN_<stage>.md` | Full writeup with pseudocode, tables, and address references |
| Slides | `slides/NN_<stage>_slides.html` | Visual presentation deck for the same material |

Open `master_slide.html` in a browser to navigate across all decks.

## Pipeline Stages

The scan pipeline is sequential — each stage can produce detections, collect attributes for downstream stages, or recursively invoke the entire pipeline on extracted content.

| # | Stage | What It Does |
|---|-------|-------------|
| 00 | **Overview** | End-to-end map of the pipeline architecture, `ScanContext` / `ThreatRecord` data structures, and the `__rsignal` / `rsignal` export API |
| 01 | **Entry Point** | How `__rsignal` and `rsignal` receive scan commands, dispatch by command code, and initialize the `ScanContext` for execution |
| 02 | **Friendly File** | SHA-256/SHA-512 trusted-file whitelist lookup — files that match are immediately returned clean, short-circuiting the rest of the pipeline |
| 03 | **Static Engine Cascade** | 11 signature engines that fire in a fixed order over raw file bytes: STATIC, PEHSTR, PEHSTR_EXT, MACRO, KCRCE, BRUTE, NID, DBVAR, VDLL_SIG, ARHSTR, and MSILFLAG |
| 04 | **Attribute Collection** | Continuous collection of string-tag attributes into the scan context — fed into the AAGGREGATOR boolean evaluator at Stage 11 |
| 05 | **PE Emulation** | Full x86/x64/ARM CPU emulator embedded in the engine: 198 emulated Windows APIs, 973 virtual DLLs, FOP opcode tracing, and behavioral telemetry for dynamic unpacking |
| 06 | **Unpacked Content** | Recursive rescan of PE sections and files dropped by the emulator — feeds unpacked content back through the full pipeline |
| 07 | **Container Extraction** | Recursive extraction of child objects from archives, Office docs, PDFs, installers, and other containers via pluggable nUFS format handlers |
| 08 | **Script Deobfuscation** | NScript fixed-point deobfuscation engine for PowerShell, VBScript, JScript, and Batch — iteratively simplifies obfuscated scripts until stable |
| 09 | **BRUTE Matching** | Format-agnostic content matching over raw, unpacked, and deobfuscated buffers — catches patterns the format-specific engines miss |
| 10 | **Lua Scripts** | Lua 5.1 detection runtime executing rule sets through custom `mp.*` APIs — the most flexible detection layer in the engine |
| 11 | **Attribute Evaluation** | AAGGREGATOR boolean evaluation: combines all collected attributes via AND/OR/NOT logic trees to produce composite threat detections |
| 12 | **MAPS Cloud Lookup** | Cloud escalation to Microsoft MAPS for low-confidence local detections — includes FASTPATH quick-response and full sample submission |
| 13 | **Verdict Resolution** | Final stage: merges all detections, deduplicates, applies severity ranking, filters infrastructure markers, and returns the single highest-priority verdict |
