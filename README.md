# HexTrail 0.1

A working local desktop prototype for inspecting **Android ARM64 native `.so` libraries**. It takes inspiration from the workflow of a binary-analysis workbench: functions on the left, disassembly and graphs in the centre, evidence and annotations on the right.

The current engine uses **pyelftools + Capstone**, with a **PySide6/Qt** desktop interface. It performs real static analysis of the file you open. It does not require a model, API key, GPU, server or cloud account.

## Start on your Mac

You need **Python 3.10 or newer**. Clone the `main` branch and start the app:

```bash
git clone --branch main --single-branch https://github.com/lakpa/hextrail.git
cd hextrail
bash run.sh
```

Alternatively, download the repository ZIP from GitHub, extract it, open Terminal
in the extracted directory, and run:

```bash
bash run.sh
```

The first run creates a project-local `.venv` and downloads the pinned
dependencies. Subsequent launches use the installed dependencies. Close the
window to exit.

The included, compiled ARM64 demonstration library opens automatically. This is a source prototype, not a signed or notarised `.app` bundle. The desktop UI and analysis pipeline have been checked with Qt's offscreen renderer on macOS ARM64, including real Ghidra 12.2 decompilation. Native macOS packaging and a hands-on interactive Mac check remain to be done.

To open one of your own libraries at launch:

```bash
bash run.sh /absolute/path/to/libexample.so
```

Or use **Open .so**, the File menu, or drag a local file onto the window. For an APK, unzip it first and choose a `.so` from `lib/arm64-v8a/`. This version does not parse APK containers, DEX bytecode or Java/Kotlin source.

### Manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m hextrail
```

On Windows, use `py -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt` and `.venv\Scripts\python -m hextrail`. Windows-specific UI behaviour has not been tested.

## What works

| Feature | Behaviour |
|---|---|
| ELF inspection | SHA-256, architecture, sections, sizes, virtual addresses and file offsets |
| Function navigation | ELF function symbols, aliases and separate executable-section regions |
| Disassembly | Real AArch64 instructions decoded by Capstone, paged in 4 KiB chunks |
| Control-flow graph | Basic blocks and direct branch/fallthrough edges for the current page |
| Direct-call references | Incoming/outgoing BL candidates with clickable addresses |
| Strings | Search printable ASCII strings; double-click to inspect underlying bytes |
| Imports | Search undefined dynamic symbols, including Android API imports |
| Hex view | Inspect bytes using an explicitly labelled address or file-offset basis |
| Notes and aliases | Automatic local saving, scoped to the exact binary's SHA-256 |
| Optional deep analysis | User-installed Ghidra runs locally in the background, with cancellation and retry |
| Pseudocode | Read-only C-like output, searchable recovered functions, function-address navigation and provider warnings |
| JSON export | Metadata, functions, strings, call candidates, annotations and coverage notes |
| Copy AI context | Copies a grounded prompt plus the selected disassembly page to the clipboard |

**Copy AI context does not call an LLM.** No AI provider is connected and the application contains no network client. You can choose where to paste the context yourself.

## Try the demo

1. Select `calculate_total`. It computes a quantity/price total and applies a member discount.
2. Double-click its `bl` instruction to navigate to `validate_quantity`.
3. Return to `calculate_total` using the function list, then open **Control flow**. Green edges are taken conditional branches; blue edges are fallthroughs or jumps. Drag to pan, use Ctrl + wheel to zoom, and double-click a block to return to its instructions.
4. Select `checksum_bytes` to see a small loop.
5. In **Strings**, search `ready for inspection`. Double-click the result to open its bytes in **Hex**.
6. In **Imports**, find `__android_log_write`.
7. Add an alias and note. Close and reopen the same binary to confirm they persist.
8. Open `hextrail/samples/libnative_demo_stripped.so`. The local `validate_quantity` symbol is gone, while exported dynamic symbols remain. The app reports the reduced coverage.

These demos are small, benign analysis fixtures. The original C source is included. The logging import is deliberately unresolved in the freestanding build; the sample is provided for static inspection, not installation as an Android application.

## Optional Ghidra pseudocode

The built-in inspector works without Ghidra. For deeper analysis:

1. Install [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and the JDK required by that release, following its installation instructions. HexTrail does not download or bundle either.
2. Open a supported library and select **Pseudocode**.
3. Use **Browse…** to choose the extracted Ghidra installation directory. Alternatively, set `GHIDRA_HOME` before launching HexTrail or put `analyzeHeadless` on `PATH`. The directory selected in the UI applies to the current session.
4. Click **Run deep analysis** (also available in the **Analysis** menu). The UI shows analysis stages and remains available for navigation. **Cancel** stops the worker; failures and cancellations can be retried.
5. Selecting an ELF function displays pseudocode when its entry address matches a Ghidra function. Search by name or address in the **Recovered functions** selector to inspect entries missing from ELF symbols, then choose a result. **Show function in disassembly** navigates to its entry address.

The view identifies the provider/version, signature and boundary source, and displays provider warnings as plain text. Empty pseudocode is explained explicitly. Navigation operates at function-entry level; schema v1 does not provide pseudocode-line mappings or discontiguous function-body ranges. Recovered functions remain in their own selector rather than replacing ELF symbols. On stripped binaries the assembly inspector may therefore show the containing executable section, and annotations continue to use that inspector's selected entry.

Opening another library requires finishing or cancelling deep analysis. Closing the window cancels active deep analysis before closing. A failed or cancelled rerun retains earlier results for the same binary; opening another binary clears them. Decompiler results are currently held in memory and are not included in JSON exports or saved across launches; versioned caching is the next phase.

**Verified with Ghidra 12.2 on macOS ARM64:** both sample libraries produce pseudocode at their original ELF addresses, including the stripped local function. The real provider was also exercised through the offscreen Qt interface for pseudocode/assembly navigation and cancellation. Other Ghidra versions and operating systems still need acceptance checks.

### Configured local checkout

This development checkout has Ghidra 12.2, Temurin JDK 25.0.5 for ARM64 and a native Python environment under the Git-ignored `.tools/` directory. The Ghidra and JDK archives were verified against their published SHA-256 checksums. Installation metadata is in `.tools/installation.json`.

`bash run.sh` loads `.tools/activate.sh` when present and uses `.tools/python` when available. The activation file sets the local Ghidra/JDK paths and keeps Ghidra settings and caches inside `.tools/`. Edit that file to change this checkout's installation. These files are local to this checkout and are not included when cloning the repository.

Ghidra 12.2 requires JDK 25 and a native-component build on macOS; see the [release installation instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md#building-native-components). After setting up the tools and sourcing the activation file, the native build can be repeated with:

```bash
source .tools/activate.sh
GRADLE_USER_HOME="$PWD/.tools/gradle-cache" "$GHIDRA_HOME/support/gradle/gradlew" \
  -p "$GHIDRA_HOME/support/gradle" --no-daemon buildNatives
```

## Interpretation and limits

- Inputs must be little-endian **ELF64 / AArch64** linked libraries or executables with section headers, up to **128 MiB**. The first version rejects 32-bit ARM, x86, PE, Mach-O, relocatable object files, compressed sections and sectionless binaries.
- AArch64 ELF does not itself establish Android compatibility. The loader accepts other AArch64 ELF libraries too.
- Built-in function names and boundaries come from symbol tables. Zero-sized symbol extents are estimated and labelled. Built-in inspection of a stripped library can expose only its exported functions; an unnamed executable region is **not** a recovered function. Optional Ghidra results are displayed separately.
- Addresses are **link-time virtual addresses**, not file offsets or runtime ASLR addresses. Android's runtime load base is not applied.
- The direct-call index scans aligned `BL` encodings in at most **8 MiB** of executable bytes. Embedded data can create false candidates. Indirect calls, tail calls and final PLT/import targets are not resolved. The Details tab and JSON export expose coverage.
- Each disassembly/graph page contains at most **4 KiB**. A page boundary can cut across a function or basic block. Only edges with targets on the current page appear in the graph.
- Strings are ASCII only, capped at **12,000** entries and **512** displayed characters per string. The symbol-table limit is 100,000 entries.
- Built-in inspection does not decompile; optional Ghidra analysis produces interpreted C-like pseudocode. This is not a debugger and cannot recover original C/C++, Java, Kotlin or Dart source, handle Dart AOT snapshots semantically, analyse obfuscation reliably, or determine that a call is a vulnerability.
- Qt displays and parses files locally. This prototype does not execute or patch the inspected binary. Built-in parsing runs in a background thread; Ghidra runs in a separate process. Neither is a hardened sandbox.

## Saved work

Notes are stored separately at:

```text
~/.hextrail/projects/<binary-sha256>.json
```

This keeps annotations separate from the original library and reuses them when the exact same bytes are opened under another filename. A rebuilt binary with a different digest gets a separate set of notes. Use **Export JSON** to create a portable analysis report with your annotations. JSON report import is not implemented yet.

Existing HexTrail annotations in `~/.hextrail/projects/` are read automatically when no HexTrail annotation file exists for that binary. New saves go to `~/.hextrail/projects/`; the earlier notes are retained. The older `HEXTRAIL_DATA_DIR` environment variable also remains supported as a fallback.

For an alternative data location:

```bash
HEXTRAIL_DATA_DIR=/path/to/your/notes bash run.sh
```

## Command-line use

```bash
python -m hextrail path/to/libexample.so --json > analysis.json
```

The CLI loads the same parser, has the same limits, and prints an actionable error on unsupported or malformed input. UI annotations are added by the desktop export, not by this raw CLI report.

## Development and verification

```bash
python -m pip install pytest
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

The default suite covers compiled-binary metadata, virtual-address mapping, a real call target, conditional/loop graph edges, stripped and untyped symbols, malformed/truncated inputs, size limits, cancellation, note persistence, validated decompiler-result imports, bounded Ghidra process control, Qt navigation/filtering, clipboard context, export and background loading. Pseudocode UI tests also cover responsiveness, provider absence, retry, function-address synchronization, stripped-function navigation, report identity/architecture mismatches, retained results after failure, clearing results on library changes and safe closing during analysis.

**Verified: 48 passed, no skips**, including the two real-Ghidra tests, on macOS ARM64 with Python 3.12, Temurin JDK 25.0.5 and Ghidra 12.2. The UI was visually checked with synthetic provider output at 1440×920 and 1050×700 and with real stripped-binary pseudocode at 1440×920. The default suite still skips the real-Ghidra checks unless explicitly enabled.

To run the two real-Ghidra acceptance checks explicitly:

```bash
GHIDRA_HOME=/absolute/path/to/ghidra HEXTRAIL_TEST_GHIDRA=1 python -m pytest -q -m integration
```

In this configured checkout, run the complete suite with real Ghidra enabled:

```bash
source .tools/activate.sh
HEXTRAIL_TEST_GHIDRA=1 .tools/python/bin/python -m pytest -q
```

These tests use both supplied samples, check pseudocode at known function entries (including the stripped local function), verify provider identity/version and check temporary-project cleanup. They are skipped in the default suite and do not install Ghidra. Passing them checks the sample workflow, not general decompilation fidelity.

Tests that check exact demo addresses use the included fixture, whose original compiler invocation is documented in `samples/README.md`. Rebuilding with a different compiler may change those addresses.

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the extension plan and the path to a Ghidra-backed decompiler.
The phased implementation and acceptance checklist are in [DECOMPILER_PLAN.md](DECOMPILER_PLAN.md).

## License

HexTrail is available under the [MIT License](LICENSE).

## Primary references

- [IDA Pro capabilities](https://hex-rays.com/ida-pro)
- [Capstone disassembly framework](https://www.capstone-engine.org/)
- [pyelftools](https://github.com/eliben/pyelftools)
- [Qt for Python](https://doc.qt.io/qtforpython-6/)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

Dependencies are installed separately and retain their own licences. This package contains the prototype source, tests and original demonstration fixtures; it does not bundle IDA, Ghidra, Qt, Capstone or an AI model.
