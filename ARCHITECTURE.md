# HexTrail architecture and next steps

## Current implementation

The first version is a native Python/Qt desktop application. Using Python gives the analysis layer direct access to binary tooling and keeps a future Ghidra adapter practical. The parser and data model are independent of Qt, so a Flutter desktop interface could consume the same analysis through a local process boundary later.

| File | Responsibility |
|---|---|
| `hextrail/engine.py` | ELF validation and metadata, symbols, ASCII strings, virtual-address mapping, call candidates, Capstone disassembly, basic-block graph |
| `hextrail/decompiler.py` | Provider-neutral, bounded JSON contract for out-of-process decompiler results |
| `hextrail/cache.py` | Canonical analysis identities, validated snapshots, atomic writes, eviction and cached-job orchestration |
| `hextrail/app.py` | Background inspection/decompilation, tables and navigation, graph canvas, pseudocode and hex display, annotation editing, JSON export |
| `hextrail/storage.py` | Atomic JSON annotation writes keyed by binary digest |
| `hextrail/samples/` | Benign compiled ARM64 libraries and their C source |
| `tests/` | Engine, persistence and offscreen Qt interaction checks |

The original binary is read into memory. All annotations live in a separate file. Analysis exports contain structured observations and explicit coverage limits. No model output is presented as a binary fact.

## Why this engine first

Capstone supplies instruction decoding, while pyelftools supplies the ELF structure. This is sufficient for a small working inspector with modest setup. It does not provide the function recovery, type propagation or decompiler pipeline expected from IDA Pro. Those are substantial independent analysis tasks.

Ghidra provides the optional deeper analysis path. HexTrail has a provider-neutral, validated result contract, a bounded headless Ghidra provider and a Qt pseudocode interface. Both sample acceptance tests pass with Ghidra 12.2 on macOS ARM64; opt-in checks are available in `tests/test_ghidra_integration.py`. Real-provider Qt navigation and cancellation were also checked offscreen. Other versions and platforms remain unverified.

## Decompiler integration phases

The detailed implementation plan and acceptance checklist live in
[DECOMPILER_PLAN.md](DECOMPILER_PLAN.md).

1. **Result contract — complete.** Validate bounded worker JSON containing the binary digest, provider identity and version, architecture, recovered function boundaries, signatures, pseudocode and warnings. Reject stale, malformed or oversized output before it reaches the UI.
2. **Ghidra headless provider — accepted with Ghidra 12.2 on macOS ARM64.** Discover a user-configured Ghidra installation, run it in a temporary project with timeouts and cancellation, and export the contract above. Import preserves the ELF image base to retain link-time addresses. Do not execute code from the inspected binary.
3. **Pseudocode interface — accepted with Ghidra 12.2 in offscreen Qt on macOS ARM64.** Explicit deep-analysis action, off-thread provider discovery and processing, analysis-stage feedback, cancellation/retry, read-only pseudocode, recovered-function filtering and exact function-entry navigation. Show provider/version provenance, signatures, boundary sources and warnings. Deterministic Qt tests exercise worker lifecycle and failure handling.
4. **Caching — implemented as parity milestone M1; broader hardening remains.** Match input/provider/configuration/code identity, validate reads, save atomically and evict bounded stored entries. Restore matching analysis on open; support rerun and removal. Stronger parser/process isolation and large-corpus evaluation remain later work.

### Pseudocode data flow and limits

The UI snapshots the current binary path/digest into a `DecompileWorker`. The
worker discovers Ghidra and calls the existing bounded process controller outside
the UI thread. Only validated results with the expected digest and AArch64
architecture are delivered to the UI. Qt signals update analysis-stage labels;
the progress indicator is indeterminate because the provider does not expose
percentage progress.

Recovered functions stay separate from ELF symbols in a searchable selector.
Selecting an ELF function matches pseudocode by exact entry address. Choosing a
recovered function uses the existing assembly address navigation, including executable-region
fallback for stripped code. Schema v1's size is a body byte count and cannot prove
a contiguous address range, so the UI does not use size-based containment to
associate pseudocode. Line mappings and complete function-body graphs need a
future report contract.

The original analysis session remains usable during deep analysis. Library
replacement is blocked until the worker finishes; close requests cancel and wait
asynchronously for worker cleanup. Failed/cancelled reruns preserve earlier
results for that binary. Successful library replacement clears them. Reports
are cached separately from annotations, but are not included in inspection JSON exports.

### Cache data flow

The worker discovers the configured provider without launching it, verifies the
input file digest and builds an immutable canonical identity from the provider's
analysis profile. `AnalysisCache` reads a bounded JSON envelope and validates its
identity, checksum, timestamp and existing report contract. A valid hit returns
the report without starting Ghidra. A cache-only restore miss never starts it.

Fresh runs and explicit reruns publish only complete validated reports using a
temporary file, file fsync and atomic replacement. Cache failures are reported
separately from provider failures: valid fresh analysis remains usable when disk
storage is unavailable. Eviction reserves space before replacement, preserving
an earlier entry if the replacement cannot be completed. Notes are never part of
cache files or cache removal.

The default budget is 512 MiB and 128 completed snapshots. Entry size is bounded
by the 32 MiB report limit plus bounded metadata. Successful reads update recency;
oldest managed entries are removed before a new entry is published. Budget
coordination across simultaneous application instances is best effort. Atomic
files protect readers from partial writes; this is not a general project database.

## Next milestones

1. **More complete analysis.** With M1 caching implemented, proceed to M2: extend the provider contract for function-body ranges, cross-references and types before integrating recovered functions into the main analysis model. Preserve address mapping and provenance. Expand validation to optimization-varied samples and other provider/platform versions.
2. **Robust local processing.** Move parsers into isolated worker processes with time and memory limits, cancellation and structured failures. Add project/report import, navigation history, bookmarks, search by address, and session recovery.
3. **Android workflow.** Add safe APK listing and bounded extraction, ABI selection, JNI export/registration mapping, and explicit separation of native ELF analysis from DEX analysis. Treat Flutter/Dart AOT semantics as a separate research feature.
4. **Optional local AI.** Add an explicitly configured Ollama or MLX endpoint. Supply only selected functions and relevant references; require address citations and distinguish observations from hypotheses. Keep tool execution and binary changes outside the model's direct control. No model is necessary for core analysis.
5. **Evaluation.** Use a corpus with source available. Measure address/target accuracy, recovered-function coverage, decompiler fidelity, unsupported cases, analyst navigation time and the factual accuracy of AI explanations. Stripped symbols and changed optimisation levels should be separate test conditions.
6. **Desktop distribution.** Validate on the user's Mac, package a native launcher, add CI for macOS/Windows/Linux, review dependency distribution requirements, and only then prepare a signed/notarised Mac build.

## AI features with a clear purpose

Useful early additions would be explaining a selected function, proposing descriptive names, comparing two versions of a function and helping a reader navigate related callers/callees. Every explanation should link to the evidence used. A general chat panel alone would add little to the existing inspector.

## Boundaries

The prototype does not claim parity with IDA Pro. Debugging, binary patching, automatic exploitation, deobfuscation, complete type recovery, source reconstruction and vulnerability verdicts are outside this first release. A useful next milestone is correct decompilation and cross-reference navigation for a small corpus of native Android libraries.

## Official technical references

- https://hex-rays.com/ida-pro
- https://www.capstone-engine.org/
- https://github.com/eliben/pyelftools
- https://doc.qt.io/qtforpython-6/
- https://github.com/NationalSecurityAgency/ghidra
