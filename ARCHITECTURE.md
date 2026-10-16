# HexTrail architecture and next steps

## Current implementation

The first version is a native Python/Qt desktop application. Using Python gives the analysis layer direct access to binary tooling and keeps a future Ghidra adapter practical. The parser and data model are independent of Qt, so a Flutter desktop interface could consume the same analysis through a local process boundary later.

| File | Responsibility |
|---|---|
| `hextrail/engine.py` | ELF validation and metadata, symbols, ASCII strings, virtual-address mapping, call candidates, Capstone disassembly, basic-block graph |
| `hextrail/decompiler.py` | Provider-neutral, bounded JSON contract for out-of-process decompiler results |
| `hextrail/app.py` | Background analysis, tables and navigation, graph canvas, hex display, annotation editing, JSON export |
| `hextrail/storage.py` | Atomic JSON annotation writes keyed by binary digest |
| `hextrail/samples/` | Benign compiled ARM64 libraries and their C source |
| `tests/` | Engine, persistence and offscreen Qt interaction checks |

The original binary is read into memory. All annotations live in a separate file. Analysis exports contain structured observations and explicit coverage limits. No model output is presented as a binary fact.

## Why this engine first

Capstone supplies instruction decoding, while pyelftools supplies the ELF structure. This is sufficient for a small working inspector with modest setup. It does not provide the function recovery, type propagation or decompiler pipeline expected from IDA Pro. Those are substantial independent analysis tasks.

Ghidra is the proposed next analysis engine because it already provides disassembly, decompilation, scripting and automated workflows. HexTrail now has a provider-neutral, validated result contract and a bounded headless Ghidra provider. The pseudocode UI and acceptance checks against a real Ghidra installation remain separate phases.

## Decompiler integration phases

The detailed implementation plan and acceptance checklist live in
[DECOMPILER_PLAN.md](DECOMPILER_PLAN.md).

1. **Result contract — complete.** Validate bounded worker JSON containing the binary digest, provider identity and version, architecture, recovered function boundaries, signatures, pseudocode and warnings. Reject stale, malformed or oversized output before it reaches the UI.
2. **Ghidra headless provider — implemented; real-Ghidra acceptance pending.** Discover a user-configured Ghidra installation, run it in a temporary project with timeouts and cancellation, and export the contract above. Do not execute code from the inspected binary.
3. **Pseudocode interface.** Add an explicitly labelled pseudocode view synchronized by function address with disassembly. Show provider/version provenance and analysis warnings.
4. **Caching and hardening.** Cache by binary digest plus provider/version, isolate the worker, bound resources, preserve structured failures and validate against source-backed and stripped fixtures.

## Next milestones

1. **More complete analysis.** Add a Ghidra headless worker behind the existing data model. Return recovered functions, cross-references, types and decompiled C-like text with their source and analysis version. Preserve address mapping and provenance. Validate on compiled samples with known source and on stripped versions of the same files.
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
