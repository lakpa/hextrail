# Ghidra decompiler integration plan

## Objective

Add optional C-like pseudocode and recovered function metadata to HexTrail by
running a user-installed Ghidra instance as a separate, local process. Preserve
the current Capstone and pyelftools workflow as the fast built-in analysis path.

The integration must never execute code from the inspected binary. Every result
must identify its source, provider version and exact input binary digest.

## Success criteria

The first complete release should let a user:

1. Open a supported ARM64 ELF binary with the existing analyzer.
2. Request deeper analysis explicitly.
3. See progress and cancel the operation.
4. View Ghidra-produced pseudocode for the selected function.
5. Navigate between pseudocode and disassembly by virtual address.
6. Distinguish ELF facts, Capstone output and Ghidra analysis.
7. Reuse a valid cached result for the same binary and provider version.
8. Receive a clear error when Ghidra is absent, incompatible or fails.

The included source-backed and stripped sample libraries are the initial
acceptance fixtures.

## Non-goals for the first release

- Building a decompiler inside HexTrail
- Bundling or redistributing Ghidra
- Debugging or executing the inspected program
- Editing or recompiling pseudocode
- Applying binary patches
- APK, DEX, Java, Kotlin or Dart decompilation
- Automatic vulnerability verdicts
- Running arbitrary user-provided Ghidra scripts
- Claiming that pseudocode is recovered original source

## Proposed architecture

```text
HexTrail Qt UI
    |
    | explicit deep-analysis request
    v
Python provider/controller
    |
    | bounded subprocess + temporary project
    v
Ghidra analyzeHeadless + HexTrail-owned export script
    |
    | hextrail.decompilation.v1 JSON
    v
Validated immutable result model
    |
    +--> pseudocode view
    +--> recovered function metadata
    +--> digest/version keyed cache
```

The UI must not parse raw Ghidra output. The provider writes a JSON report, and
`hextrail/decompiler.py` validates that report before any result reaches the UI.

## Phase 1 — Result contract

Status: **complete**

Deliverables:

- Provider-neutral `Decompiler` protocol
- Immutable report and decompiled-function models
- `hextrail.decompilation.v1` JSON contract
- Binary SHA-256 identity check
- Provider name, version and architecture provenance
- Function address, size, name, signature, pseudocode and boundary source
- Bounded file, function count and pseudocode sizes
- Rejection of malformed, stale and duplicate results
- Unit tests independent of a Ghidra installation

Exit criteria:

- Valid reports round-trip through the model.
- Reports for another binary are rejected.
- Oversized or malformed provider output fails safely.
- Existing Capstone and UI tests continue to pass.

## Phase 2 — Ghidra headless provider

Status: **implementation complete; real-Ghidra acceptance pending**

The provider, exporter and deterministic fake-process tests are implemented.
This development environment does not currently have Ghidra configured, so the
two fixture-based exit criteria remain open until a real installation is used.

### 2.1 Installation discovery

- Accept an explicit Ghidra directory in application settings.
- Support `GHIDRA_HOME` as a secondary configuration source.
- Optionally discover `analyzeHeadless` on `PATH`.
- Validate the executable and obtain the Ghidra version before analysis.
- Never download or install Ghidra automatically.

### 2.2 Export script

- Add a HexTrail-owned Ghidra post-analysis script.
- Enumerate analyzed functions in deterministic address order.
- Export entry address, body size, name and boundary source.
- Decompile each eligible function with a per-function timeout.
- Export the recovered signature and C-like pseudocode.
- Record per-function failures as warnings instead of discarding the report.
- Write JSON atomically to a path supplied by the controller.
- Avoid loading scripts from the inspected binary's directory.

### 2.3 Process controller

- Create a unique temporary Ghidra project for each uncached run.
- Construct subprocess arguments as a list without a shell.
- Capture bounded stdout and stderr for diagnostics.
- Apply a whole-analysis timeout.
- Support cancellation and terminate the child process tree.
- Delete the temporary project after success, failure or cancellation.
- Convert exit codes and missing output into structured `DecompilerError`s.
- Verify the report digest before returning results.

### 2.4 Tests

- Test discovery with temporary fake installations.
- Test command construction without launching Ghidra.
- Use a fake headless executable for success, failure, timeout and cancellation.
- Test output truncation and missing-report behavior.
- Keep real Ghidra tests optional and separately marked.

Phase 2 exit criteria:

- A configured Ghidra installation can analyze the included sample from Python.
- The stripped fixture contains recovered functions absent from its ELF symbols.
- Cancellation and timeouts leave no active worker or temporary project.
- Failures do not affect the existing Capstone analysis session.

## Phase 3 — Pseudocode interface

Status: **planned**

Deliverables:

- Add an explicit **Run deep analysis** action.
- Run the provider outside the Qt UI thread.
- Show preparing, analyzing, importing and completed states.
- Add a read-only **Pseudocode** tab.
- Synchronize the selected function by link-time virtual address.
- Show signature, provider, version and boundary provenance.
- Display analysis warnings without presenting them as binary facts.
- Preserve existing behavior when no provider is configured.
- Allow retry after failure and cancellation.

Phase 3 exit criteria:

- The application remains responsive throughout analysis.
- Selecting a known function shows the corresponding pseudocode.
- Switching between pseudocode and disassembly preserves the function context.
- Missing pseudocode has a clear explanation rather than an empty view.
- UI tests cover success, failure, cancellation and provider absence.

## Phase 4 — Cache and hardening

Status: **planned**

### Cache

- Key entries by binary SHA-256, provider name, provider version, language and
  HexTrail report-schema version.
- Store reports separately from annotations and original binaries.
- Write atomically and validate every cache read.
- Provide cache inspection and removal controls.
- Never silently reuse results from a different provider version.

### Isolation and limits

- Set conservative whole-run and per-function timeouts.
- Bound report size, logs, temporary disk usage and imported function count.
- Restrict project and output paths to HexTrail-created directories.
- Document that Ghidra processes untrusted binary input and is not a hardened
  sandbox.
- Investigate stronger OS-specific process isolation as a later enhancement.

### Evaluation

- Compare recovered names, boundaries and call relationships with known source.
- Test source-backed, stripped and optimization-varied fixture builds.
- Record unsupported binaries and per-function decompilation failures.
- Verify that displayed addresses map back to the original ELF correctly.
- Measure cold analysis time and cached-result load time.

Phase 4 exit criteria:

- Cache behavior is deterministic and covered by corruption tests.
- Resource and failure limits are documented and enforced.
- Evaluation results and known limitations are published in the repository.

## Future phases

After the initial integration is stable, consider:

- Cross-reference import and callers/callees navigation
- Ghidra-recovered local variables, structures and data types
- Whole-program call graphs
- Side-by-side binary and function comparison
- User-controlled provider profiles and analysis options
- A documented plugin API for additional decompiler providers

These should extend the provider contract through a new schema version instead
of changing the meaning of existing fields.

## Testing strategy

The default test suite must not require Ghidra. It should use unit tests and fake
processes for deterministic behavior. Real Ghidra integration tests should run
only when explicitly enabled and should record the tested Ghidra version.

Required test groups:

- Contract validation and bounds
- Installation discovery
- Command construction and path handling
- Process success, nonzero exit, malformed output and missing output
- Timeout and cancellation cleanup
- Digest and provider-version mismatches
- Cache hit, miss, invalidation and corruption
- Qt responsiveness and pseudocode synchronization
- Source-backed and stripped fixture acceptance

## Security and trust boundaries

- Treat binaries, filenames, symbols, pseudocode and Ghidra logs as untrusted.
- Pass subprocess arguments without shell interpretation.
- Never execute the analyzed file.
- Never treat recovered pseudocode as original source or ground truth.
- Keep annotations and cached analysis outside the binary.
- Escape untrusted text in rich UI widgets and exported reports.
- Preserve provider provenance wherever derived information is displayed.

## Decisions to revisit after Phase 2

- Minimum supported Ghidra version
- Default whole-run and per-function timeouts
- Whether cross-references belong in schema v1 or a future schema
- Cache location and retention policy
- Whether macOS, Linux and Windows need different cancellation strategies
- Whether recovered functions should augment or remain separate from ELF symbols

## Release checklist

- [x] Provider-neutral report contract
- [x] Contract validation and unit tests
- [x] Ghidra discovery and version reporting
- [x] Headless export script
- [x] Bounded process controller
- [x] Timeout and cancellation cleanup
- [ ] Source-backed sample acceptance
- [ ] Stripped sample acceptance
- [ ] Pseudocode UI
- [ ] Provenance and warning display
- [ ] Versioned cache
- [ ] Cross-platform verification
- [ ] User documentation

