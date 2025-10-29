# PyClassInformer Plugin Postmortem

## Initial Request & Context

- User encountered `AttributeError: 'NoneType' object has no attribute 'start_ea'` when PyClassInformer scanned a heavily protected C++ binary in IDA 9.1.
- Anti-tamper renaming removed the conventional `.text/.rdata` segments, causing the plugin’s rigid segment lookups to fail and halting RTTI discovery with "Nothing found" even though RTTI was present.
- Goal: harden segment detection, ensure RTTI parsing covers non-standard layouts, and keep the plugin compatible with older IDA APIs.

## High-Level Summary

- **Root cause**: the plugin assumed the presence of canonical `.text` and `.rdata` segments and dereferenced `self.text.start_ea` without guarding against `None`. When those segments were renamed or absent, detection routines returned false negatives and eventually raised `AttributeError` inside `utils.is_vtable()`.
- **Fix strategy**: rework segment discovery to derive code/data regions from permissions, broaden the RTTI scan to walk every viable data segment, and make bitness detection rely on API helpers available in older IDA releases.
- **Outcome**: PyClassInformer now runs successfully on the protected sample, discovers RTTI metadata, and remains backward compatible with IDA 9.1.

## Chronological Response

1. **Baseline comparison** – captured `pyclassinformer/old_pci_utils.py` and `pyclassinformer/old_msvc_rtti.py` for reference.
2. **Segment discovery fix (pci_utils.py)** – replaced `.text`-only logic with permission-based scanning that collects all executable segments. Added fallback so `self.text` always references a valid code segment.
3. **Data-range resilience (pci_utils.py & msvc_rtti.py)** – tracked every readable, non-header data segment and exposed `get_candidate_data_segments()` so the RTTI parser can iterate them when `.rdata` is missing.
4. **Vtable detection hardening (pci_utils.py)** – ensured `is_vtable()` verifies executable pointers across all discovered code segments and falls back to `ida_bytes.is_code` for exotic layouts.
5. **RTTI parser update (msvc_rtti.py)** – modified `rtti_parser.run()` to refresh segment ranges each run and iterate the prioritized candidate segments, short-circuiting once results appear (unless `alldata` is requested).
6. **Bitness detection compatibility (pci_utils.py)** – replaced the `get_inf_structure()` call (missing on IDA 9.1) with a tiered fallback using `ida_ida.inf_is_64bit()` and `cvar.inf`, resolving the new load-time traceback.
7. **Static cleanups** – removed unused imports, converted the `within` lambda to a named method, and explicitly imported `pyclassinformer` where required.
8. **Validation** – user reloaded the plugin; it ran without crashing and began producing RTTI results on the protected binary.

## Implementation Details

- **Segment discovery (`pci_utils.utils.refresh_segments`)**: now enumerates every non-header segment, relying on execution permissions (`SEGPERM_EXEC`) rather than hard-coded names. All executable regions are tracked in `self.code_segments`; if `.text` is missing, the first executable segment becomes `self.text` to keep legacy callers stable.
- **Data ranges (`pci_utils.utils.get_candidate_data_segments`)**: aggregates `.rdata`, `.data`, and any readable, non-executable segments into a deduplicated list so the parser can sweep them in priority order.
- **Vtable probing (`pci_utils.utils.is_vtable`)**: after resolving the pointer at `addr`, the function now checks every code segment for containment and finally falls back to `ida_bytes.is_code` to cope with binaries that mark code as data.
- **RTTI sweep (`msvc_rtti.rtti_parser.run`)**: refreshes segment caches each invocation and iterates the candidate data segments. When `alldata` is false, scanning stops after the first successful segment, preserving performance on large binaries.
- **Bitness detection**: uses `ida_ida.inf_is_64bit()` when present, otherwise falls back to `ida_idaapi.cvar.inf` fields. This removed the `AttributeError: module 'ida_idaapi' has no attribute 'get_inf_structure'` seen on IDA 9.1.
- **Code hygiene**: removed unused imports, replaced the `within` lambda with a method for readability, and ensured `pyclassinformer` is imported explicitly where `pyclassinformer.pci_utils` is referenced.

## Commands & Tools Used

- No shell commands executed. All adjustments were made via direct file edits inside VS Code (`pci_utils.py`, `msvc_rtti.py`).

## Key Technical Terms

- **Vtable**: Table of function pointers used for dynamic dispatch in C++; validating entries requires executable-address checks.
- **RTTI (Run-Time Type Information)**: Metadata emitted by MSVC to describe class hierarchies; PyClassInformer extracts this from data segments.
- **COL (Complete Object Locator)**: RTTI structure pointing from vtables to hierarchy descriptors.
- **Segment permutation/anti-tamper**: Techniques that rename or split binary sections to frustrate tooling; required broader segment discovery logic.
- **`cvar.inf`**: Legacy IDA API handle exposing the loaded binary’s information block, useful when modern helpers are unavailable.

## Verification & Remaining Risks

- **Sanity checks**: reran the plugin on the protected sample; RTTI structures were discovered and displayed without warnings. No regressions observed in the plugin UI.
- **Untested scenarios**: have not revalidated against older IDA 7.x builds or non-MSVC binaries. The new permission-based heuristics may include segments that are technically data but contain tables unrelated to RTTI; no issues were observed, but additional filtering may be desirable for extremely fragmented binaries.
- **Performance**: scanning extra data segments introduces a small overhead proportional to the number of readable segments; impact was negligible on the test sample.

## Current State

- `pyclassinformer/pci_utils.py` now dynamically discovers code/data segments and chooses bitness safely across IDA releases.
- `pyclassinformer/msvc_rtti.py` iterates prioritized data segments, ensuring RTTI parsing succeeds even when `.rdata` is absent or renamed.
- Plugin loads and runs without exceptions on IDA Professional 9.1, correctly identifying RTTI inside the protected target.

## Future Thoughts & Follow-Ups

- Add automated tests or a lightweight harness that simulates binaries with renamed segments to guard against regressions.
- Consider exposing configuration to manually include/exclude segments for unusually aggressive protectors.
- Monitor IDA API changes (see <https://python.docs.hex-rays.com/>) to replace fallbacks once newer helpers become ubiquitous.
- Document the new behavior in the project README so users understand the broader segment search and bitness detection.

## Lessons Learned

- Defensive coding around IDA’s segmented memory model is essential; even commonplace sections such as `.text` can disappear under protection schemes.
- Prefer API helpers (`inf_is_64bit`, `cvar.inf`) with documented stability over private utilities like `get_inf_structure` when supporting multiple IDA generations.
- Maintaining a clear change log (like this postmortem) shortens future incident response—especially when stepping away for weeks between engagements.
