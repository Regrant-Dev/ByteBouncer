# Design: analyzing very large nested files

Status: implemented (2026-10-13) for SquashFS/AppImage, zip-based and
tar-based containers. Validated on the GitHub Copilot AppImage: the 1.4 GiB
`usr/bin/github` is extracted in about 4 s and analyzed. The whole scan takes
about 14 s.

## Problem

Tier 1 expands containers entirely in memory inside the sandboxed worker.
A nested file larger than `Limits::max_entry_bytes` (512 MiB) used to be cut
off, and the scan was marked incomplete. Raising the limit does not help: the
worker would hold the container, every expanded child, and analysis state at
once, and hit its 4 GiB address-space limit.

## How it works

1. **Detection (Tier 1).** While expanding a container, a regular file over
   `max_entry_bytes` is not read. The formats crate lists it in
   `Expanded::oversized`, and the analysis walk turns it into a
   `SpillRequest`: the chain of containers leading to it, its path, size, and
   display path. For zip, an entry is only spilled when its compression
   ratio is plausible. Implausible ratios keep the bomb-style truncation, and
   a test checks that a zip bomb is never spilled.

2. **Extraction worker (`crates/cli/src/spill.rs`).** For each request, the
   parent starts `__extract-worker`. It:
   1. reads the input snapshot,
   2. creates its single output file under `workspace/spill/`,
   3. confines itself with the Tier 1 allow-list (no network, no new file
      access, no exec, `RLIMIT_FSIZE` = size cap),
   4. streams the entry into the already-open file, hashing as it writes.

   Intermediate containers in the chain are expanded in memory within the
   default limits; the large file itself never is.
   `bytebouncer_formats::extract_entry` streams SquashFS block by block, and
   zip and tar entry by entry.

3. **Analysis.** Each extracted file becomes an ordinary input snapshot,
   with display path `outer!inner` and `parent` set to its container. It
   runs through Tier 1 in its own batch and can spill further files through
   the same queue. It is a deep-mode candidate like any other input, except
   that deep mode skips anything over 400 MiB with an explicit coverage
   note, because decompiling it would consume the budget without finishing.

4. **Bounds.** At most 16 files, 4 GiB per file and 8 GiB per scan
   (`SPILL_MAX_*` in `crates/cli/src/inspect.rs`). Exceeding them makes the
   scan `incomplete` with a message naming the file. Spill files live in the
   scan workspace and are removed with it.

## Related changes made at the same time

- **Code map prioritization:** named functions matching network, identifier,
  credential, telemetry or persistence keywords are disassembled first, using
  up to half the instruction budget; a linear sweep covers the rest.
  Limitation: in async Rust (e.g. Copilot), URLs and send calls sit more than
  four direct calls apart, so static pairing still misses them. The model's
  code tools cover that ground.
- **Report layout:** with `--model`, the AI investigation comes first in the
  Markdown and HTML reports, labelled as unverified narrative, followed by
  the verified findings.
- **Duplicate AI claims:** a model claim that restates an existing finding is
  kept as that finding's explanation instead of a rejected hypothesis.
- **Memory:** UTF-16 URL extraction works in fixed windows, so very large
  inputs no longer need about 4× their size in memory.

## Not yet covered

- Streaming extraction for other containers (RPM payloads, DEB data
  archives, CAB, MSI streams, compressed single streams). These still report
  "too large" as a limitation.
- Formats where the container itself does not fit in memory (inputs over
  about 2 GiB).
