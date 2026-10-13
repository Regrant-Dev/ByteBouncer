# Large files inside archives

Status: done for SquashFS/AppImage, zip and tar (October 2026).

## The problem

Quick mode unpacks archives in memory inside a locked-down worker. Anything
bigger than 512 MiB used to be cut off, and the scan was marked incomplete.
The GitHub Copilot AppImage hit this: its main program, `usr/bin/github`, is
1.4 GiB, so the most important file in the package was never checked. Raising
the limit wasn't an option, because the worker would need the whole archive,
everything in it, and the analysis in memory at once.

## What happens now

1. When unpacking finds a file over the limit, it doesn't read it. It notes
   the file's path, its size, and which archives it sits inside. Zip entries
   are only treated this way when their compression ratio is believable.
   Zip bombs are still cut off as before, and a test makes sure of it.
2. A separate worker (`crates/cli/src/spill.rs`) extracts that one file. It
   reads the input, opens its single output file, then locks itself down the
   same way the quick-mode worker does: no network, no new files, no
   starting programs, and a cap on how much it can write. It streams the
   file out block by block and hashes it on the way. The big file never has
   to fit in memory.
3. The extracted file is scanned like any other input and shows up in the
   report under its archive path (`outer!inner`). It can contain more large
   files, which go through the same steps. Deep mode skips anything over
   400 MiB, since Ghidra wouldn't finish in time, and the report says so.
4. Limits: 16 files, 4 GiB each, 8 GiB per scan (`SPILL_MAX_*` in
   `crates/cli/src/inspect.rs`). Going over makes the scan incomplete, with
   the file named. Extracted files are deleted with the rest of the scan
   workspace.

On the Copilot AppImage the 1.4 GiB program is extracted in about 4 seconds
and the whole scan takes about 14.

## Done at the same time

- The code map disassembles functions with telling names first (network,
  identifiers, credentials, telemetry, persistence), using up to half its
  budget, then sweeps the rest. This doesn't help much with async Rust like
  Copilot: the URLs and the network calls end up too many calls apart to
  pair statically. A model investigating with the code tools can still
  follow them.
- With `--model`, the model's write-up now comes first in the report, marked
  as unverified, with the checked findings below it.
- When the model repeats something ByteBouncer already found, its
  explanation is attached to that finding instead of being filed as a
  rejected claim.
- Pulling UTF-16 URLs out of a file now works in fixed-size chunks, so huge
  inputs no longer need four times their size in memory.

## Still to do

- Streaming extraction for RPM and DEB payloads, CAB, MSI streams and plain
  compressed files. These still report "too large".
- Inputs that are themselves too big to read into memory (over about 2 GiB).
