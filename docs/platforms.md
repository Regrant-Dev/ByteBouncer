# Platforms and sandboxing

ByteBouncer doesn't use virtual machines. On each operating system it locks its
workers down with whatever the kernel lets an ordinary (non-root) program use.
This page explains each restriction name you'll see in `bytebouncer doctor` and
in reports (`isolation.active` / `isolation.missing`), which systems have been
tested, and what isn't covered.

If a restriction shows up as missing, isolation is reduced. Quick mode and deep
mode then refuse to run unless you pass `--allow-reduced-isolation`, and the
report notes it.

## Summary

| Host | Tier 1 worker (quick mode) | Fetch worker | Tier 2 tools (deep mode) | Qualification job |
|---|---|---|---|---|
| Linux x86_64 / aarch64 | rlimits, user+network namespace, Landlock, seccomp allow-list | Landlock TCP ports 80/443 | same mechanisms, seccomp deny-list | `ubuntu-latest` (x86_64, glibc and musl); aarch64 at release |
| macOS (Apple Silicon, Intel) | rlimits, Seatbelt (`sandbox_init`) | Seatbelt remote ports 80/443 | `sandbox-exec` with a generated Seatbelt profile | `macos-latest` (arm64); x86_64 under Rosetta at release |
| Windows x86_64 | AppContainer (no capabilities) + Job Object | AppContainer `internetClient` + Job Object; **no port filtering** | AppContainer + Job Object | `windows-latest` |

A system counts as tested when its CI job runs the sandbox tests and
`bytebouncer doctor`, and every Tier 1 restriction is active and every escape
attempt is blocked. Each test also checks that the same action works when it's
allowed, so a broken test environment can't pass by accident.

## Linux

| Name | Mechanism |
|---|---|
| `rlimits` | `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, no core dumps |
| `netns` | new user namespace + empty network namespace (no interfaces) |
| `landlock_fs` | Landlock: only the profile's paths are readable/writable/executable |
| `landlock_net` | Landlock ABI ≥ 4: TCP bind/connect denied (fetch: connect to 80/443 only) |
| `landlock_scope` | Landlock ABI ≥ 6: no abstract-socket or signal access outside (bonus, not required) |
| `seccomp` | Tier 1 syscall allow-list (no `execve`, no sockets) |
| `seccomp_denylist` | Tier 2/fetch: denies ptrace, mounts, namespaces, modules, bpf, io_uring, … |

Tier 1 requires `rlimits, netns, landlock_fs, landlock_net, seccomp`.
Landlock needs Linux ≥ 6.7 for `landlock_net`.

### Ubuntu 24.04 and user namespaces

Ubuntu 23.10+ sets `kernel.apparmor_restrict_unprivileged_userns=1`: an
unprivileged process can create a user namespace but gets no capabilities in
it, so the empty network namespace cannot be set up and `netns` is reported
missing (Landlock still denies TCP). CI records `doctor` with the stock
setting for information, then runs
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` and requires
the full set. On an Ubuntu desktop you can do the same, or add an AppArmor
profile granting `userns` to the `bytebouncer` binary, or accept the reduced
isolation explicitly with `--allow-reduced-isolation`.

### musl

Release binaries for Linux are static musl builds. musl's `open()` uses the
legacy `open` syscall on x86_64, so the Tier 1 seccomp filter treats it like
`openat` (fails with `EACCES`). CI qualifies the musl build separately.

## macOS

| Name | Mechanism |
|---|---|
| `rlimits` | `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, no core dumps |
| `seatbelt_fs` | Seatbelt `(deny default)`; only the profile's paths are allowed (`subpath`) |
| `seatbelt_net` | no network operations at all, or (fetch) `network-outbound` to remote TCP ports 80/443 plus the system DNS resolver (mDNSResponder) |
| `seatbelt_exec` | Tier 1/fetch: `process-fork` and `process-exec` denied. Tier 2: exec only from the profile's executable paths |

Tier 1 requires `rlimits, seatbelt_fs, seatbelt_net, seatbelt_exec`.

- **In-process confinement** uses `sandbox_init(profile, 0, …)` with an SBPL
  profile generated from the `Profile`. The API is deprecated since macOS 10.8
  but remains supported and is what major browsers' helper processes use. The
  Tier 1 profile allows nothing except a few CPU-count `sysctl` reads: the
  worker has already read its input when it confines itself.
- **Tools** run as `/usr/bin/sandbox-exec -p <profile> <tool> …`.
  `sandbox_init` cannot safely run between `fork` and `exec` of a
  multithreaded parent (it allocates and parses), while `sandbox-exec` is a
  fresh single-threaded process that applies the profile and then execs the
  tool. Only `setrlimit` runs in `pre_exec`. `sandbox-exec` is also deprecated
  and present on all current macOS releases; if it is ever missing, all
  Seatbelt restrictions are reported missing.
- Seatbelt matches resolved paths, so profile paths are emitted both as given
  and canonicalized (`/tmp` → `/private/tmp`, `/var` → `/private/var`).

Known gaps:

- macOS does not enforce `RLIMIT_AS`; the Tier 1 memory limit is attempted but
  not counted. CPU, file-size and descriptor limits are enforced.
- Tier 2 tools may read file *metadata* (`stat`) anywhere, which many runtimes
  need; file contents and directory listings stay restricted to the profile.
- JVM-based tools (Ghidra) may need Mach services the profile does not allow.
  They then fail and the failure is reported; they never run unconfined.
- There is no equivalent of the Linux seccomp deny-list for tools.

## Windows

| Name | Mechanism |
|---|---|
| `appcontainer_fs` | the process token is an AppContainer (lowbox) token: files need an ACE for the container SID (or "ALL APPLICATION PACKAGES", which covers system directories) |
| `appcontainer_net` | no network capability (Tier 1, tools), or only `internetClient` (fetch) |
| `job_limits` | Job Object: kill on close, per-process memory and CPU-time limits, die on unhandled exception, UI restrictions (desktop, clipboard, global atoms, system parameters, …) |
| `job_no_child` | Job Object active-process limit of 1: the worker cannot start any program |
| `port_restriction` | always **missing** for the fetch worker: AppContainer capabilities cannot filter by port |

Tier 1 requires `appcontainer_fs, appcontainer_net, job_limits, job_no_child`.

How it works: an AppContainer can only be applied when a process is created,
so the parent launches its workers confined (`spawn_worker`) instead of the
worker confining itself. For each launch it derives a fresh AppContainer SID
(`bytebouncer.<kind>.<pid>.<n>`; no profile is registered unless the system
requires it, in which case it is deleted afterwards), adds ACL entries for that
SID on exactly the paths the profile grants (Tier 1: its batch file and input
snapshots; fetch: its download directory; tools: inputs, tool directories and
scratch), creates the process suspended with `SECURITY_CAPABILITIES`, an
explicit inherited-handle list (its three pipes only), no console, and a
cleared environment (plus `SystemRoot`/`windir`), assigns it to the Job
Object, and resumes it. The ACL entries are removed when the process handle is
dropped, after the job (and so every process in it) has been terminated. The
worker's `confine_self` then verifies the token and job limits and reports
them.

Known gaps:

- **No per-port egress filtering for the fetch worker.** `internetClient`
  allows outbound connections to any internet host and port (not to the LAN
  or loopback). The fetch worker therefore reports `port_restriction` missing
  and downloads require `--allow-reduced-isolation` on Windows.
- AppContainer network isolation is enforced by the Windows Filtering
  Platform; `doctor`'s `tcp_connect` probe checks that it is effective.
- Every AppContainer can read what "ALL APPLICATION PACKAGES" can read:
  `C:\Windows`, `Program Files` and parts of the registry. User profiles and
  other users' files are not readable.
- There is no syscall filter (win32k lockdown would break system DLLs the
  binary links), no file-size limit, and the memory limit counts committed
  memory rather than address space.
- Granting a directory propagates the ACE to everything under it (and
  revoking propagates again), which can be slow for large tool directories.
  Paths the user cannot re-ACL (e.g. under `Program Files`) are skipped; they
  are normally readable by all AppContainers anyway.
- JVM-based tools may not run inside an AppContainer; the failure is reported.
- `sandbox::spawn` on Windows always gives tools an empty stdin and piped
  stdout/stderr.

## Escape probes (`bytebouncer doctor`)

`doctor` starts a Tier 1 worker in probe mode. The parent creates a fresh
directory in the user's temp directory holding a secret file; the confined
worker then tries to:

| Probe | Must fail because of |
|---|---|
| `tcp_connect` (1.1.1.1:443) | netns/Landlock, Seatbelt, AppContainer without capabilities |
| `file_write` (into that directory) | Landlock, Seatbelt, AppContainer ACLs |
| `file_read` (the secret) | Landlock, Seatbelt, AppContainer ACLs |
| `exec` (`/bin/true`, `/usr/bin/true`, `cmd.exe`) | Landlock/seccomp, Seatbelt, Job Object process limit |

`doctor` exits non-zero if any required restriction is missing or any probe
succeeds.

## Releases

Tags `v*` build `x86_64`/`aarch64` Linux (static musl), `aarch64`/`x86_64`
macOS and `x86_64` Windows (static CRT). Each native build must pass `doctor`
before it is packaged (`x86_64` macOS only when the runner has Rosetta 2). The
release contains the archives, `SHA256SUMS`, GitHub build-provenance
attestations (verify with `gh attestation verify <archive> --repo <owner>/<repo>`),
and, when the `MINISIGN_SECRET_KEY` secret is configured, `SHA256SUMS.minisig`
(verify with `minisign -Vm SHA256SUMS -P <public key>`).
