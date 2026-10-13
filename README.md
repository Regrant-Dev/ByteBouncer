# ByteBouncer

**Know what you're letting in.**

ByteBouncer inspects software *before* you install or run it: a download, an installer, a folder, a URL, or a package request like `yay -S foo`. It tells you what it found, how strong the evidence is, and what it could not check. It never installs or executes what it inspects.

```console
$ bytebouncer inspect ~/Downloads/some-app.AppImage
$ bytebouncer inspect https://example.com/tool-1.2.tar.gz --checksums-file https://example.com/SHA256SUMS
$ bytebouncer inspect "pacman -S firefox"
$ bytebouncer inspect -- yay -S some-aur-package
$ bytebouncer watch ~/Downloads --notify
```

One binary, no setup. Deep analysis and AI explanations are optional extras that use tools you may already have.

> **Status: early development.** Linux is the qualified host platform. Windows and macOS builds exist, but their sandboxes are qualified only in CI. See [docs/platforms.md](docs/platforms.md).

## What it checks

**Quick mode (default, no prerequisites)**
- **Unpacks almost anything, in memory:** zip, tar, gzip/xz/zstd/bzip2, `.deb`, `.rpm`, Arch packages, AppImage, MSI and CAB, MSIX, macOS `.pkg` and DMG. Nested archives are followed. Path-traversal tricks, decompression bombs and links are handled safely.
- **Binaries:** ELF, PE and Mach-O imports and sections, packers, Authenticode signer and integrity.
- **Install-time scripts:** Debian maintainer scripts, RPM scriptlets, `.INSTALL`, MSI custom actions, `.pkg` pre/postinstall, PowerShell, and shell. It looks for download-and-execute, persistence, security weakening, setuid, and encoded payloads.
- **Privacy:** embedded endpoints and references to analytics and crash-reporting services.
- **YARA-X rules:** a small bundled set (reverse shells, miners, credential-store access, Defender tampering, …) plus your own rule files.
- **Provenance:** `--expect-sha256`, `SHA256SUMS` files, minisign and OpenPGP detached signatures, and repository digests and signatures for package requests (pacman packages are verified against the system pacman keyring).

**Package requests** use familiar syntax but are *never executed*: pacman, yay/paru (AUR), apt and dnf (on hosts that have them), Homebrew, winget, Scoop, and Chocolatey. ByteBouncer resolves the exact files, downloads them through a sandboxed fetcher, checks repository digests and signatures, and inspects recipes (PKGBUILD, formulae, manifests) as data. PKGBUILDs are parsed, not sourced.

**Deep mode** (`--mode deep`): built around REA (see below). It also runs whichever of [capa](https://github.com/mandiant/capa), [ClamAV](https://www.clamav.net/) and [Ghidra](https://ghidra-sre.org/) are available. It finds capabilities, signature matches, call paths, and URLs referenced by network code. Each tool runs in the Tier 2 sandbox (no network, read-only input, scratch-only writes). Use tools you already have, or let ByteBouncer fetch them into its own folder. Nothing is installed system-wide, and every download is checked against the publisher's SHA-256:

```console
$ bytebouncer setup ghidra     # official Ghidra + Temurin JDK 21 (~800 MB), CPU specs precompiled
$ bytebouncer setup capa       # standalone capa binary
$ bytebouncer setup clamav     # prints package-manager instructions (needs freshclam updates)
$ bytebouncer doctor           # shows what deep mode will use
```

**REA** ([morluto/rea](https://github.com/morluto/rea)) is the preferred way to use Ghidra. It drives Ghidra over MCP: ByteBouncer opens the file in REA, records where each network destination is used along with the decompiled code, and gives your model about 25 read-only REA tools to investigate further (decompile, call paths, xrefs, strings). Every result the model fetches becomes evidence it can cite. REA's dynamic tools (Frida, ADB, UI automation) and editing tools are never exposed. There are two ways to run it:

```console
$ bytebouncer setup ghidra && bytebouncer setup rea   # local REA (needs Node.js 22+), runs in the Tier 2 sandbox
```

Or point ByteBouncer at analysis servers that run somewhere more isolated, for example a disposable offline VM. ByteBouncer starts each command as an MCP server on stdio:

```toml
[deep.rea]
command = ["/path/to/connector", "mcp", "rea"]   # any REA MCP server
sandbox = false              # only when the command provides its own isolation (e.g. a VM)
staging_dir = "~/Downloads/bytebouncer-staging"   # if the connector only accepts files from certain folders

[deep.scan]                  # capa + ClamAV elsewhere: tools `capa_scan {path}`, `clamav_scan {path}`
command = ["/path/to/connector", "mcp", "scan"]
staging_dir = "~/Downloads/bytebouncer-staging"
```

`[deep.scan]` servers return each tool's raw output (`capa -j` JSON, or `clamscan` output with its exit code and database version), and ByteBouncer parses it exactly as it does for local runs. Reports say which isolation was used: ByteBouncer's sandbox, or "provided by that command".

**Model synthesis** (`--model NAME`, optional): bring any OpenAI-compatible endpoint (llama.cpp, vLLM, LM Studio, Ollama's OpenAI API, or a hosted provider). The model reads evidence through read-only tools and can only *add* findings that cite real evidence. Anything it can't back up is kept as an "unverified hypothesis". Hosted endpoints require `--allow-hosted-model`.

## What it does *not* claim

- **No findings ≠ safe.** Reports say what was analyzed and what was not. Absence of findings is never a safety verdict.
- **Capability ≠ intent.** An analytics URL or a keyboard-hook import is evidence to review, not proof of wrongdoing.
- **Static only.** Nothing is executed, so behavior that only shows up at run time (downloaded updates, server-side configuration) is outside the report.

| Exit code | Meaning |
|---|---|
| 0 | Analysis completed, policy not exceeded (not proof of safety) |
| 1 | Policy exceeded (default: a high/critical security finding or a checksum/signature mismatch) |
| 2 | Invalid request (bad syntax, unsupported command, `sudo`, shell operators…) |
| 3 | Analysis incomplete or input unsupported |
| 4 | Internal or isolation failure |
| 130 | Cancelled |

## How it stays safe while looking at hostile files

- **Tier 1 (all quick-mode parsing):** memory-safe Rust analyzers run in a separate worker process. On Linux the worker has an empty network namespace, Landlock denying all filesystem access, exec and TCP, a tight seccomp syscall allow-list, and resource limits. Inputs are read before confinement.
- **Tier 2 (deep-mode tools, `gpgv`):** external tools are confined between fork and exec. They get no network, read-only access to the input, and write access only to a scratch directory. A seccomp deny-list blocks ptrace, mounts, namespaces, BPF and io_uring.
- **Fetch worker:** downloads may only connect out on TCP 80/443 and write their own destination. The fetcher never parses what it downloads.

`bytebouncer doctor` shows which restrictions are active and runs escape probes. If a restriction is unavailable, ByteBouncer refuses to analyze unless you pass `--allow-reduced-isolation`, and every report records what was missing. The trade-off is deliberate: Tier 2 is a kernel sandbox, not a VM, so it works on ordinary machines without setup.

## Requirements

| What you want | You need |
|---|---|
| **Quick mode**: archives, installers, packages, signatures, scripts, rules, code map | Just the `bytebouncer` binary. Full Linux isolation needs kernel 6.7+ (Landlock ABI 4) and unprivileged user namespaces. |
| **Deep mode + AI**: what the code actually does, where data goes, decompiled evidence | **[REA](https://github.com/morluto/rea) + Ghidra.** This is the core of deep analysis. Either `bytebouncer setup rea` (installs REA, Ghidra and a JDK into ByteBouncer's folder; needs Node.js 22+), or an existing REA you run in an isolated VM (`[deep.rea]`). |
| AI investigation | Any OpenAI-compatible model endpoint (local or hosted) |
| Nothing else | capa and ClamAV are optional extras that deep mode uses only if they happen to be installed. For a known-malware check without installing anything, use `--lookup malwarebazaar` (sends only the file's SHA-256). |

Without REA, deep mode falls back to running Ghidra directly if it is installed, and the AI still gets the built-in x86/x64 code map. REA is what lets the model navigate and decompile code itself.

## Install

```console
$ cargo install --git https://github.com/Regrant-Dev/bytebouncer bytebouncer
$ bytebouncer doctor
$ bytebouncer setup rea        # recommended: enables deep mode and AI code investigation
```

Tagged releases publish binaries with `SHA256SUMS` and build-provenance attestations on the Releases page.

## Everyday use

```console
# Files, folders, URLs (add --open to see the report in your browser)
bytebouncer inspect ./setup.exe --open
bytebouncer inspect ./project --include-vendored
bytebouncer inspect https://example.com/app.zip --expect-sha256 <hex>

# Package requests (quote them, or put them after --)
bytebouncer inspect "pacman -S obs-studio"
bytebouncer inspect -- yay -S visual-studio-code-bin --include-dependencies
bytebouncer inspect "winget install --id Microsoft.PowerToys -e"

# Reports
bytebouncer report --list
bytebouncer report 01JABCDE --open                 # styled HTML report in your browser
bytebouncer compare <old-id> <new-id>      # what changed in an update

# Opt-in extras
bytebouncer inspect ./app --lookup malwarebazaar      # sends only the SHA-256
bytebouncer inspect ./app --mode deep --model local --ask "does this phone home?"
```

Reports are saved (owner-only permissions) under `~/.local/share/bytebouncer/reports/`.

## Configuration

Optional. Create `~/.config/bytebouncer/config.toml`:

```toml
default_model = "local"

[policy]                       # what makes exit code 1
fail_on_security = "high"      # none | info | low | medium | high | critical
fail_on_privacy = "none"
fail_on_provenance_mismatch = true

[models.local]                 # any OpenAI-compatible endpoint
base_url = "http://127.0.0.1:8080/v1"
model = "your-model"
# api_key_env = "MY_KEY_VAR"   # name of an env var, never the key itself

[deep]                         # only if tools aren't on PATH / standard locations
# ghidra_dir = "/opt/ghidra"
# java_home = "/usr/lib/jvm/java-21-openjdk"   # Ghidra needs a full JDK

[lookup]
# malwarebazaar_key_env = "MALWAREBAZAAR_KEY"
# virustotal_key_env = "VT_API_KEY"

[keys]
# minisign = ["RWQ...publickey"]
# pgp_keyrings = ["~/.config/bytebouncer/trusted.gpg"]

[rules]
# directories = ["~/.config/bytebouncer/rules"]   # your own .yar files

[watch]
directories = ["~/Downloads"]
notify = true
```

## Optional integrations

- **Approvals and install handoff:** `bytebouncer approve <report>` records the exact SHA-256s you accepted. `bytebouncer install <report>` re-downloads a pacman/apt/dnf request, verifies it byte-for-byte against the approved report, and only then runs `sudo pacman -U …` (or the apt/dnf equivalent) after asking you.
- **pacman hook:** `bytebouncer pacman-hook --print-hook` prints a PreTransaction hook that warns about (or, in `enforce` mode, blocks) packages without an approval. It runs as root but never analyzes anything; it only checks approval records. Configure it in `/etc/bytebouncer/pacman-hook.toml`:
  ```toml
  mode = "warn"   # or "enforce"
  approvals_dir = "/home/you/.local/share/bytebouncer/approvals"
  ```
- **MCP server:** `bytebouncer mcp` exposes `inspect`, `get_report`, `list_reports` and `compare_reports` to AI agents over stdio. There are no install, approve or configuration tools.

## Privacy

ByteBouncer has no telemetry. Inspecting a local file makes no network requests. Network use is limited to what you ask for: downloading a URL or package, fetching detached signatures and checksums next to it, opt-in hash lookups, and your configured model. Every report records which of these happened.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option. Bundled YARA rules are original to this project under the same terms. capa, ClamAV and Ghidra are separate programs under their own licenses and are not distributed with ByteBouncer.
