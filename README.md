# ByteBouncer

Know what you're letting in.

ByteBouncer looks inside software before you install or run it. Point it at a download, an installer, a folder, a URL, or a package request like `yay -S foo`, and it tells you what it found, how solid the evidence is, and what it couldn't check. It never installs or runs the thing it's looking at.

```console
$ bytebouncer inspect ~/Downloads/some-app.AppImage
$ bytebouncer inspect "pacman -S firefox"
$ bytebouncer inspect -- yay -S some-aur-package
$ bytebouncer inspect https://example.com/tool.tar.gz --checksums-file https://example.com/SHA256SUMS
$ bytebouncer watch ~/Downloads --notify
```

It's a single binary and works without any setup. Deeper analysis (Ghidra through REA) and AI investigation are optional.

This is early software. Linux is the main platform. Windows and macOS builds exist, but their sandboxes have only been tested in CI so far; see [docs/platforms.md](docs/platforms.md).

## What it looks at

A normal scan (quick mode) needs nothing else installed. It:

- unpacks zip, tar, gzip/xz/zstd/bzip2, `.deb`, `.rpm`, Arch packages, AppImage, MSI/CAB, MSIX, macOS `.pkg` and DMG, including archives inside archives. Path traversal, zip bombs and symlink tricks are handled. Files too big to unpack in memory are extracted to disk by a separate sandboxed worker and checked on their own.
- reads ELF, PE and Mach-O binaries: imports, sections, packers, and Authenticode signatures.
- maps the code of x86/x64 binaries: which functions call network, file, registry, clipboard or identifier APIs, and which strings (URLs, paths, registry keys) they use.
- reads install scripts (Debian maintainer scripts, RPM scriptlets, `.INSTALL`, MSI custom actions, `.pkg` scripts, PowerShell, shell) and flags things like download-and-run, persistence, disabling security tools, and encoded payloads.
- lists embedded endpoints and spots common analytics and crash-reporting services.
- runs a small set of bundled YARA rules (reverse shells, miners, credential theft, Defender tampering, and so on), plus any rules you add.
- checks provenance: `--expect-sha256`, `SHA256SUMS` files, minisign and OpenPGP signatures, and for packages the repository's own checksums and signatures. Pacman packages are checked against your system's pacman keyring.

Package requests use the commands you already know, but nothing gets installed. ByteBouncer works out which exact files the request would install, downloads them through a sandboxed fetcher, verifies them, and reads recipes (PKGBUILDs, Homebrew formulae, winget/Scoop/Chocolatey manifests) as plain data. A PKGBUILD is parsed, never sourced. Supported: pacman, yay/paru (AUR), apt and dnf (on systems that have them), Homebrew, winget, Scoop and Chocolatey.

## Deep mode and REA

`--mode deep` is where the real code reading happens, and it's built around [REA](https://github.com/morluto/rea), which drives Ghidra over MCP. ByteBouncer opens each executable in REA, finds where every network destination is used, and keeps the decompiled code as evidence. If you also use a model, the model gets about 25 read-only REA tools (decompile a function, follow call paths, look up cross-references and strings) so it can dig further. Anything it looks at becomes evidence it can cite. REA's tools that run or change things (Frida, ADB, UI automation, renaming) are never given to the model.

You can run REA locally:

```console
$ bytebouncer setup rea    # installs REA, Ghidra and a JDK into ByteBouncer's own folder (needs Node.js 22+)
```

Or you can run it somewhere more isolated, like a throwaway offline VM, and point ByteBouncer at it. ByteBouncer starts the command as an MCP server and talks to it over stdio:

```toml
[deep.rea]
command = ["/path/to/connector", "mcp", "rea"]
sandbox = false        # only if that command provides its own isolation
staging_dir = "~/Downloads/bytebouncer-staging"   # if it only accepts files from certain folders
```

Deep mode also uses [capa](https://github.com/mandiant/capa), [ClamAV](https://www.clamav.net/) or a plain Ghidra install if you happen to have them. None of them are required. `bytebouncer doctor` shows what it found. capa and ClamAV can also run behind an MCP server with a `[deep.scan]` section that works the same way as `[deep.rea]`. Anything ByteBouncer installs for you goes in its own folder, is checked against the publisher's SHA-256, and is never installed system-wide.

## Asking a model

Add `--model NAME` to have a model investigate the evidence. Any OpenAI-compatible endpoint works: llama.cpp, vLLM, LM Studio, Ollama's OpenAI API, or a hosted provider. By default it goes through a checklist: what data the program can collect, where it stores it, what it sends and to whom, which third-party services are involved, whether there are opt-outs, and whether anything looks harmful. `--ask` adds your own question on top.

The model can only add findings, and each one has to cite real evidence. ByteBouncer checks every citation and caps how strong a claim can be based on the evidence behind it. Claims that don't hold up are kept separately as unverified. The model's written summary goes at the top of the report, marked as its own narrative. Hosted endpoints need `--allow-hosted-model`, since evidence would leave your machine.

## What a report does and doesn't mean

Reports start with a TL;DR, severity counts (Critical, High, Medium, Low and Info), and the key findings. Expand a finding to see its evidence, or open the full AI investigation. Incomplete coverage stays visible alongside severity. Terminal scans show the short overview; `bytebouncer report <id>` shows the full details.

- No findings doesn't mean safe. Every report says what was analyzed and what wasn't.
- A capability isn't intent. An analytics URL or a keyboard-hook import is something to look at, not proof of wrongdoing.
- It's all static. Nothing is executed, so anything that only shows up at runtime (downloaded updates, server-side config) is outside the report.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Finished, policy not exceeded (still not a safety guarantee) |
| 1 | Policy exceeded (by default: a high or critical security finding, or a checksum/signature mismatch) |
| 2 | Bad request: syntax error, unsupported command, `sudo`, shell operators |
| 3 | Incomplete, or the input isn't supported |
| 4 | Internal or isolation failure |
| 130 | Cancelled |

## Sandboxing

Hostile files are parsed in isolation:

- All quick-mode parsing is done by memory-safe Rust code in a separate worker process. On Linux that worker has no network (empty network namespace), no file access and no ability to start programs (Landlock), a short syscall allow-list (seccomp), and resource limits. It reads its input before locking itself down.
- Deep-mode tools like capa, ClamAV, Ghidra and `gpgv` run with no network, read-only access to the file being checked, and write access only to a scratch folder. A seccomp deny-list blocks ptrace, mounts, namespaces, BPF and io_uring.
- Downloads go through their own worker, which can only connect out on ports 80 and 443 and only write the file it's downloading. It never parses anything.

`bytebouncer doctor` shows which restrictions are active and tries a few escapes (network, reading and writing files, starting a program) to confirm they're blocked. If a restriction isn't available on your system, ByteBouncer won't analyze anything unless you pass `--allow-reduced-isolation`, and the report records what was missing. This is a kernel sandbox, not a VM. That's a deliberate trade-off so it works on a normal machine with no setup.

## Requirements

- Quick mode: just the binary. Full isolation on Linux needs kernel 6.7 or newer (Landlock ABI 4) and unprivileged user namespaces.
- Deep mode: REA and Ghidra, either through `bytebouncer setup rea` or your own REA server. Without REA, deep mode falls back to a plain Ghidra install if there is one, and models still get the built-in code map.
- AI investigation: any OpenAI-compatible endpoint.

For a known-malware check without installing anything, `--lookup malwarebazaar` sends only the file's SHA-256 to MalwareBazaar.

## Install

```console
$ cargo install --git https://github.com/Regrant-Dev/ByteBouncer bytebouncer
$ bytebouncer doctor
$ bytebouncer setup rea    # optional, for deep mode
```

Tagged releases include prebuilt binaries, a `SHA256SUMS` file and GitHub build attestations.

## Everyday use

```console
# Files, folders and URLs (--open shows the report in your browser)
bytebouncer inspect ./setup.exe --open
bytebouncer inspect ./project --include-vendored
bytebouncer inspect https://example.com/app.zip --expect-sha256 <hex>

# Packages (quote the command, or put it after --)
bytebouncer inspect "pacman -S obs-studio"
bytebouncer inspect -- yay -S visual-studio-code-bin --include-dependencies
bytebouncer inspect "winget install --id Microsoft.PowerToys -e"

# Deep mode with a model
bytebouncer inspect ./app --mode deep --model local
bytebouncer inspect ./app --mode deep --model local --effort medium --ask "does this phone home?"

# Reports
bytebouncer report --list
bytebouncer report 01JABCDE --open
bytebouncer compare <old-id> <new-id>    # what changed between two versions
```

Reports are saved with owner-only permissions in `~/.local/share/bytebouncer/reports/`.

## Configuration

Everything is optional. Put this in `~/.config/bytebouncer/config.toml` and keep what you need:

```toml
default_model = "local"

[policy]                       # what makes the exit code 1
fail_on_security = "high"      # none | info | low | medium | high | critical
fail_on_privacy = "none"
fail_on_provenance_mismatch = true

[models.local]                 # any OpenAI-compatible endpoint
base_url = "http://127.0.0.1:8080/v1"
model = "your-model"
# reasoning_effort = "medium"  # passed through as-is; valid values depend on your model
# api_key_env = "MY_KEY_VAR"   # the name of an environment variable holding the key
# api_key_file = "~/.config/myprovider/key"

[deep]                         # only needed if tools aren't found automatically
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

## Extras

- `bytebouncer guard -- pacman -Syu` downloads the transaction and dependencies, scans the exact files, and waits for you to continue, request deep/REA analysis, read the report, or cancel. The shared flow supports pacman, yay/paru/makepkg, apt/apt-get, and DNF 4/5 on Linux. To guard ordinary commands in your current bash or zsh session, run `eval "$(bytebouncer integration --shell bash)"` (use `zsh` for zsh). This also catches plain `sudo pacman …` and `sudo apt …`; no background service is needed. See [installation guard](docs/install-guard.md) for coverage, configuration and limitations.
- `bytebouncer approve <report>` records the exact files you've accepted. `bytebouncer install <report>` downloads a pacman, apt or dnf request again, checks that every byte matches what you approved, and then hands it to your package manager, after asking you.
- `bytebouncer pacman-hook --print-hook` prints a pacman hook that warns about packages you haven't approved, or blocks them in `enforce` mode. It runs as root but only compares checksums against your approvals; it never analyzes anything as root. Configure it in `/etc/bytebouncer/pacman-hook.toml`:
  ```toml
  mode = "warn"   # or "enforce"
  approvals_dir = "/home/you/.local/share/bytebouncer/approvals"
  ```
- `bytebouncer mcp` lets AI agents use ByteBouncer over MCP. It offers `inspect`, `get_report`, `list_reports` and `compare_reports`, and nothing that installs, approves or changes settings.

## Privacy

ByteBouncer has no telemetry. Checking a local file doesn't touch the network. It only goes online when you ask it to: downloading a URL or package (and any signatures or checksum files next to it), hash lookups you opted into, and the model you configured. Each report lists which of these happened.

## License

MIT or Apache 2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). The bundled YARA rules were written for this project and use the same license. capa, ClamAV, Ghidra and REA are separate projects under their own licenses and are not shipped with ByteBouncer.
