# Installation guard

The guard downloads a native package-manager transaction, scans its package
files and dependencies, then waits for your decision before installation.
One review engine handles reports, quick/deep analysis, approvals and digest
checks. Small connectors handle each package manager; distributions using the
same manager share a connector. No background service is required.

## Enable it

After building/installing the updated ByteBouncer binary, activate the functions
in your current **bash** session:

```sh
eval "$(bytebouncer integration --shell bash)"
```

For **zsh**, use `--shell zsh`. To enable it in future sessions, add that line to
your shell startup file yourself. The integration command only prints shell
code; it does not edit configuration or install system hooks.

Then use familiar commands:

```sh
sudo pacman -S firefox
sudo pacman -Syu
yay -S some-aur-package
paru -S some-aur-package
sudo apt install curl
sudo apt upgrade
sudo dnf upgrade
```

The generated functions also cover `apt-get`, `dnf5` and direct `makepkg` calls.
The `sudo` function intercepts a package-manager name immediately after `sudo`.
Other sudo invocations are forwarded unchanged. To remove these functions:

```sh
eval "$(bytebouncer integration --disable)"
```

You can use the guard without shell functions:

```sh
bytebouncer guard -- pacman -Syu
bytebouncer guard -- apt install curl
bytebouncer guard --mode deep --model local -- yay -S some-aur-package
```

Run the guard as your normal user. It uses `sudo` for the native operations
that require root. If an AUR helper elevates a callback, ByteBouncer returns
to the invoking user before scanning. A root shell without an invoking user
is refused.

## Review and continue

A quick scan runs automatically. The report is saved in the normal report
store, and you choose:

```text
[c] continue
[d] deep/REA scan
[r] read report
[o] open report in a browser
[x] cancel (default)
```

Deep review attempts every executable within the scan's time/resource budgets;
REA must already be configured or installed. Missing tools and incomplete
coverage are reported. Choosing continue on an incomplete report or exceeded
policy requires a nonempty override reason, saved with the approvals.

Approvals refer to exact SHA-256 hashes. Files are checked again before native
installation. A file absent from the report cannot be approved by this gate.
Additional package downloads are disabled during installation; if another
transaction or changed repository state requires different packages, the
native manager must stop rather than fetch an unreviewed payload. Restart the
guard to review the new transaction.

The guard has its own confirmation. Native `-y`/`--noconfirm` options do not
answer it. For explicitly unattended use, `guard --yes` proceeds only when
analysis completes and policy passes; it cannot override either failure.
Without `--yes`, a terminal is required. AUR callbacks use the terminal for
review, keeping metadata on stdout intact. Ctrl-C or an empty decision cancels.

Defaults can be configured in ByteBouncer's normal config:

```toml
[guard]
mode = "quick"       # or "deep"
# model = "local"   # optional configured model profile
```

CLI `--mode` and `--model` override these settings. Hosted model use still
requires `--allow-hosted-model`; reduced sandbox isolation still requires
`--allow-reduced-isolation`. These flags can also be supplied to `integration`
when generating your shell functions.

## Manager behavior

| Manager | Before review | After approval |
|---|---|---|
| pacman sync/install/upgrade | Native download-only transaction into a private cache, including dependencies | Original goals with the reviewed cache, refreshed database and a temporary configuration disabling further downloads; signature settings and dependency reasons are preserved |
| pacman `-U` | Copies local package archives into the review workspace | Installs those reviewed copies; URLs must be downloaded first |
| yay / paru | Temporary pacman and makepkg callbacks route native operations through the shared gate | Each build-input set is approved before makepkg runs, and built packages are reviewed before pacman installs |
| makepkg | Reviews PKGBUILD, `.install`, patches and other local build inputs as data, including metadata-only calls | Runs makepkg after approval, with its pacman calls guarded too |
| apt / apt-get | Native download-only install/reinstall/upgrade, with removals disallowed | Original goals with downloads disabled and only the reviewed archive cache, preserving dependency reasons |
| DNF 4 | Native download-only transaction | Original goals in cache-only mode, with package lookups directed to the reviewed cache |
| DNF 5 | Stores the native transaction and RPMs without installation | Verifies the stored files and replays the transaction in cache-only mode |

If `dnf` is a symlink to `dnf5`, the DNF5 connector is selected automatically.
Queries, explicit download-only operations, metadata refreshes and removals
pass through without a review prompt. Unknown installation operations or
options are refused rather than run without review. This initial version does
not cover every native flag, apt full-upgrade/repair-only operations, alternate
installation roots, or custom AUR callback/chroot options.

## Coverage and limits

Automatic guarding currently supports Linux bash/zsh command sessions. Windows
and macOS retain their existing inspection support; automatic installer
interception is not implemented there yet. Zypper, Flatpak, Snap and graphical
package-manager installations are not intercepted by this integration.

Shell functions are an opt-in convenience, not a system enforcement boundary.
Commands from other shells/scripts, explicit paths such as `/usr/bin/pacman`,
`command pacman`, or sudo options such as `sudo -u root pacman` bypass the
functions. Use `bytebouncer guard -- …` explicitly in scripts.

The older approval-only `pacman-hook` remains independent. Its current cache
lookup does not understand the guard's private cache or local/AUR packages.
If enabled in `enforce` mode, it can still block a reviewed transaction. Use
the interactive guard independently rather than enabling that legacy hook
for this workflow.

AUR recipe review excludes `.git`, generated `src`/`pkg` directories, `target`
and previously built package archives. Links and special files in build inputs
are refused. Identical previously approved inputs can proceed without another
recipe prompt; changed bytes require review. This does not sandbox the build,
review every downloaded source before execution, or prevent an accepted
recipe from invoking other commands. Built binaries are reviewed separately.

Native package managers retain their existing configuration, plugins, hooks,
signature checks and installer/script execution after approval. Static analysis
does not establish that software is safe, and an installer may fetch more
content at runtime. The gate covers incoming package files, not every future
action of installed software.

Testing uses harmless package-manager doubles to exercise downloads,
dependency coverage, policy failures, cancellation, approval and offline
handoff. Real read-only pacman/yay callbacks are checked on the development
host. Native installation/upgrade tests on each target distribution are still
needed before treating these connectors as production-qualified.

Native interfaces: [pacman](https://man.archlinux.org/man/pacman.8),
[yay](https://jguer.github.io/yay/man.html),
[APT](https://manpages.debian.org/testing/apt/apt-get.8.en.html),
[DNF](https://dnf.readthedocs.io/en/stable/command_ref.html), and
[DNF5 replay](https://dnf5.readthedocs.io/en/latest/commands/replay.8.html).
