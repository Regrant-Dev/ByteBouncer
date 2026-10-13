//! `bytebouncer setup`: optional, explicit installation of deep-mode tools
//! into ByteBouncer's own data directory. Nothing is installed system-wide.
//! Every download comes from the project's official release channel, goes
//! through the sandboxed fetch worker, and must match the publisher's
//! SHA-256 before it is unpacked. ClamAV is left to the system package
//! manager because it needs a signature-update service.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytebouncer_core::ExitCode;
use serde_json::Value;

use crate::fetch::{self, FetchRequest, WorkerFetcher};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Tool {
    /// Ghidra plus a JDK (Ghidra requires Java); ~800 MB on disk
    Ghidra,
    /// capa standalone binary; ~50 MB
    Capa,
    /// REA (Ghidra investigation over MCP) plus Ghidra and a JDK if missing; needs Node.js 22+
    Rea,
    /// Prints package-manager instructions (ClamAV needs freshclam updates)
    Clamav,
}

pub fn tools_dir() -> Result<PathBuf> {
    Ok(directories::ProjectDirs::from("", "", "ByteBouncer")
        .context("cannot determine home directory")?
        .data_dir()
        .join("tools"))
}

/// A verified download: URL, file name, expected SHA-256, size.
struct Asset {
    url: String,
    name: String,
    sha256: String,
    size: u64,
    version: String,
}

fn os_arch() -> (&'static str, &'static str) {
    (std::env::consts::OS, std::env::consts::ARCH)
}

fn fetch_json(fetcher: &WorkerFetcher, url: &str) -> Result<Value> {
    let (bytes, _) = fetcher.get(url, &[("Accept", "application/json")], 4 << 20)?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {url}"))
}

/// Latest GitHub release asset matching `pick`; GitHub publishes a SHA-256 digest per asset.
fn github_asset(fetcher: &WorkerFetcher, repo: &str, pick: impl Fn(&str) -> bool) -> Result<Asset> {
    let rel = fetch_json(
        fetcher,
        &format!("https://api.github.com/repos/{repo}/releases/latest"),
    )?;
    let tag = rel["tag_name"].as_str().unwrap_or("unknown").to_owned();
    let asset = rel["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"].as_str().is_some_and(&pick))
        .with_context(|| format!("no suitable asset in {repo} release {tag}"))?;
    let sha256 = asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .context("release asset has no published SHA-256 digest; refusing to install it")?;
    Ok(Asset {
        url: asset["browser_download_url"]
            .as_str()
            .context("asset URL")?
            .to_owned(),
        name: asset["name"].as_str().unwrap_or_default().to_owned(),
        sha256: sha256.to_ascii_lowercase(),
        size: asset["size"].as_u64().unwrap_or(0),
        version: tag,
    })
}

/// Eclipse Temurin JDK 21 from the Adoptium API (publishes SHA-256 checksums).
fn jdk_asset(fetcher: &WorkerFetcher) -> Result<Asset> {
    let (os, arch) = os_arch();
    let os = match os {
        "linux" => "linux",
        "macos" => "mac",
        "windows" => "windows",
        other => bail!("no JDK download for {other}"),
    };
    let arch = match arch {
        "x86_64" => "x64",
        "aarch64" => "aarch64",
        other => bail!("no JDK download for {other}"),
    };
    let url = format!(
        "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture={arch}&image_type=jdk&os={os}&vendor=eclipse"
    );
    let v = fetch_json(fetcher, &url)?;
    let first = &v[0];
    let pkg = &first["binary"]["package"];
    Ok(Asset {
        url: pkg["link"].as_str().context("JDK link")?.to_owned(),
        name: pkg["name"].as_str().unwrap_or("jdk").to_owned(),
        sha256: pkg["checksum"]
            .as_str()
            .context("JDK checksum")?
            .to_ascii_lowercase(),
        size: pkg["size"].as_u64().unwrap_or(0),
        version: first["version"]["semver"]
            .as_str()
            .unwrap_or("21")
            .to_owned(),
    })
}

fn capa_asset(fetcher: &WorkerFetcher) -> Result<Asset> {
    let want = match os_arch() {
        ("linux", "x86_64") => "-linux.zip",
        ("linux", "aarch64") => "-linux-arm64.zip",
        ("macos", "x86_64") => "-macos.zip",
        ("macos", "aarch64") => "-macos-arm64.zip",
        ("windows", _) => "-windows.zip",
        (os, arch) => bail!("capa publishes no standalone build for {os}/{arch}"),
    };
    github_asset(fetcher, "mandiant/capa", |n| n.ends_with(want))
}

fn confirm(plan: &[&Asset], yes: bool) -> Result<bool> {
    eprintln!("This will download and verify:");
    for a in plan {
        eprintln!(
            "  {} {} ({} MB)\n    {}\n    sha256 {}",
            a.name,
            a.version,
            a.size >> 20,
            a.url,
            a.sha256
        );
    }
    eprintln!(
        "into {} (nothing is installed system-wide).",
        tools_dir()?.display()
    );
    if yes {
        return Ok(true);
    }
    eprint!("proceed? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// Download through the fetch worker and verify the published digest.
fn download(asset: &Asset, dir: &Path, allow_reduced: bool) -> Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let dest = dir.join(&asset.name);
    let _ = fs::remove_file(&dest);
    eprintln!("downloading {} …", asset.name);
    let reply = fetch::fetch(&FetchRequest {
        url: asset.url.clone(),
        headers: vec![],
        max_bytes: asset.size.max(1) + (64 << 20),
        dest: dest.clone(),
        timeout_secs: 3600,
        allow_reduced,
    })?;
    if reply.sha256 != asset.sha256 {
        let _ = fs::remove_file(&dest);
        bail!(
            "{}: SHA-256 {} does not match the published {}; nothing was installed",
            asset.name,
            reply.sha256,
            asset.sha256
        );
    }
    eprintln!("verified {} (sha256 {})", asset.name, &asset.sha256[..16]);
    Ok(dest)
}

/// Unpack a verified official archive into a fresh directory, then move it into place.
fn unpack(archive: &Path, target: &Path) -> Result<()> {
    let partial = target.with_extension("partial");
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir_all(&partial)?;
    let name = archive.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(fs::File::open(archive)?)?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let Some(rel) = entry.enclosed_name() else {
                bail!(
                    "archive entry {} escapes the target directory",
                    entry.name().unwrap_or_default()
                );
            };
            let out = partial.join(rel);
            if entry.is_dir() {
                fs::create_dir_all(&out)?;
                continue;
            }
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = fs::File::create(&out)?;
            std::io::copy(&mut entry, &mut f)?;
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out, fs::Permissions::from_mode(mode & 0o755))?;
            }
        }
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(archive)?));
        tar.set_overwrite(false);
        for entry in tar.entries()? {
            let mut entry = entry?;
            // unpack_in refuses paths that would land outside `partial`.
            if !entry.unpack_in(&partial)? {
                bail!(
                    "archive entry {} escapes the target directory",
                    entry.path()?.display()
                );
            }
        }
    } else {
        bail!("unsupported archive type: {}", archive.display());
    }
    let _ = fs::remove_dir_all(target);
    fs::rename(&partial, target)?;
    Ok(())
}

pub fn run(tool: Tool, yes: bool, allow_reduced: bool) -> Result<ExitCode> {
    if tool == Tool::Clamav {
        println!(
            "ClamAV needs regular signature updates, so install it with your package manager:"
        );
        println!("  Arch:          sudo pacman -S clamav && sudo freshclam");
        println!("  Debian/Ubuntu: sudo apt install clamav && sudo freshclam");
        println!("  Fedora:        sudo dnf install clamav clamav-update && sudo freshclam");
        println!("  macOS:         brew install clamav  (then configure and run freshclam)");
        println!(
            "ByteBouncer finds clamscan and /var/lib/clamav automatically; check with `bytebouncer doctor`."
        );
        return Ok(ExitCode::Ok);
    }
    let dir = tools_dir()?;
    let scratch = crate::store::new_workspace(&format!("setup-{}", ulid::Ulid::new()))?;
    let fetcher = WorkerFetcher {
        scratch: scratch.join("meta"),
        allow_reduced,
        counter: Default::default(),
    };
    let result = (|| -> Result<ExitCode> {
        match tool {
            Tool::Ghidra => {
                if !install_ghidra(&fetcher, &scratch, &dir, yes, allow_reduced)? {
                    eprintln!("cancelled");
                    return Ok(ExitCode::Cancelled);
                }
            }
            Tool::Capa => {
                let capa = capa_asset(&fetcher)?;
                if !confirm(&[&capa], yes)? {
                    eprintln!("cancelled");
                    return Ok(ExitCode::Cancelled);
                }
                let c = download(&capa, &scratch.join("dl"), allow_reduced)?;
                unpack(&c, &dir.join("capa"))?;
            }
            Tool::Rea => {
                install_rea(&dir, yes, allow_reduced)?;
                // REA drives Ghidra, so one command sets up both.
                if installed().ghidra_dir.is_none() {
                    eprintln!("REA needs Ghidra and a JDK; installing them next.");
                    if !install_ghidra(&fetcher, &scratch, &dir, yes, allow_reduced)? {
                        eprintln!(
                            "REA is installed but needs Ghidra: run `bytebouncer setup ghidra` (or set [deep] ghidra_dir)"
                        );
                        return Ok(ExitCode::Cancelled);
                    }
                }
            }
            Tool::Clamav => unreachable!(),
        }
        eprintln!("done; `bytebouncer doctor` should now list it, and `--mode deep` will use it");
        Ok(ExitCode::Ok)
    })();
    let _ = fs::remove_dir_all(&scratch);
    result
}

/// Download, verify, unpack and prepare Ghidra plus a JDK. `false` if declined.
fn install_ghidra(
    fetcher: &WorkerFetcher,
    scratch: &Path,
    dir: &Path,
    yes: bool,
    allow_reduced: bool,
) -> Result<bool> {
    let ghidra = github_asset(fetcher, "NationalSecurityAgency/ghidra", |n| {
        n.starts_with("ghidra_") && n.ends_with(".zip")
    })?;
    let jdk = jdk_asset(fetcher)?;
    if !confirm(&[&ghidra, &jdk], yes)? {
        return Ok(false);
    }
    let g = download(&ghidra, &scratch.join("dl"), allow_reduced)?;
    let j = download(&jdk, &scratch.join("dl"), allow_reduced)?;
    eprintln!("unpacking …");
    unpack(&g, &dir.join("ghidra"))?;
    unpack(&j, &dir.join("jdk"))?;
    compile_sleigh(allow_reduced)?;
    Ok(true)
}

/// Pinned REA release; npm verifies the tarball against the registry's
/// integrity hash. Install scripts are disabled.
const REA_VERSION: &str = "6.4.0";

fn install_rea(dir: &Path, yes: bool, allow_reduced: bool) -> Result<()> {
    let node_ok = std::process::Command::new("node")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| {
            v.trim()
                .trim_start_matches('v')
                .split('.')
                .next()?
                .parse::<u32>()
                .ok()
        })
        .is_some_and(|major| major >= 22);
    if !node_ok {
        bail!(
            "REA needs Node.js 22 or newer (`node --version`); install it with your package manager first"
        );
    }
    let target = dir.join("rea");
    eprintln!(
        "This will install rea-agents@{REA_VERSION} from the npm registry into {} (install scripts disabled).",
        target.display()
    );
    if !yes {
        eprint!("proceed? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            bail!("cancelled");
        }
    }
    let partial = dir.join("rea.partial");
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir_all(&partial)?;
    let cache = partial.join(".npm-cache");
    // npm runs confined: outbound HTTPS only, writes only into the new folder.
    let mut profile = bytebouncer_sandbox::Profile::external_tool(vec![], vec![], partial.clone());
    profile.network = bytebouncer_sandbox::Network::TcpConnectPorts(vec![443]);
    profile.read_only.push("/run/systemd/resolve".into());
    profile.limits.address_space = None;
    profile
        .env
        .push(("HOME".into(), partial.clone().into_os_string()));
    profile
        .env
        .push(("npm_config_cache".into(), cache.clone().into_os_string()));
    let npm = which("npm").context("npm not found")?;
    let (child, _) = bytebouncer_sandbox::spawn(
        &profile,
        &npm,
        |c| {
            c.args([
                "install",
                "--no-audit",
                "--no-fund",
                "--ignore-scripts",
                "--prefix",
            ])
            .arg(&partial)
            .arg(format!("rea-agents@{REA_VERSION}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        },
        allow_reduced,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "npm install failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or_default()
        );
    }
    let _ = fs::remove_dir_all(&cache);
    let _ = fs::remove_dir_all(&target);
    fs::rename(&partial, &target)?;
    eprintln!("installed REA {REA_VERSION}");
    Ok(())
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Processor families most downloads target. Ghidra releases ship SLEIGH
/// sources only and compile them on first use by writing into the install
/// directory, which deep mode's sandbox makes read-only, so compile now.
const SLEIGH_PROCESSORS: &[&str] = &[
    "x86", "ARM", "AARCH64", "RISCV", "PowerPC", "MIPS", "JVM", "Dalvik",
];

fn compile_sleigh(allow_reduced: bool) -> Result<()> {
    let found = installed();
    let (Some(ghidra), Some(java)) = (found.ghidra_dir, found.java_home) else {
        bail!("Ghidra or the JDK is missing after unpacking");
    };
    let script = ghidra.join("support").join(if cfg!(windows) {
        "sleigh.bat"
    } else {
        "sleigh"
    });
    for proc in SLEIGH_PROCESSORS {
        let langs = ghidra
            .join("Ghidra")
            .join("Processors")
            .join(proc)
            .join("data")
            .join("languages");
        if !langs.is_dir() {
            continue;
        }
        eprintln!("compiling {proc} processor specifications …");
        // Run Ghidra's own compiler confined: no network, write access only to
        // this processor's language directory.
        let mut profile = bytebouncer_sandbox::Profile::external_tool(
            vec![ghidra.clone(), java.clone()],
            vec![],
            langs.clone(),
        );
        profile.limits.address_space = None;
        profile
            .env
            .push(("JAVA_HOME".into(), java.clone().into_os_string()));
        // Ghidra keeps launcher settings under the user's config directory;
        // point it (and Java's user.home) at a scratch dir inside the grant.
        let settings = langs.join(".bytebouncer-sleigh-home");
        fs::create_dir_all(&settings)?;
        for var in ["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"] {
            profile
                .env
                .push((var.into(), settings.clone().into_os_string()));
        }
        profile.env.push((
            "JAVA_TOOL_OPTIONS".into(),
            format!("-Duser.home={0} -Djava.io.tmpdir={0}", settings.display()).into(),
        ));
        let (child, _) = bytebouncer_sandbox::spawn(
            &profile,
            &script,
            |c| {
                c.arg("-a")
                    .arg(&langs)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped());
            },
            allow_reduced,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let out = child.wait_with_output()?;
        let _ = fs::remove_dir_all(&settings);
        if !out.status.success() {
            bail!("compiling {proc} specifications failed: {}", {
                let err = String::from_utf8_lossy(&out.stderr);
                let lines: Vec<&str> = err
                    .lines()
                    .filter(|l| !l.starts_with("Picked up"))
                    .collect();
                lines[lines.len().saturating_sub(8)..].join(" | ")
            });
        }
    }
    Ok(())
}

pub fn remove(tool: Tool) -> Result<ExitCode> {
    let name = match tool {
        Tool::Ghidra => vec!["ghidra", "jdk"],
        Tool::Capa => vec!["capa"],
        Tool::Rea => vec!["rea"],
        Tool::Clamav => {
            println!("ClamAV was installed by your package manager; remove it there.");
            return Ok(ExitCode::Ok);
        }
    };
    let dir = tools_dir()?;
    for n in name {
        let p = dir.join(n);
        if p.exists() {
            fs::remove_dir_all(&p)?;
            println!("removed {}", p.display());
        }
    }
    Ok(ExitCode::Ok)
}

/// Locations of tools installed by `setup`, for deep-mode discovery.
pub struct Installed {
    pub ghidra_dir: Option<PathBuf>,
    pub java_home: Option<PathBuf>,
    pub capa: Option<PathBuf>,
    /// `rea` launcher and the directory to grant (its node_modules tree).
    pub rea: Option<(PathBuf, PathBuf)>,
}

pub fn installed() -> Installed {
    let Ok(dir) = tools_dir() else {
        return Installed {
            ghidra_dir: None,
            java_home: None,
            capa: None,
            rea: None,
        };
    };
    let first_child = |p: PathBuf| -> Option<PathBuf> {
        fs::read_dir(p)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p| p.is_dir())
    };
    let ghidra_dir = first_child(dir.join("ghidra"))
        .filter(|g| g.join("support").join("analyzeHeadless").exists());
    let java_home = first_child(dir.join("jdk")).map(|j| {
        let mac = j.join("Contents").join("Home");
        if mac.exists() { mac } else { j }
    });
    let capa_bin = dir
        .join("capa")
        .join(if cfg!(windows) { "capa.exe" } else { "capa" });
    let rea_dir = dir.join("rea");
    let rea_bin = rea_dir
        .join("node_modules")
        .join(".bin")
        .join(if cfg!(windows) { "rea.cmd" } else { "rea" });
    Installed {
        ghidra_dir,
        java_home,
        capa: capa_bin.exists().then_some(capa_bin),
        rea: rea_bin.exists().then_some((rea_bin, rea_dir)),
    }
}
