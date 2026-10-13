//! Running one external tool inside the sandbox with bounded output, a
//! wall-clock timeout, and cancellation.

use bytebouncer_sandbox::Child;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytebouncer_sandbox::{Applied, Profile, SpawnError};

/// How often the child is polled for exit, timeout, and cancellation.
const POLL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Exited normally with this code.
    Exited(i32),
    /// Terminated by a signal (crash, OOM kill, rlimit).
    Signaled,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub struct RunOutput {
    pub status: Status,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr: Vec<u8>,
    pub applied: Applied,
    pub elapsed: Duration,
}

impl RunOutput {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// The last non-empty stderr line, bounded, for coverage messages.
    pub fn stderr_tail(&self) -> String {
        let text = self.stderr_text();
        let line = text
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("");
        bounded(line, 200)
    }
}

pub fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

pub struct RunSpec<'a> {
    pub program: &'a Path,
    pub args: Vec<OsString>,
    pub profile: Profile,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
    pub stdout_cap: usize,
    pub stderr_cap: usize,
    pub allow_reduced: bool,
}

#[derive(Debug)]
pub enum RunError {
    /// The sandbox could not provide the required restrictions.
    Reduced(Vec<String>),
    Spawn(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reduced(m) => write!(
                f,
                "sandbox restrictions unavailable ({}); rerun with --allow-reduced-isolation to accept",
                m.join(", ")
            ),
            Self::Spawn(e) => write!(f, "could not start: {e}"),
        }
    }
}

fn reader(mut src: impl Read + Send + 'static, cap: usize) -> JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut src).take(cap as u64).read_to_end(&mut buf);
        // Keep draining so the child never blocks on a full pipe.
        let drained = io::copy(&mut src, &mut io::sink()).unwrap_or(0);
        (buf, drained > 0)
    })
}

/// Kill the child's whole process group (wrapper scripts spawn JVMs etc.).
fn kill_group(child: &mut Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
}

pub fn run(spec: RunSpec<'_>, cancel: &AtomicBool) -> Result<RunOutput, RunError> {
    let args = spec.args.clone();
    let cwd = spec.cwd.clone();
    let configure = move |cmd: &mut Command| {
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = &cwd {
            cmd.current_dir(dir);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
    };
    let start = Instant::now();
    let (mut child, applied) =
        bytebouncer_sandbox::spawn(&spec.profile, spec.program, configure, spec.allow_reduced)
            .map_err(|e| match e {
                SpawnError::Reduced(m) => RunError::Reduced(m),
                SpawnError::Io(e) => RunError::Spawn(e.to_string()),
            })?;
    let out = child.stdout.take().map(|s| reader(s, spec.stdout_cap));
    let err = child.stderr.take().map(|s| reader(s, spec.stderr_cap));

    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().map_or(Status::Signaled, Status::Exited),
            Ok(None) => {}
            Err(_) => break Status::Signaled,
        }
        if cancel.load(Ordering::Relaxed) {
            kill_group(&mut child);
            let _ = child.wait();
            break Status::Cancelled;
        }
        if start.elapsed() >= spec.timeout {
            kill_group(&mut child);
            let _ = child.wait();
            break Status::TimedOut;
        }
        std::thread::sleep(POLL);
    };
    // Reap anything the tool left behind in its process group, so the pipes
    // close and nothing outlives the scan.
    kill_group(&mut child);
    let (stdout, stdout_truncated) = out.and_then(|h| h.join().ok()).unwrap_or_default();
    let (stderr, _) = err.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(RunOutput {
        status,
        stdout,
        stdout_truncated,
        stderr,
        applied,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> bytebouncer_sandbox::testutil::TempDir {
        bytebouncer_sandbox::testutil::temp_dir("bb-deep-runner", name)
    }

    fn sh(script: &str, timeout: Duration, cap: usize, cancel: &AtomicBool) -> RunOutput {
        let dir = scratch(&format!("{}", script.len()));
        run(
            RunSpec {
                program: Path::new("/bin/sh"),
                args: vec!["-c".into(), script.into()],
                profile: Profile::external_tool(vec![], vec![], dir.clone()),
                cwd: Some(dir.to_path_buf()),
                timeout,
                stdout_cap: cap,
                stderr_cap: cap,
                allow_reduced: true,
            },
            cancel,
        )
        .unwrap()
    }

    #[test]
    fn captures_output_with_cap() {
        let out = sh(
            "yes hello | head -c 100000; echo err >&2",
            Duration::from_secs(20),
            1000,
            &AtomicBool::new(false),
        );
        assert_eq!(out.status, Status::Exited(0));
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.stdout_truncated);
        assert_eq!(out.stderr_tail(), "err");
    }

    #[test]
    fn timeout_kills_process_group() {
        let t = Instant::now();
        // The grandchild `sleep` would keep stdout open if only sh were killed.
        let out = sh(
            "sleep 30 & sleep 30",
            Duration::from_millis(300),
            1000,
            &AtomicBool::new(false),
        );
        assert_eq!(out.status, Status::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn cancellation_stops_tool() {
        let cancel = AtomicBool::new(true);
        let out = sh("sleep 30", Duration::from_secs(60), 1000, &cancel);
        assert_eq!(out.status, Status::Cancelled);
    }

    #[test]
    fn bounded_respects_char_boundaries() {
        assert_eq!(bounded("ééé", 3), "é…");
        assert_eq!(bounded("abc", 3), "abc");
    }
}
