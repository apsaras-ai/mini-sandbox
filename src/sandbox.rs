//! One-request Linux sandbox. The host owns lifetime and cgroup cleanup.
//! A read-only rootfs is shared; each request gets a private quota-limited tmpfs.
use crate::protocol;
use crate::seccomp;
use crate::types::{ExecuteRequest, ExecuteResponse, MAX_BODY_BYTES};
use anyhow::{Context, Result, bail};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{error, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub data_dir: PathBuf,
    pub rootfs: PathBuf,
    pub cgroup_base: PathBuf,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub max_pids: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        let data_dir = std::env::var_os("MINI_SANDBOX_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/mini-sandbox"));
        let rootfs = std::env::var_os("MINI_SANDBOX_ROOTFS")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("rootfs"));
        Self {
            data_dir,
            rootfs,
            cgroup_base: PathBuf::from("/sys/fs/cgroup/mini-sandbox"),
            memory_bytes: 256 * 1024 * 1024,
            disk_bytes: 64 * 1024 * 1024,
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            max_pids: 64,
        }
    }
}

pub fn prerequisites(cfg: &SandboxConfig) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the sandbox service requires root for tmpfs and cgroup v2 setup");
    }
    for binary in [
        "usr/bin/python3",
        "usr/bin/node",
        "usr/local/bin/mini-sandbox",
    ] {
        if !cfg.rootfs.join(binary).is_file() {
            bail!("rootfs missing {binary}; run scripts/build-rootfs.sh");
        }
    }
    if !cfg
        .cgroup_base
        .parent()
        .unwrap_or(Path::new("/sys/fs/cgroup"))
        .join("cgroup.controllers")
        .is_file()
    {
        bail!("cgroup v2 unified hierarchy is required");
    }
    let bwrap = Command::new("bwrap")
        .arg("--version")
        .output()
        .context("bubblewrap (bwrap) is required on the host")?;
    if !bwrap.status.success() {
        bail!("bubblewrap --version failed");
    }
    Ok(())
}

pub fn acquire_service_lock(cfg: &SandboxConfig) -> Result<File> {
    fs::create_dir_all(&cfg.data_dir)?;
    fs::set_permissions(&cfg.data_dir, Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(cfg.data_dir.join("service.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error()).context("another mini-sandbox service is running");
    }
    Ok(lock)
}

fn configure_cgroup_base(cfg: &SandboxConfig) -> Result<()> {
    fs::create_dir_all(&cfg.cgroup_base)
        .context("creating cgroup base; check cgroup delegation")?;
    let controllers = fs::read_to_string(cfg.cgroup_base.join("cgroup.controllers"))?;
    for controller in ["cpu", "memory", "pids"] {
        if !controllers.split_whitespace().any(|c| c == controller) {
            bail!(
                "cgroup controller {controller} not delegated to {}",
                cfg.cgroup_base.display()
            );
        }
    }
    // Parent has no member processes; controllers propagate to child cgroups.
    let enabled = fs::read_to_string(cfg.cgroup_base.join("cgroup.subtree_control"))?;
    for controller in ["cpu", "memory", "pids"] {
        if !enabled.split_whitespace().any(|c| c == controller) {
            fs::write(
                cfg.cgroup_base.join("cgroup.subtree_control"),
                format!("+{controller}"),
            )
            .with_context(|| format!("enabling {controller} cgroup controller"))?;
        }
    }
    Ok(())
}

pub fn recover_orphans(cfg: &SandboxConfig) -> Result<()> {
    configure_cgroup_base(cfg)?;
    let runs = cfg.data_dir.join("runs");
    fs::create_dir_all(&runs)?;
    fs::set_permissions(&runs, Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(&runs)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let id = name.to_string_lossy();
        if Uuid::parse_str(&id).is_err() {
            warn!(sandbox_id = %id, "skipping unrecognized run directory");
            continue;
        }
        let mut sandbox = Sandbox {
            run_dir: entry.path(),
            workspace: entry.path().join("workspace"),
            ipc: entry.path().join("ipc"),
            cgroup: cfg.cgroup_base.join(id.as_ref()),
            child: None,
            mounted: true,
            ipc_mounted: true,
            cleaned: false,
        };
        sandbox
            .reap_orphan()
            .with_context(|| format!("reaping orphan {id}"))?;
    }
    Ok(())
}

pub fn execute(req: ExecuteRequest, cfg: &SandboxConfig) -> Result<ExecuteResponse> {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(req.timeout_ms);
    let mut sb = Sandbox::create(cfg)?;
    let response = sb.run(&req, deadline, started);
    let cleanup = sb.cleanup();
    match (response, cleanup) {
        (Ok(r), Ok(())) => Ok(r),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err.context("sandbox cleanup failed")),
        (Err(err), Err(clean_err)) => {
            error!(error = %clean_err, "sandbox cleanup failed after execution error");
            Err(err.context(format!("sandbox cleanup also failed: {clean_err}")))
        }
    }
}

struct Sandbox {
    run_dir: PathBuf,
    workspace: PathBuf,
    ipc: PathBuf,
    cgroup: PathBuf,
    child: Option<Child>,
    mounted: bool,
    ipc_mounted: bool,
    cleaned: bool,
}

impl Sandbox {
    fn create(cfg: &SandboxConfig) -> Result<Self> {
        prerequisites(cfg)?;
        let id = Uuid::new_v4().to_string();
        let run_dir = cfg.data_dir.join("runs").join(&id);
        let workspace = run_dir.join("workspace");
        let ipc = run_dir.join("ipc");
        let cgroup = cfg.cgroup_base.join(&id);
        fs::DirBuilder::new().mode(0o700).create(&run_dir)?;
        let mut guard = Self {
            run_dir,
            workspace,
            ipc,
            cgroup,
            child: None,
            mounted: false,
            ipc_mounted: false,
            cleaned: false,
        };
        fs::create_dir(&guard.workspace)?;
        fs::create_dir(&guard.ipc)?;
        let ipc_options = "size=1048576,mode=1777";
        mount(
            Some("tmpfs"),
            &guard.ipc,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some(ipc_options),
        )
        .context("mounting quota-limited IPC tmpfs")?;
        guard.ipc_mounted = true;
        let options = format!("size={},mode=1777", cfg.disk_bytes);
        mount(
            Some("tmpfs"),
            &guard.workspace,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some(options.as_str()),
        )
        .context("mounting quota-limited tmpfs")?;
        guard.mounted = true;
        fs::create_dir(&guard.cgroup).context("creating cgroup")?;
        fs::write(
            guard.cgroup.join("memory.max"),
            cfg.memory_bytes.to_string(),
        )?;
        fs::write(guard.cgroup.join("memory.swap.max"), "0")?;
        fs::write(guard.cgroup.join("memory.oom.group"), "1")?;
        fs::write(guard.cgroup.join("pids.max"), cfg.max_pids.to_string())?;
        fs::write(
            guard.cgroup.join("cpu.max"),
            format!("{} {}", cfg.cpu_quota_us, cfg.cpu_period_us),
        )?;
        guard.launch(cfg)?;
        Ok(guard)
    }

    fn launch(&mut self, cfg: &SandboxConfig) -> Result<()> {
        let filter = seccomp::write_filter(&self.run_dir.join("seccomp.bpf"))?;
        let log = File::create(self.run_dir.join("launcher.log"))?;
        let mut cmd = Command::new("bwrap");
        cmd.args([
            "--unshare-all",
            "--unshare-user",
            "--unshare-cgroup",
            "--disable-userns",
            "--assert-userns-disabled",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--hostname",
            "mini-sandbox",
            "--new-session",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/workspace",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--ro-bind",
        ]);
        cmd.arg(&cfg.rootfs).arg("/");
        cmd.args(["--proc", "/proc", "--dev", "/dev", "--dir", "/workspace"]);
        cmd.arg("--bind").arg(&self.workspace).arg("/workspace");
        cmd.args(["--dir", "/tmp"]);
        cmd.arg("--bind").arg(&self.workspace).arg("/tmp");
        cmd.args(["--dir", "/run", "--dir", "/run/mini-sandbox"]);
        cmd.arg("--bind").arg(&self.ipc).arg("/run/mini-sandbox");
        cmd.arg("--seccomp").arg(filter.as_raw_fd().to_string());
        cmd.args([
            "--chdir",
            "/workspace",
            "/usr/local/bin/mini-sandbox",
            "executor",
            "/run/mini-sandbox/executor.sock",
        ]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let child = cmd.spawn().context("launching bubblewrap")?;
        // The task is not dispatched until cgroup attachment and socket readiness.
        // bubblewrap setup can briefly run before attachment; production threat models
        // requiring atomic attachment should use clone3(CLONE_INTO_CGROUP).
        let pid = child.id();
        self.child = Some(child);
        fs::write(self.cgroup.join("cgroup.procs"), pid.to_string())
            .context("attaching launcher to cgroup")?;
        Ok(())
    }

    fn run(
        &mut self,
        req: &ExecuteRequest,
        deadline: Instant,
        started: Instant,
    ) -> Result<ExecuteResponse> {
        let socket = self.ipc.join("executor.sock");
        let startup_deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            if Instant::now() >= deadline {
                return Ok(ExecuteResponse::timeout(
                    started.elapsed().as_millis() as u64
                ));
            }
            if Instant::now() >= startup_deadline {
                bail!("executor startup timed out; see launcher.log");
            }
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    if let Some(status) = self
                        .child
                        .as_mut()
                        .map(|c| c.try_wait())
                        .transpose()?
                        .flatten()
                    {
                        bail!("bubblewrap exited before readiness with status {status}");
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(err) => return Err(err).context("connecting to executor"),
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        stream.set_write_timeout(Some(remaining.max(Duration::from_millis(1))))?;
        if let Err(err) = protocol::send_sync(&mut stream, req, MAX_BODY_BYTES) {
            if Instant::now() >= deadline {
                return Ok(ExecuteResponse::timeout(
                    started.elapsed().as_millis() as u64
                ));
            }
            return Err(err).context("sending executor request");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ExecuteResponse::timeout(
                started.elapsed().as_millis() as u64
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let result: Result<ExecuteResponse> = protocol::receive_sync(&mut stream, MAX_BODY_BYTES);
        match result {
            Ok(mut result) => {
                result.duration_ms = started.elapsed().as_millis() as u64;
                result.peak_memory_bytes = fs::read_to_string(self.cgroup.join("memory.peak"))
                    .ok()
                    .and_then(|x| x.trim().parse().ok())
                    .unwrap_or(0);
                result.oom_killed = self.oom_killed();
                Ok(result)
            }
            Err(_err) if Instant::now() >= deadline => Ok(ExecuteResponse::timeout(
                started.elapsed().as_millis() as u64,
            )),
            Err(err) => Err(err).context("receiving executor response"),
        }
    }

    fn oom_killed(&self) -> bool {
        fs::read_to_string(self.cgroup.join("memory.events"))
            .ok()
            .map(|content| {
                content.lines().any(|line| {
                    line.split_once(' ').is_some_and(|(key, n)| {
                        key == "oom_kill" && n.trim().parse::<u64>().unwrap_or(0) > 0
                    })
                })
            })
            .unwrap_or(false)
    }

    fn kill_cgroup(&self) -> Result<()> {
        if self.cgroup.exists() {
            fs::write(self.cgroup.join("cgroup.kill"), "1").context("cgroup.kill")?;
        }
        Ok(())
    }

    fn wait_empty(&self) -> Result<()> {
        if !self.cgroup.exists() {
            return Ok(());
        }
        for _ in 0..100 {
            let events = fs::read_to_string(self.cgroup.join("cgroup.events"))?;
            if events.lines().any(|line| line.trim() == "populated 0") {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        bail!("cgroup processes did not exit within 2 seconds");
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.kill_cgroup()?;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.wait_empty()?;
        if self.mounted {
            umount2(&self.workspace, MntFlags::empty()).context("unmounting workspace tmpfs")?;
            self.mounted = false;
        }
        if self.ipc_mounted {
            umount2(&self.ipc, MntFlags::empty()).context("unmounting IPC tmpfs")?;
            self.ipc_mounted = false;
        }
        if self.cgroup.exists() {
            fs::remove_dir(&self.cgroup).context("removing cgroup")?;
        }
        if self.run_dir.exists() {
            fs::remove_dir_all(&self.run_dir).context("removing run files")?;
        }
        self.cleaned = true;
        Ok(())
    }

    fn reap_orphan(&mut self) -> Result<()> {
        self.kill_cgroup()?;
        self.wait_empty()?;
        match umount2(&self.workspace, MntFlags::empty()) {
            Ok(()) => {}
            Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
            Err(err) => return Err(err).context("unmounting orphan workspace"),
        }
        self.mounted = false;
        match umount2(&self.ipc, MntFlags::empty()) {
            Ok(()) => {}
            Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
            Err(err) => return Err(err).context("unmounting orphan IPC"),
        }
        self.ipc_mounted = false;
        self.cleanup()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        if let Err(err) = self.cleanup() {
            error!(error = %err, run_dir = %self.run_dir.display(),
                "sandbox cleanup failed; orphan recovery required");
        }
    }
}
