use crate::protocol;
use crate::types::{ExecuteRequest, ExecuteResponse, MAX_BODY_BYTES, MAX_OUTPUT_BYTES};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::task::JoinHandle;

pub async fn serve(socket: &Path) -> Result<()> {
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("binding executor socket {}", socket.display()))?;
    let (mut stream, _) = listener.accept().await?;
    let req: ExecuteRequest = protocol::receive(&mut stream, MAX_BODY_BYTES).await?;
    req.validate()?;
    let result = execute(&req, Path::new("/workspace")).await?;
    protocol::send(&mut stream, &result, MAX_BODY_BYTES).await?;
    Ok(())
}

async fn read_capped<R: AsyncRead + Unpin>(
    mut reader: R,
    used: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> Vec<u8> {
    let mut collected = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let prior = used.fetch_add(n, Ordering::Relaxed);
                let remaining = MAX_OUTPUT_BYTES.saturating_sub(prior);
                collected.extend_from_slice(&chunk[..n.min(remaining)]);
                if n > remaining {
                    exceeded.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    collected
}

async fn collect(mut task: JoinHandle<Vec<u8>>) -> Vec<u8> {
    match tokio::time::timeout(Duration::from_millis(300), &mut task).await {
        Ok(Ok(buf)) => buf,
        _ => {
            task.abort();
            Vec::new()
        }
    }
}

pub async fn execute(req: &ExecuteRequest, workspace: &Path) -> Result<ExecuteResponse> {
    req.validate()?;
    let script = if req.language == "python" {
        workspace.join("__mini_sandbox_main__.py")
    } else {
        workspace.join("__mini_sandbox_main__.js")
    };
    for file in &req.files {
        let target = workspace.join(&file.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, &file.content)?;
    }
    std::fs::write(&script, &req.code)?;
    let start = Instant::now();
    let (program, args): (&str, &[&str]) = if req.language == "python" {
        ("/usr/bin/python3", &["-B", "-u"])
    } else {
        ("/usr/bin/node", &[])
    };
    let mut cmd = Command::new(program);
    cmd.args(args)
        .arg(&script)
        .current_dir(workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/workspace")
        .env("TMPDIR", "/tmp")
        .env("LANG", "C.UTF-8")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in &req.env_vars {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().context("starting language interpreter")?;
    let used = Arc::new(AtomicUsize::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout = tokio::spawn(read_capped(
        child.stdout.take().expect("stdout configured as piped"),
        used.clone(),
        exceeded.clone(),
    ));
    let stderr = tokio::spawn(read_capped(
        child.stderr.take().expect("stderr configured as piped"),
        used,
        exceeded.clone(),
    ));
    let exit = loop {
        if exceeded.load(Ordering::Relaxed) {
            let _ = child.start_kill();
            break child.wait().await?;
        }
        if let Some(exit) = child.try_wait()? {
            break exit;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let stdout = collect(stdout).await;
    let stderr = collect(stderr).await;
    Ok(ExecuteResponse {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code: exit.code().unwrap_or(-1),
        duration_ms: start.elapsed().as_millis() as u64,
        timed_out: false,
        peak_memory_bytes: 0,
        output_truncated: exceeded.load(Ordering::Relaxed),
        oom_killed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(language: &str, code: &str) -> ExecuteRequest {
        ExecuteRequest {
            language: language.into(),
            code: code.into(),
            timeout_ms: 3000,
            files: vec![],
            env_vars: vec![],
        }
    }

    #[tokio::test]
    async fn python_success_and_nonzero_exit() {
        let temp = tempfile::tempdir().unwrap();
        let success = execute(&request("python", "print('ok')"), temp.path()).await.unwrap();
        assert_eq!(success.exit_code, 0);
        assert_eq!(success.stdout.trim(), "ok");
        let fail = execute(&request("python", "raise ValueError('bad')"), temp.path()).await.unwrap();
        assert_ne!(fail.exit_code, 0);
        assert!(fail.stderr.contains("ValueError"));
    }

    #[tokio::test]
    async fn node_and_file_input() {
        let temp = tempfile::tempdir().unwrap();
        let mut req = request("node", "console.log(require('fs').readFileSync('x.txt','utf8'))");
        req.files.push(crate::types::FileInput { path: "x.txt".into(), content: b"loaded".to_vec() });
        let result = execute(&req, temp.path()).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "loaded");
    }

    #[tokio::test]
    async fn output_cap_is_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let res = execute(&request("python", "print('x' * 200000)"), temp.path()).await.unwrap();
        assert!(res.output_truncated);
        assert!(res.stdout.len() <= MAX_OUTPUT_BYTES);
    }
}
