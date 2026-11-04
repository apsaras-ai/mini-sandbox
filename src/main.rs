#[cfg(not(target_os = "linux"))]
compile_error!("mini-sandbox supports Linux hosts only");

use anyhow::{Context, Result};
use mini_sandbox::{api, executor, sandbox::SandboxConfig};
use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::info;

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mini_sandbox=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    if let Some(mode) = args.next() {
        if mode != "executor" {
            anyhow::bail!("usage: mini-sandbox [executor /run/mini-sandbox/executor.sock]");
        }
        let socket = args.next().context("executor socket path required")?;
        if args.next().is_some() {
            anyhow::bail!("unexpected extra arguments");
        }
        return executor::serve(&PathBuf::from(socket)).await;
    }

    let cfg = SandboxConfig::default();
    mini_sandbox::sandbox::prerequisites(&cfg)?;
    let _service_lock = mini_sandbox::sandbox::acquire_service_lock(&cfg)?;
    mini_sandbox::sandbox::recover_orphans(&cfg)?;
    let max_concurrency = std::env::var("MINI_SANDBOX_MAX_CONCURRENCY")
        .ok()
        .and_then(|n| n.parse::<usize>().ok())
        .filter(|n| (1..=128).contains(n))
        .unwrap_or(4);
    let addr = std::env::var("MINI_SANDBOX_LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, max_concurrency, "mini-sandbox service ready");
    axum::serve(listener, api::router(cfg, max_concurrency))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
