# mini-sandbox

Single-use Linux code-execution sandbox for **trusted internal Agent deployments**.
Rust + Tokio + Axum. Runs Python 3 and Node.js in a fresh sandbox for each
`POST /execute` request, then tears down every child process and writable mount.

**Not a public multi-tenant security boundary.** bubblewrap namespaces and a
seccomp denylist reduce exposure, but do not provide VM-grade kernel isolation.

## Architecture

`HTTP -> validate + semaphore -> cgroup v2 -> bubblewrap namespace -> Unix socket -> executor -> teardown`

Each run gets:
- Read-only Ubuntu 24.04 root filesystem, shared only for read access
- Private 64 MiB tmpfs mounted at both `/workspace` and `/tmp` (noexec, nosuid, nodev)
- Isolated user, PID, mount, UTS, IPC, network, and cgroup namespaces
- Unprivileged uid/gid 65534, dropped capabilities, bubblewrap's no-new-privileges
  model, a seccomp BPF denylist including namespace creation
- cgroup v2 limits (256 MiB memory with swap disabled, 1 CPU, 64 PIDs)
- A separate per-request bind-mounted IPC directory, not the overlay upper layer
- Host-owned timeout and `cgroup.kill`, including lingering background processes
- Max 128 KiB code, 512 KiB input files, 128 KiB combined stdout/stderr,
  2 MiB HTTP/protocol body, and 30 second maximum execution deadline

No external network by default. There is **no unsafe non-sandbox fallback**.

## Prerequisites and rootfs

Linux with cgroup v2 and delegated `cpu`, `memory`, `pids` controllers,
root privileges (for mount/cgroup), bubblewrap (`bwrap`), Docker (to build
the rootfs), and Rust (to build the host service). For example on Ubuntu 24.04:

```bash
sudo apt-get install -y bubblewrap docker.io curl
sudo bash scripts/build-rootfs.sh
cargo test --all-targets
cargo build --release
sudo ./target/release/mini-sandbox
```

The Dockerfile builds the **same Rust binary** into the rootfs using Debian
Bookworm glibc and includes Python 3 and Node.js. The host binary can be built
separately. The build script refuses to overwrite an existing rootfs.

The host needs permission to create and write under `/sys/fs/cgroup/mini-sandbox`.
In environments with systemd delegation restrictions or where user namespaces
are denied by security policy, the service **fails closed** rather than running
code without isolation. Use a disposable Linux VM for initial deployment;
do not expose this privileged service to the Internet.

The service binds to `127.0.0.1:3000` by default, and accepts:
`MINI_SANDBOX_LISTEN`, `MINI_SANDBOX_MAX_CONCURRENCY`,
`MINI_SANDBOX_DATA_DIR`, `MINI_SANDBOX_ROOTFS`.

## API

```bash
curl -sS http://127.0.0.1:3000/execute \
  -H 'content-type: application/json' \
  -d '{"language":"python","code":"print(1 + 1)","timeout_ms":5000,"files":[{"path":"input.txt","content":"aGVsbG8="}],"env_vars":[["GREETING","hello"]]}'
```

Input file `content` is standard Base64. `env_vars` is a list of name/value
pairs. Reserved runtime/loader variables are rejected. File paths must be
relative and cannot traverse outside the private workspace. Each request
starts a new sandbox.

Successful execution HTTP response (including nonzero code exit):
```json
{
  "stdout": "2\n",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 140,
  "timed_out": false,
  "peak_memory_bytes": 12000000,
  "output_truncated": false,
  "oom_killed": false
}
```

HTTP 400: invalid request; 429: max concurrency reached; 503: sandbox setup,
executor communication, or teardown failure. `/healthz` checks HTTP process
liveness; `/readyz` checks basic host prerequisites.

```bash
bash scripts/smoke-linux.sh
```

## Operational notes / security boundaries

1. A privileged host service is **not** safe to expose publicly. Put it behind
   an authenticated internal Agent service, with its own request quotas.
2. cgroup attachment happens immediately after spawning bubblewrap, **not
   atomically in clone3**. User code is never dispatched before attachment,
   but bubblewrap setup may momentarily run outside limits. This needs a
   stronger launcher for hostile multi-tenant use.
3. Seccomp is a denylist, not a complete syscall allowlist. The service uses
   the host Linux kernel. For untrusted Internet code, reevaluate against
   microVMs (Firecracker, Kata) and independent security review.
4. All cleanup paths kill the cgroup, wait for it to empty, unmount tmpfs,
   remove the cgroup, and delete the run directory. Startup reaps orphaned
   run directories after a previous crash. Cleanup failures are logged and
   fail the request instead of pretending the run was cleaned.
5. Running jobs stay alive until their host deadline even if the HTTP client
   disconnects; the background worker retains its concurrency permit and
   always executes cleanup. SIGINT/SIGTERM drain in-flight Axum requests.
6. `cargo test` is only unit coverage. Linux integration testing requires
   privileged host facilities and should additionally exercise OOM, fork
   bombs, background process cleanup, filesystem isolation, network denial,
   and forced service termination before claiming production readiness.

## Linux end-to-end acceptance

After building the rootfs and starting the service on an appropriately privileged
Linux host, run `python3 scripts/acceptance-linux.py`. It checks success/failure,
Python/Node, file and environment injection, deadlines, output overflow, disk
quota, network denial, request validation, cross-run isolation, background process
cleanup, overload and cgroup OOM. Run the service with
`MINI_SANDBOX_MAX_CONCURRENCY=1` for the overload assertion. GitHub Actions also
contains a Linux integration workflow; if the hosted runner lacks delegated
cgroup or namespace privileges, treat that as an environment limitation rather
than bypassing the checks.
