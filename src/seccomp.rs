//! Minimal fail-closed classic-BPF seccomp policy installed by bubblewrap.
//! A denylist is defense-in-depth, not a guarantee against kernel exploits.
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

pub fn write_filter(path: &Path) -> Result<File> {
    use libc::{BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
    const ALLOW: u32 = 0x7fff_0000;
    const KILL: u32 = 0x8000_0000;
    const ERRNO: u32 = 0x0005_0000;
    let deny = ERRNO | libc::EPERM as u32;

    let mut p = vec![
        stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 4), // seccomp_data.arch
        jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, AUDIT_ARCH, 1, 0),
        stmt((BPF_RET | BPF_K) as u16, KILL),
        stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 0), // syscall number
    ];
    // Restrict CLONE_NEW* flags while permitting ordinary threads/forks.
    let namespace_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWCGROUP) as u32;
    p.extend([
        jump(
            (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            libc::SYS_clone as u32,
            0,
            4,
        ),
        stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 16), // arg0 low 32 bits
        stmt((BPF_ALU | BPF_AND | BPF_K) as u16, namespace_flags),
        jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, 0),
        stmt((BPF_RET | BPF_K) as u16, deny),
        stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 0),
    ]);
    // clone3 should return ENOSYS, allowing glibc to fall back to clone.
    p.extend([
        jump(
            (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            libc::SYS_clone3 as u32,
            0,
            1,
        ),
        stmt((BPF_RET | BPF_K) as u16, ERRNO | libc::ENOSYS as u32),
    ]);
    let blocked: &[libc::c_long] = &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];
    for syscall in blocked {
        p.push(jump(
            (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            *syscall as u32,
            0,
            1,
        ));
        p.push(stmt((BPF_RET | BPF_K) as u16, deny));
    }
    p.push(stmt((BPF_RET | BPF_K) as u16, ALLOW));

    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating seccomp filter {}", path.display()))?;
    // sock_filter has a fixed Linux C layout: u16,u8,u8,u32.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            p.as_ptr().cast::<u8>(),
            p.len() * std::mem::size_of::<libc::sock_filter>(),
        )
    };
    file.write_all(bytes)?;
    file.rewind()?;
    // bubblewrap consumes the filter through an inherited descriptor.
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("configuring seccomp descriptor");
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filter_is_not_empty() {
        let temp = tempfile::tempdir().unwrap();
        let f = write_filter(&temp.path().join("seccomp.bpf")).unwrap();
        assert!(f.metadata().unwrap().len() > 64);
    }
}
