//! Does an open `/dev/kvm` run a guest of this build's architecture?
//!
//! QEMU user mode passes the open of `/dev/kvm` and its ioctls to the
//! kernel of the host. In an arm64 container on an x86_64 host the device
//! opens and answers, but runs no aarch64 guest (PodUtils/podvm#407). After
//! the open: `KVM_GET_API_VERSION`, `KVM_CREATE_VM`, then one ioctl that only
//! the KVM of the build's architecture answers.

use crate::sys::{self, Errno};
use crate::verdict::{Outcome, Verdict};

const KVMIO: u64 = 0xAE;

/// `_IO(KVMIO, nr)`: the generic encoding of x86 and arm64.
const fn io(nr: u64) -> u64 {
    (KVMIO << 8) | nr
}

/// `_IOC(dir, KVMIO, nr, size)`: dir 2 is read, 3 is read and write.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (KVMIO << 8) | nr
}

const KVM_GET_API_VERSION: u64 = io(0x00);
const KVM_CREATE_VM: u64 = io(0x01);
/// The version that each KVM since Linux 2.6.22 answers.
const KVM_API_VERSION: i64 = 12;

/// `_IOWR(KVMIO, 0x05, struct kvm_cpuid2)` on the system descriptor: the
/// header is 8 bytes (`nent`, `padding`).
#[cfg(target_arch = "x86_64")]
const KVM_GET_SUPPORTED_CPUID: u64 = ioc(3, 0x05, 8);
/// `_IOR(KVMIO, 0xaf, struct kvm_vcpu_init)` on the VM descriptor: a target
/// and seven feature words, 32 bytes.
#[cfg(target_arch = "aarch64")]
const KVM_ARM_PREFERRED_TARGET: u64 = ioc(2, 0xaf, 32);

fn ioctl(fd: i64, request: u64, arg: u64) -> Result<i64, Errno> {
    // SAFETY: each request below writes at most the buffer that `arg`
    // points to, and that buffer lives past the call.
    unsafe { sys::sys(sys::SYS_IOCTL, [fd as u64, request, arg, 0, 0, 0]) }
}

/// The architecture's own question, on the system descriptor `kvm` and the
/// VM descriptor `vm`. `None`: this build has no such question, and the open
/// alone answers.
fn native_question(kvm: i64, vm: i64) -> Option<Result<i64, Errno>> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = vm;
        // A header with no entry: the KVM of x86 answers E2BIG (too small),
        // which is a yes.
        let mut cpuid = [0u32; 2];
        return Some(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid.as_mut_ptr() as u64));
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = kvm;
        let mut init = [0u32; 8];
        return Some(ioctl(vm, KVM_ARM_PREFERRED_TARGET, init.as_mut_ptr() as u64));
    }
    #[allow(unreachable_code)]
    {
        let _ = (kvm, vm);
        None
    }
}

/// The verdict of the leg on an open device `fd`. Each descriptor that it
/// opens, it closes.
pub(super) fn runs_native_guest(fd: i64) -> Outcome {
    let api = ioctl(fd, KVM_GET_API_VERSION, 0);
    let vm = match api {
        Ok(KVM_API_VERSION) => ioctl(fd, KVM_CREATE_VM, 0),
        _ => return verdict(api, Err(sys::EINVAL), None),
    };
    let question = match vm {
        Ok(vm_fd) => {
            let q = native_question(fd, vm_fd);
            let _ = sys::close(vm_fd);
            q
        }
        Err(_) => None,
    };
    verdict(api, vm, question)
}

/// The verdict from the answers: the API version, the new VM, and the
/// architecture's question (`None` where the build has none).
pub(super) fn verdict(
    api: Result<i64, Errno>,
    vm: Result<i64, Errno>,
    question: Option<Result<i64, Errno>>,
) -> Outcome {
    let no = |errno: Errno, reason: String| Outcome { verdict: Verdict::Denied, errno: Some(errno), reason };
    match api {
        Err(e) => return no(e, "KVM_GET_API_VERSION failed".to_string()),
        Ok(v) if v != KVM_API_VERSION => {
            return no(sys::EINVAL, format!("KVM_GET_API_VERSION answered {v}, not {KVM_API_VERSION}"));
        }
        Ok(_) => {}
    }
    if let Err(e) = vm {
        return no(e, "KVM_CREATE_VM failed".to_string());
    }
    match question {
        None | Some(Ok(_)) => Outcome::ok(),
        Some(Err(e)) if e == sys::E2BIG => Outcome::ok(),
        Some(Err(e)) if e == sys::ENOTTY || e == sys::EINVAL => {
            no(e, format!("the device runs no guest of {} (QEMU user mode?)", std::env::consts::ARCH))
        }
        Some(Err(e)) => no(e, format!("the question of {} to KVM failed", std::env::consts::ARCH)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encodings of the kernel's headers.
    #[test]
    fn the_requests_are_the_kernel_numbers() {
        assert_eq!(KVM_GET_API_VERSION, 0xAE00);
        assert_eq!(KVM_CREATE_VM, 0xAE01);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(KVM_GET_SUPPORTED_CPUID, 0xC008_AE05);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(KVM_ARM_PREFERRED_TARGET, 0x8020_AEAF);
    }

    /// A device of the build's architecture is a yes; one that refuses the
    /// architecture's question with ENOTTY or EINVAL is a no, with the reason.
    #[test]
    fn a_device_of_another_architecture_is_a_no_with_the_reason() {
        let ok = |v| Ok::<i64, Errno>(v);
        assert_eq!(verdict(ok(12), ok(5), Some(ok(0))).verdict, Verdict::Ok);
        assert_eq!(verdict(ok(12), ok(5), Some(Err(sys::E2BIG))).verdict, Verdict::Ok);
        assert_eq!(verdict(ok(12), ok(5), None).verdict, Verdict::Ok);
        for e in [sys::ENOTTY, sys::EINVAL] {
            let out = verdict(ok(12), ok(5), Some(Err(e)));
            assert_eq!((out.verdict, out.errno), (Verdict::Denied, Some(e)));
            assert!(out.reason.contains("runs no guest of") && out.reason.contains("QEMU user mode"), "{}", out.reason);
        }
        let out = verdict(Err(sys::ENOTTY), Err(sys::EINVAL), None);
        assert_eq!(out.verdict, Verdict::Denied);
        assert!(out.reason.contains("KVM_GET_API_VERSION"), "{}", out.reason);
        let out = verdict(ok(11), Err(sys::EINVAL), None);
        assert!(out.reason.contains("answered 11"), "{}", out.reason);
        let out = verdict(ok(12), Err(sys::EPERM), None);
        assert_eq!(out.errno, Some(sys::EPERM));
        assert!(out.reason.contains("KVM_CREATE_VM"), "{}", out.reason);
    }
}
