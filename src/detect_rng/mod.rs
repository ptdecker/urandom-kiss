//! Best-effort identification of hardware-backed RNG mechanisms available to the current program.
//!
//! # What this module does
//!
//! This module attempts to detect the presence of *hardware-backed* random-number mechanisms and
//! classify them into a small set of known types (`RngType`). The detection is intentionally
//! best-effort and conservative: it reports what the current platform makes observable without
//! relying on allocation or `std`.
//!
//! # What this module does *not* do
//!
//! - It **does not prove** that the operating system RNG (e.g., `/dev/urandom`) has been seeded
//!   from any particular hardware source.
//! - It **does not measure entropy contribution** or verify that a kernel RNG is “fully seeded”.
//! - On some systems (notably macOS) the OS intentionally abstracts entropy sources; in such cases
//!   only coarse classifications are possible.
//!
//! # Platform behavior overview
//!
//! The implementation is selected at compile time via `cfg(...)`:
//!
//! - **`x86/x86_64` (all OSes):** CPU feature detection via `CPUID` is used to detect `RDSEED` and
//!   `RDRAND`.
//! - **macOS:** additional probing via `sysctlbyname` is used where applicable. If a specific
//!   mechanism cannot be identified, the function returns a macOS kernel RNG fallback
//!   (`RngType::MacosKernelCprng`) to indicate “hardware-backed but not attributable”.
//! - **Linux `x86_64`:** the Linux hwrng framework is probed via sysfs to detect drivers such as
//!   `virtio-rng` and TPM-based RNGs.
//!
//! # Const vs non-const API shape
//!
//! On **non-macOS** targets, `detect_rng()` is a `const fn`. This allows you to use it in
//! compile-time contexts when the detection path is purely CPU-feature based (e.g., `CPUID`) and/or
//! otherwise does not require OS calls.
//!
//! On **macOS**, `detect_rng()` is a regular `fn` because macOS detection may call into the OS
//! (`sysctlbyname`), which cannot be evaluated in a `const` context. A separate `cfg`-gated
//! definition is provided so callers can use `detect_rng()` uniformly on all targets.
//!
//! # Examples
//!
//! ```rust
//! use kiss_entropy::detect_rng;
//! let detected = detect_rng();
//! if let Some(kind) = detected {
//!     // e.g. "CPU hardware entropy generator (Intel/AMD RDSEED)" or "macOS kernel random number
//!     // generator (hardware-backed, source not exposed)"
//!     println!("{kind}");
//! }
//! ```

use super::fmt;

use core::fmt::Display;

/// Detected hardware RNG source/type (best-effort).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RngType {
    /// A hardware-backed RNG appears to be available, but the specific source cannot be identified.
    ///
    /// This is a best-effort classification used when the platform indicates “some hardware source
    /// exists” but does not provide a reliable way to name it.
    Unknown,
    /// CPU instruction-based random number generator (`RDRAND`) on Intel/AMD `x86/x86_64` CPUs.
    ///
    /// `RDRAND` produces random values from an on-CPU generator. It is typically suitable as a
    /// *random-number* source, but may not be the best choice when the caller specifically wants
    /// raw entropy.
    X86Rdrand,
    /// CPU instruction-based entropy seed generator (`RDSEED`) on Intel/AMD `x86/x86_64` CPUs.
    ///
    /// `RDSEED` is intended to provide seed material or entropy suitable for seeding a software
    /// DRAG.
    X86Rdseed,
    /// ARMv8.5-A `FEAT_RNG` (`RNDR`/`RNDRRS`) support on aarch64.
    ///
    /// If this is reported, the CPU provides random-number instructions. Many Apple Silicon
    /// generations (e.g., M1/M2) do **not** implement `FEAT_RNG`; on those machines this variant
    /// will typically not be returned.
    Aarch64FeatRng,
    /// macOS kernel random number generator (hardware-backed, but source attribution is not exposed).
    ///
    /// macOS provides a kernel RNG that is designed to be hardware-backed. However, macOS generally
    /// does not expose which hardware source(s) contribute entropy, so precise attribution is not
    /// possible using public interfaces.
    ///
    /// This variant is used as a **macOS fallback** (both Intel and Apple Silicon) when a more
    /// specific mechanism (e.g., `RDRAND`, `RDSEED`, or `FEAT_RNG`) cannot be identified.
    MacosKernelCprng,
    /// Linux hwrng framework reports a current RNG driver, but it was not mapped to a specific
    /// variant in this enum.
    LinuxHwrngCurrentDriver,
    /// Linux hwrng framework indicates a virtio-rng device (commonly used in virtual machines).
    VirtioRng,
    /// Linux hwrng framework indicates a TPM-backed RNG.
    TpmRng,
}

impl Display for RngType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Unknown => {
                write!(f, "hardware random number source present, but type is unknown")
            }
            | Self::X86Rdrand => {
                write!(f, "CPU hardware random number generator (Intel/AMD RDRAND)")
            }
            | Self::X86Rdseed => write!(f, "CPU hardware entropy generator (Intel/AMD RDSEED)"),
            | Self::Aarch64FeatRng => {
                write!(f, "ARM CPU hardware random number generator (RNDR instruction)")
            }
            | Self::MacosKernelCprng => write!(
                f,
                "macOS kernel random number generator (hardware-backed, source not exposed)"
            ),
            | Self::LinuxHwrngCurrentDriver => {
                write!(f, "Linux kernel hardware random number driver")
            }
            | Self::VirtioRng => {
                write!(f, "virtual machine hardware random number device (virtio-rng)")
            }
            | Self::TpmRng => {
                write!(f, "trusted platform module (TPM) hardware random number generator")
            }
        }
    }
}

/// Detect a hardware-backed RNG mechanism and classify it.
///
/// Returns `Some(RngType)` when a hardware-backed RNG mechanism is detected, or `None` when no
/// hardware-backed mechanism can be identified.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub const fn detect_rng() -> Option<RngType> {
    // 1) CPU instruction-based detection (works without OS access).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if x86_cpuid::has_rdseed() {
            return Some(RngType::X86Rdseed);
        }
        if x86_cpuid::has_rdrand() {
            return Some(RngType::X86Rdrand);
        }
    }

    // 2) macOS detection via sysctlbyname (OS-specific, no_std-friendly).
    #[cfg(target_os = "macos")]
    {
        if let Some(t) = macos_rng::detect_via_sysctl() {
            return Some(t);
        }
    }

    // 3) Linux sysfs hwrng detection (OS-specific).
    // Implemented only for x86_64 Linux here, using raw syscalls (no libc, no std).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        if let Some(t) = linux_hwrng::detect_from_sysfs()? {
            return Some(t);
        }
    }

    // Fallback
    None
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn detect_rng() -> Option<RngType> {
    // 1) If we're on Intel macOS, CPUID is definitive and doesn't depend on sysctl visibility.
    #[cfg(all(target_os = "macos", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        if x86_cpuid::has_rdseed() {
            return Some(RngType::X86Rdseed);
        }
        if x86_cpuid::has_rdrand() {
            return Some(RngType::X86Rdrand);
        }
    }

    // 2) macOS `sysctl` probes
    if let Some(t) = macos_rng::detect_via_sysctl() {
        return Some(t);
    }

    // 3) macOS-wide fallback: kernel CPRNG exists, but type attribution is not exposed.
    Some(RngType::MacosKernelCprng)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_cpuid {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::__cpuid;

    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::__cpuid;

    // CPUID.(EAX=1):ECX bit 30 = RDRAND
    const ECX_RDRAND_BIT: u32 = 1u32 << 30;

    // CPUID.(EAX=7,ECX=0):EBX bit 18 = RDSEED
    const EBX_RDSEED_BIT: u32 = 1u32 << 18;

    #[inline]
    pub fn has_rdrand() -> bool {
        // Safety: __cpuid is safe to call; it just executes CPUID.
        let r = unsafe { __cpuid(1) };
        (r.ecx & ECX_RDRAND_BIT) != 0
    }

    #[inline]
    pub fn has_rdseed() -> bool {
        // Safety: __cpuid is safe to call; it just executes CPUID.
        let r = unsafe { __cpuid(7) };
        (r.ebx & EBX_RDSEED_BIT) != 0
    }
}

#[cfg(target_os = "macos")]
mod macos_rng {
    use super::RngType;
    use core::ffi::{c_char, c_int, c_void};

    // sysctlbyname signature (from <sys/sysctl.h>):
    // int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }

    // Intel macOS probes:
    const HW_OPTIONAL_RDRAND: &[u8] = b"hw.optional.rdrand\0";
    const HW_OPTIONAL_RDSEED: &[u8] = b"hw.optional.rdseed\0";

    // Apple Silicon probe for ARM FEAT_RNG (RNDR). This key is used by widely-deployed CPU feature
    // detectors on darwin/arm64.
    const HW_OPTIONAL_ARM_FEAT_RNG: &[u8] = b"hw.optional.arm.FEAT_RNG\0";

    #[inline]
    pub fn detect_via_sysctl() -> Option<RngType> {
        // On Intel Macs, these sysctls typically exist. Prefer `RDSEED` over `RDRAND` when both are
        // present.
        if sysctl_u32_eq_1(HW_OPTIONAL_RDSEED) {
            return Some(RngType::X86Rdseed);
        }
        if sysctl_u32_eq_1(HW_OPTIONAL_RDRAND) {
            return Some(RngType::X86Rdrand);
        }

        // On Apple Silicon, detect ARM `FEAT_RNG` (`RNDR` instructions).
        if sysctl_u32_eq_1(HW_OPTIONAL_ARM_FEAT_RNG) {
            return Some(RngType::Aarch64FeatRng);
        }

        None
    }

    #[inline]
    fn sysctl_u32_eq_1(name_cstr: &[u8]) -> bool {
        use core::ffi::{c_char, c_void};

        // Require NUL-terminated; avoid unwrap to satisfy clippy::unwrap_used.
        match name_cstr.last() {
            | Some(&0) => {}
            | _ => return false,
        }

        let mut value: u32 = 0;
        let mut len: usize = size_of::<u32>();

        // Use from_mut to produce *mut T without `as`, then cast to *mut c_void.
        let oldp: *mut c_void = core::ptr::from_mut(&mut value).cast::<c_void>();

        let rc = unsafe {
            sysctlbyname(
                name_cstr.as_ptr().cast::<c_char>(),
                oldp,
                &raw mut len,
                core::ptr::null_mut(),
                0,
            )
        };

        rc == 0 && len == size_of::<u32>() && value == 1
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_hwrng {
    use super::{DetectError, RngType};

    /// Errors that may occur during RNG detection.
    ///
    /// This module is intended to be `no_std`, so we keep the error surface small and allocation-free.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum DetectError {
        /// OS call failed (platform-specific errno is provided when available).
        OsError(i32),
        /// Unexpected / malformed data (e.g., sysfs/sysctl content not in the expected format).
        ParseError,
    }

    impl core::fmt::Display for DetectError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                | DetectError::OsError(e) => write!(f, "OS error (errno={e})"),
                | DetectError::ParseError => write!(f, "parse error"),
            }
        }
    }

    /// Convenience alias used throughout this module.
    pub type Result<T> = core::result::Result<T, DetectError>;

    // Paths used by the Linux hwrng framework:
    // - /sys/devices/virtual/misc/hw_random/rng_current
    // - /sys/devices/virtual/misc/hw_random/rng_available
    // We prefer rng_current because it indicates the driver currently selected.

    const RNG_CURRENT: &[u8] = b"/sys/devices/virtual/misc/hw_random/rng_current\0";
    const RNG_AVAILABLE: &[u8] = b"/sys/devices/virtual/misc/hw_random/rng_available\0";

    pub fn detect_from_sysfs() -> Result<Option<RngType>> {
        // If rng_current exists and is readable, parse it.
        if let Ok(s) = read_small_cstr_file(RNG_CURRENT) {
            if let Some(t) = map_driver_name(s) {
                return Ok(Some(t));
            }
            // If it exists but doesn't match known names, it's still evidence of hwrng presence.
            if !s.is_empty() {
                return Ok(Some(RngType::LinuxHwrngCurrentDriver));
            }
        }

        // Fall back to rng_available: if it lists anything, treat as hardware RNG present.
        if let Ok(s) = read_small_cstr_file(RNG_AVAILABLE) {
            if s.is_empty() {
                return Ok(None::<RngType>);
            }
            // If it mentions a known driver, return it; otherwise Unknown.
            if let Some(t) = map_driver_name(s) {
                return Ok(Some(t));
            }
            return Ok(Some(RngType::Unknown));
        }

        Ok(None)
    }

    fn map_driver_name(s: &[u8]) -> Option<RngType> {
        // sysfs usually returns something like:
        // - "virtio_rng.0\n"
        // - "tpm-rng\n"
        // - other driver identifiers
        //
        // We do simple substring checks, case-sensitive.
        if contains_subslice(s, b"virtio") {
            return Some(RngType::VirtioRng);
        }
        if contains_subslice(s, b"tpm") {
            return Some(RngType::TpmRng);
        }
        None
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Read a small sysfs file into a fixed buffer, trim trailing whitespace/newlines,
    /// and return the bytes slice (no allocation).
    fn read_small_cstr_file(path_cstr: &[u8]) -> Result<&'static [u8]> {
        // This function uses a static buffer to stay no_std + no_alloc.
        // This is not re-entrant/thread-safe; if you need that, pass in a caller buffer instead.
        //
        // If you'd prefer re-entrant behavior, replace this with:
        //   fn read_small_cstr_file_into(path, buf: &mut [u8]) -> Result<&[u8]>
        static mut BUF: [u8; 256] = [0u8; 256];

        let fd = sys_open_readonly(path_cstr)?;
        let n = sys_read(fd, unsafe { &mut BUF })?;
        let _ = sys_close(fd);

        let trimmed = trim_ascii_whitespace(unsafe { &BUF[..n] });
        // Return as static lifetime because BUF is static. Caller must treat it as ephemeral.
        Ok(unsafe { core::mem::transmute::<&[u8], &'static [u8]>(trimmed) })
    }

    fn trim_ascii_whitespace(mut s: &[u8]) -> &[u8] {
        while let Some((&b, rest)) = s.split_first() {
            if !is_ws(b) {
                break;
            }
            s = rest;
        }
        while let Some((&b, rest)) = s.split_last() {
            if !is_ws(b) {
                break;
            }
            s = rest;
        }
        s
    }

    #[inline]
    fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\n' | b'\r' | b'\t')
    }

    // ---------------------------
    // Raw syscall wrappers (x86_64)
    // ---------------------------

    // x86_64 Linux syscall numbers:
    const SYS_READ: usize = 0;
    const SYS_CLOSE: usize = 3;
    const SYS_OPENAT: usize = 257;

    const AT_FDCWD: isize = -100;

    // openat flags
    const O_RDONLY: usize = 0;
    const O_CLOEXEC: usize = 0o2_000_000;

    fn sys_open_readonly(path_cstr: &[u8]) -> Result<usize> {
        // path_cstr must be NUL-terminated.
        if path_cstr.is_empty() || *path_cstr.last().unwrap() != 0 {
            return Err(DetectError::ParseError);
        }
        let fd = syscall4(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path_cstr.as_ptr() as usize,
            (O_RDONLY | O_CLOEXEC) as usize,
            0,
        );
        errno_result(fd).map(|v| v as usize)
    }

    fn sys_read(fd: usize, buf: &mut [u8]) -> Result<usize> {
        let n = syscall3(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len());
        errno_result(n).map(|v| v as usize)
    }

    fn sys_close(fd: usize) -> Result<()> {
        let r = syscall1(SYS_CLOSE, fd);
        errno_result(r).map(|_| ())
    }

    #[inline]
    fn errno_result(ret: isize) -> Result<isize> {
        if ret < 0 {
            // Linux syscalls return -errno.
            Err(DetectError::OsError((-ret) as i32))
        } else {
            Ok(ret)
        }
    }

    #[inline(always)]
    fn syscall1(n: usize, a1: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1 as isize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }

    #[inline(always)]
    fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1 as isize,
            in("rsi") a2 as isize,
            in("rdx") a3 as isize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }

    #[inline(always)]
    fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1 as isize,
            in("rsi") a2 as isize,
            in("rdx") a3 as isize,
            in("r10") a4 as isize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }
}
