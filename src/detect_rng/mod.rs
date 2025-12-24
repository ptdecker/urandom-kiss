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

use core::fmt::{self, Display};

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
    /// DRNG.
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
/// - CPU instruction-based detection (works without OS access).
#[cfg(all(target_os = "linux", target_arch = "x86"))]
#[must_use]
pub fn detect_rng() -> Option<RngType> {
    if x86_cpuid::has_rdseed() || x86_cpuid::has_rdrand() {
        return Some(RngType::X86Rdseed);
    }
    None;
}

/// Linux sysfs hwrng detection (OS-specific).
/// Implemented only for `x86_64` Linux here, using raw syscalls (no libc, no std).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[must_use]
pub fn detect_rng() -> Option<RngType> {
    linux_hwrng::detect_from_sysfs()
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn detect_rng() -> Option<RngType> {
    // 1) If we're on Intel macOS, CPUID is definitive and doesn't depend on sysctl visibility.
    #[cfg(all(target_os = "macos", any(target_arch = "x86", target_arch = "x86_64")))]
    if x86_cpuid::has_rdseed() || x86_cpuid::has_rdrand() {
        return Some(RngType::X86Rdseed);
    }

    // 2) macOS `sysctl` probes
    if let Some(t) = macos_rng::detect_via_sysctl() {
        return Some(t);
    }

    // 3) macOS-wide fallback: kernel CPRNG exists, but type attribution is not exposed.
    Some(RngType::MacosKernelCprng)
}

#[cfg(any(
    all(target_os = "macos", any(target_arch = "x86", target_arch = "x86_64")),
    all(target_os = "linux", target_arch = "x86"),
))]
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
    use core::{
        ffi::{c_char, c_int, c_void},
        mem::size_of,
    };

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
        // Require NUL-terminated; avoid unwrap to satisfy clippy::unwrap_used.
        match name_cstr.last() {
            | Some(&0) => {}
            | _ => return false,
        }

        let mut value: u32 = 0;
        let mut len: usize = size_of::<u32>();

        let rc = unsafe {
            sysctlbyname(
                name_cstr.as_ptr().cast::<c_char>(),
                core::ptr::from_mut(&mut value).cast::<c_void>(),
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
    use super::RngType;

    use core::{fmt, ptr, slice};

    /// Errors that may occur during RNG detection
    ///
    /// This module is intended to be `no_std` keeping the error surface small and allocation-free.
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum DetectError {
        /// OS call failed (platform-specific errno is provided when available).
        OsError(i32),
        /// Unexpected / malformed data (e.g., sysfs/sysctl content not in the expected format).
        ParseError,
        /// Unexpected / bounds check wrap
        InvalidLength,
    }

    impl core::fmt::Display for DetectError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                | Self::OsError(e) => write!(f, "OS error (errno={e})"),
                | Self::ParseError => write!(f, "parse error"),
                | Self::InvalidLength => write!(f, "invalid length"),
            }
        }
    }

    impl From<core::num::TryFromIntError> for DetectError {
        fn from(_: core::num::TryFromIntError) -> Self {
            Self::ParseError
        }
    }

    /// Convenience alias used throughout this module
    pub type Result<T> = core::result::Result<T, DetectError>;

    // Paths used by the Linux hwrng framework:
    // - /sys/devices/virtual/misc/hw_random/rng_current
    // - /sys/devices/virtual/misc/hw_random/rng_available
    // We prefer rng_current because it indicates the driver currently selected.
    const RNG_CURRENT: &[u8] = b"/sys/devices/virtual/misc/hw_random/rng_current\0";
    const RNG_AVAILABLE: &[u8] = b"/sys/devices/virtual/misc/hw_random/rng_available\0";

    pub fn detect_from_sysfs() -> Option<RngType> {
        // If rng_current exists and is readable, parse it.
        if let Ok(s) = read_small_cstr_file(RNG_CURRENT) {
            return Some(map_driver_name(s));
        }

        // Fall back to rng_available: if it lists anything, treat as hardware RNG present.
        if let Ok(s) = read_small_cstr_file(RNG_AVAILABLE) {
            if s.is_empty() {
                return None::<RngType>;
            }
            return Some(map_driver_name(s));
        }

        None
    }

    fn map_driver_name(s: &[u8]) -> RngType {
        // sysfs usually returns something like:
        // - "virtio_rng.0\n"
        // - "tpm-rng\n"
        // - other driver identifiers
        //
        // We do simple substring checks, case-sensitive.
        match () {
            | () if contains_subslice(s, b"virtio") => RngType::VirtioRng,
            | () if contains_subslice(s, b"tpm") => RngType::TpmRng,
            | () => RngType::Unknown,
        }
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Read a small sysfs file into a fixed buffer, trim trailing whitespace or newlines, and
    /// return the bytes slice (no allocation).
    fn read_small_cstr_file(path_cstr: &[u8]) -> Result<&'static [u8]> {
        const BUF_LEN: usize = 256;
        static mut BUF: [u8; 256] = [0u8; 256];

        // Get a raw pointer to the buffer without creating any references.
        let buf_ptr: *mut u8 = ptr::addr_of_mut!(BUF).cast::<u8>();

        let fd = sys_open_readonly(path_cstr)?;
        let n: usize = sys_read_raw(fd, buf_ptr, BUF_LEN)?.try_into()?;
        let _ = sys_close(fd);

        let trimmed: &[u8] = unsafe {
            trim_ascii_whitespace(
                slice::from_raw_parts(buf_ptr.cast_const(), BUF_LEN)
                    .get(..n)
                    .ok_or(DetectError::InvalidLength)?,
            )
        };

        Ok(unsafe { core::mem::transmute::<&[u8], &'static [u8]>(trimmed) })
    }

    const fn trim_ascii_whitespace(mut s: &[u8]) -> &[u8] {
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
    const fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\n' | b'\r' | b'\t')
    }

    // -------------------------------
    // Raw syscall wrappers (`x86_64`)
    // -------------------------------

    // `x86_64` Linux syscall numbers:
    const SYS_READ: isize = 0;
    const SYS_CLOSE: isize = 3;
    const SYS_OPENAT: isize = 257;

    /// Special value for `*at()` syscalls indicating that the pathname should be resolved relative
    /// to the process’s current working directory. When used as the `dirfd` argument (e.g., with
    /// `openat`), this causes the syscall to behave as if the non-`*at()` variant were used.
    const AT_FDCWD: isize = -100;

    // openat flags
    const O_RDONLY: isize = 0;
    const O_CLOEXEC: isize = 0o2_000_000;

    /// Open a filesystem path for reading using `openat(2)`.
    ///
    /// This is a minimal wrapper around the `openat` syscall, always invoked with `AT_FDCWD` and
    /// the flags `O_RDONLY | O_CLOEXEC`.
    ///
    /// # Parameters
    ///
    /// - `path_cstr`: A NUL-terminated path expressed as a byte slice. The slice **must** end in
    ///   `\0`; no validation of interior NULs is performed.
    ///
    /// # Return value
    ///
    /// On success, returns a file descriptor (`>= 0`).
    ///
    /// On failure, returns a [`DetectError`] derived from the syscall errno.
    ///
    /// # Errors
    ///
    /// - [`DetectError::ParseError`] if `path_cstr` is empty
    /// - [`DetectError::OsError`] if the syscall fails
    ///
    /// # Safety
    ///
    /// This function assumes:
    ///
    /// - `path_cstr` points to a valid, readable NUL-terminated string
    /// - The path remains valid for the duration of the syscall
    ///
    /// Violating these assumptions may result in undefined behavior at the kernel boundary.
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    fn sys_open_readonly(path_cstr: &[u8]) -> Result<isize> {
        if path_cstr.is_empty() || path_cstr.last().is_none() {
            return Err(DetectError::ParseError);
        }
        errno_result(syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            path_cstr.as_ptr() as isize,
            O_RDONLY | O_CLOEXEC,
            0,
        ))
    }

    /// Read bytes from a file descriptor into a raw buffer.
    ///
    /// This is a low-level wrapper around the `read(2)` syscall that operates on raw pointers
    /// instead of Rust references. This avoids creating references to `static mut` buffers and is
    /// compatible with Rust 2024 rules.
    ///
    /// # Parameters
    ///
    /// - `fd`: An open file descriptor
    /// - `buf`: Destination buffer pointer
    /// - `len`: Maximum number of bytes to read
    ///
    /// # Return value
    ///
    /// On success, returns the number of bytes read (`>= 0`).
    ///
    /// On failure, returns a [`DetectError`] derived from the syscall errno.
    ///
    /// # Safety
    ///
    /// The caller must guarantee:
    ///
    /// - `buf` is valid for writes of at least `len` bytes
    /// - `buf` is properly aligned
    /// - No aliasing violations occur while the syscall is in progress
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    fn sys_read_raw(fd: isize, buf: *mut u8, len: usize) -> Result<isize> {
        errno_result(syscall3(SYS_READ, fd, buf as isize, len.try_into()?))
    }

    /// Close a file descriptor.
    ///
    /// This is a thin wrapper around the `close(2)` syscall.
    ///
    /// # Parameters
    ///
    /// - `fd`: The file descriptor to close
    ///
    /// # Errors
    ///
    /// Returns a [`DetectError::OsError`] if the syscall fails.
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    fn sys_close(fd: isize) -> Result<()> {
        errno_result(syscall1(SYS_CLOSE, fd)).map(|_| ())
    }

    /// Convert a raw syscall return value into a `Result`.
    ///
    /// Linux syscalls return:
    ///
    /// - `>= 0` on success
    /// - `< 0` as `-errno` on failure
    ///
    /// This helper translates that convention into a Rust `Result`.
    ///
    /// # Parameters
    ///
    /// - `ret`: Raw syscall return value
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::OsError`] if `ret` is negative.
    ///
    /// # Notes
    ///
    /// This function does **not** perform any syscall itself; it purely interprets kernel return
    /// values
    #[inline]
    fn errno_result(ret: isize) -> Result<isize> {
        if ret < 0 { Err(DetectError::OsError(i32::try_from(-ret)?)) } else { Ok(ret) }
    }

    /// Perform a Linux `x86_64` system call with **one argument**.
    ///
    /// This is a thin, zero-overhead wrapper around the `syscall` instruction. It follows the
    /// Linux `x86_64` syscall ABI:
    ///
    /// - `rax` — syscall number (input) / return value (output)
    /// - `rdi` — first argument
    /// - `rcx`, `r11` — clobbered by the instruction
    ///
    /// # Parameters
    ///
    /// - `n`: The syscall number (e.g., `SYS_read`, `SYS_close`)
    /// - `a1`: First syscall argument
    ///
    /// # Return value
    ///
    /// Returns the raw syscall return value:
    ///
    /// - `>= 0` indicates success
    /// - `< 0` is `-errno`
    ///
    /// Callers are responsible for translating negative return values into structured errors.
    ///
    /// # Safety
    ///
    /// This function is inherently `unsafe` in behavior, even though it is not marked `unsafe` at
    /// the type level:
    ///
    /// - No validation is performed on the syscall number of arguments
    /// - Incorrect arguments can cause undefined behavior at the kernel boundary
    /// - The caller must uphold all syscall-specific invariants
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn syscall1(n: isize, a1: isize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// Perform a Linux `x86_64` system call with **three arguments**.
    ///
    /// Register assignment follows the Linux `x86_64` syscall ABI:
    ///
    /// - `rax` — syscall number / return value
    /// - `rdi` — argument 1
    /// - `rsi` — argument 2
    /// - `rdx` — argument 3
    ///
    /// # Parameters
    ///
    /// - `n`: The syscall number
    /// - `a1`: First syscall argument
    /// - `a2`: Second syscall argument
    /// - `a3`: Third syscall argument
    ///
    /// # Return value
    ///
    /// Returns the raw syscall result:
    ///
    /// - `>= 0` indicates success
    /// - `< 0` is `-errno`
    ///
    /// # Safety
    ///
    /// Same safety considerations as [`syscall1`]. This function performs no validation and
    /// directly crosses the user to kernel boundary.
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn syscall3(n: isize, a1: isize, a2: isize, a3: isize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// Perform a Linux `x86_64` system call with **four arguments**.
    ///
    /// Note that on `x86_64` Linux, the **fourth syscall argument must be passed in **`r10`**,
    /// not `rcx`. This wrapper handles that correctly.
    ///
    /// Register assignment:
    ///
    /// - `rax` — syscall number / return value
    /// - `rdi` — argument 1
    /// - `rsi` — argument 2
    /// - `rdx` — argument 3
    /// - `r10` — argument 4
    ///
    /// # Parameters
    ///
    /// - `n`: The syscall number
    /// - `a1`: First syscall argument
    /// - `a2`: Second syscall argument
    /// - `a3`: Third syscall argument
    /// - `a4`: Fourth syscall argument
    ///
    /// # Return value
    ///
    /// Returns the raw syscall result:
    ///
    /// - `>= 0` indicates success
    /// - `< 0` is `-errno`
    ///
    /// # Safety
    ///
    /// Same safety considerations as [`syscall1`]. Incorrect register usage, invalid pointers, or
    /// malformed arguments can result in undefined behavior.
    ///
    /// # Platform
    ///
    /// Linux **`x86_64` only**
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn syscall4(n: isize, a1: isize, a2: isize, a3: isize, a4: isize) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
            );
        }
        ret
    }
}
