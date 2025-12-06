//! Core wrapper around /dev/urandom
//!
//! Platform Support
//! - Currently, this module only supports Linux and macOS

mod error;

use super::fmt;

use core::ffi::{c_char, c_int, c_void};

pub use error::Error;

/// File descriptor flag for read-only access
const O_RDONLY: c_int = 0;

/// File descriptor flag for close-on-exec behavior
///
/// # Platform Notes
/// - Both Linux and macOS define `O_CLOEXEC`, but value differs. When expanding this module to
///   support other targets, consider avoiding `O_CLOEXEC` entirely for maximum portability. Or,
///   continue implementing platform specific values
#[cfg(target_os = "linux")]
const O_CLOEXEC: c_int = 0x0008_0000;
#[cfg(target_os = "macos")]
const O_CLOEXEC: c_int = 0x0100_0000;

/// Path to the system's random device
///
/// # Safety
/// - `URANDOM_PATH` is a valid null-terminated C string
const URANDOM_PATH: &[u8] = b"/dev/urandom\0";

unsafe extern "C" {
    /// Opens a file descriptor
    fn open(path: *const c_char, oflag: c_int, ...) -> c_int;
    /// Reads from a file descriptor
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    /// Closes a file descriptor
    fn close(fd: c_int) -> c_int;
}

/// Fills the provided buffer with cryptographically secure random bytes sourced directly from
/// `/dev/urandom`.
///
/// # Overview
///
/// This function opens `/dev/urandom`, repeatedly calls the `read(2)` system call, and writes
/// random bytes into the caller-provided `buf`. The loop continues until the entire buffer is
/// filled.
///
/// Even though `/dev/urandom` is a *virtual* infinite stream of random bytes and never "runs out,"
/// the POSIX `read(2)` interface **does not guarantee** that a single call will return the full
/// number of bytes requested. This is true for *all* file descriptors, including urandom. Because
/// of this, the function uses a loop to accumulate the full buffer contents.
///
/// # Arguments
/// * `buf` - The buffer to fill with random bytes
///
/// # Errors
/// Returns `UrandomError` if:
/// - Failed to open /dev/urandom
/// - Failed to read from file descriptor
/// - Got incomplete read from /dev/urandom
/// - As system call returns an unexpected value that is out of range, negative, or would overflow
///   if incremented and thus cause a panic situation.
///
/// # Safety
/// - `URANDOM_PATH` is a valid null-terminated C string
/// - Calling `open(2)` is `unsafe` because:
///   - It crosses an FFI boundary into libc to invoke the OS `open` syscall.
///   - Rust cannot guarantee that the pointer to the path string is valid or null-terminated.
///   - Rust cannot ensure that the flags passed to `open(2)` are correct for the platform.
///   - The OS may return any file descriptor number, including low integers, which can violate
///     assumptions if not handled carefully.
///   - The syscall may fail or return `-1`, and failure must be checked manually.
///   - This function ensures safety by:
///     - Supplying a statically known, null-terminated byte string as the path.
///     - Passing only valid and platform-appropriate flags (`O_RDONLY`).
///     - Checking the return value to ensure:
///       - it is non-negative, and
///       - represents a valid, newly opened file descriptor.
///     - Not exposing raw FDs to callers, preventing misuse and double management.
///   - As long as these invariants are upheld, the `unsafe` usage is sound.
/// - Calling `read(2)` is `unsafe` because:
///   - It crosses an FFI boundary into libc to invoke the OS `read` syscall.
///   - Rust cannot ensure the pointer (`buf.as_mut_ptr()`) is valid for writes.
///   - Rust cannot confirm the length passed to `read()` matches the actual buffer size.
///   - The operating system may return partial reads or errors, which must be handled correctly.
///   - The syscall writes arbitrary bytes into the buffer, so aliasing and bounds rules must be
///     correct.
///  - This function ensures safety by:
///    - The implementation guarantees that `buf.as_mut_ptr()` points to a valid, mutable slice.
///    - The length passed to `read(2)` is exactly `buf.len()`.
///    - The result of the syscall is checked to confirm that it:
///      - did not return a negative value, and
///      - wrote exactly the expected number of bytes.
///    - No concurrent aliasing of the buffer is possible.
///  - As long as these invariants are upheld, the `unsafe` usage is sound.
/// - Calling `close(2)` is `unsafe` because:
///   - It crosses an FFI boundary into libc to invoke the OS `close` syscall.
///   - Rust cannot guarantee that `fd` is a valid, open file descriptor.
///   - Passing an invalid or previously-closed FD results in undefined behavior at the OS level
///     (`EBADF`) and may break invariants in higher-level code.
///   - This function ensures safety by:
///     - Only calling `close` on file descriptors obtained from a successful `open()` syscall.
///     - Never reusing or double-closing the same `fd`.
///     - Not exposing raw FDs to callers, preventing accidental misuse.
///   - As long as these invariants are upheld, the `unsafe` usage is sound.
///
/// # Notes on ignoring the return value of `close()`
///
/// It is intentionally safe and acceptable for this function to *ignore* the return value of the
/// `close(2)` system call. After we're finished with a file descriptor, closing it is a resource
/// release operation. A failure during `close()` does **not** retroactively invalidate any data
/// already read from `/dev/urandom`, nor does it indicate that previous operations were unsafe.
///
/// For ordinary file descriptors, especially for `/dev/urandom`, the only meaningful
/// errors returned by `close()` are:
///
/// - `EINTR` — the close was interrupted by a signal
/// - `EBADF` — the file descriptor was not valid
///
/// Neither condition requires any recovery:
///
/// - If `EINTR` occurs, the file descriptor is **already** closed or will be closed by the kernel
///   automatically. Retrying is rarely correct.
/// - If `EBADF` occurs, it means the descriptor was already invalid, which cannot happen here
///   because we only call `close(2)` on file descriptors returned by a successful `open(2)`.
///
/// Most importantly, ignoring the return value is consistent with:
/// - POSIX recommendations
/// - Glibc behavior
/// - Rust's own standard library, which does **not** expose close errors for `File` drops
///
/// There is no safe, correct, or meaningful recovery strategy after `close()` fails. Retrying can
/// lead to double-closing. Propagating the error confuses callers because nothing actionable can be
/// done. Therefore, ignoring the result of `close()` is both sound and idiomatic.
///
/// ## Summary
///
/// - Errors from `close()` do **not** affect prior reads.
/// - There is no safe recovery strategy.
/// - Rust's standard library ignores close errors as well.
/// - For `/dev/urandom`, a failure is harmless.
///
/// This makes it safe and correct to ignore the return value of `close()`.
pub fn fill_from_urandom(buf: &mut [u8]) -> Result<(), Error> {
    // Open /dev/urandom for reading.
    let file_descriptor =
        unsafe { open(URANDOM_PATH.as_ptr().cast::<c_char>(), O_RDONLY | O_CLOEXEC) };

    // open() returns -1 on error, and a valid file descriptor on success.
    if file_descriptor < 0 {
        return Err(Error::OpenFailed);
    }

    // The offset into the buffer where we should start reading.
    let mut offset = 0;

    // read() returns the number of bytes read, so we can safely add it to the offset.
    while offset < buf.len() {
        // read() requires a mutable pointer to a buffer, so we need to create a slice from the
        // buffer and cast it to a mutable pointer.
        let remaining = buf.len() - offset;
        let ptr =
            buf.get_mut(offset..).ok_or(Error::OffsetOutOfRange)?.as_mut_ptr().cast::<c_void>();

        // read() returns the number of bytes read, so we can safely add it to the offset.
        let n = unsafe { read(file_descriptor, ptr, remaining) };

        // read() returns 0 on EOF, so we need to check for that explicitly.
        if n == 0 {
            unsafe { close(file_descriptor) };
            return Err(Error::ShortRead);
        }

        // read() returns -1 on error, 0 on EOF, and the number of bytes read otherwise.
        let n_usize = usize::try_from(n).map_err(|_| {
            unsafe { close(file_descriptor) };
            Error::ReadFailed
        })?;

        // read() returns the number of bytes read, so we can safely add it to the offset since
        // we've already checked for <= 0.
        offset = offset.checked_add(n_usize).ok_or(Error::OffsetOverflow)?;
    }

    // Close the file descriptor.
    unsafe { close(file_descriptor) };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic sanity test: `fill_from_urandom` should succeed and fill the buffer
    ///
    /// Provides an extremely weak sanity check: we at least touched the buffer. This does *not*
    /// prove cryptographic quality, only that something happened.
    #[test]
    fn fills_buffer_successfully() {
        let mut buf = [0u8; 32];
        fill_from_urandom(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 32], "buffer was left all zeros");
    }

    /// Calling with a zero-length buffer should not fail or panic
    #[test]
    fn zero_length_buffer_is_ok() {
        let mut buf: [u8; 0] = [];
        fill_from_urandom(&mut buf).expect("fill_from_urandom failed on empty buffer");
        // Nothing else to assert; success is enough.
    }

    /// Two consecutive fills should almost certainly produce different output
    ///
    /// This is a probabilistic test and *could* in theory fail by chance, but the odds of two
    /// independent 32-byte outputs being identical are astronomically low.
    #[test]
    fn two_calls_produce_different_values() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_from_urandom(&mut a).expect("first fill_from_urandom failed");
        fill_from_urandom(&mut b).expect("second fill_from_urandom failed");
        // If this ever triggers, you almost certainly have a bug or a very broken /dev/urandom.
        assert_ne!(a, b, "two urandom outputs were identical; extremely unlikely");
    }

    /// Larger buffers should also be filled; test a non-trivial length
    ///
    /// Again, weak but practical: require *some* non-zero bytes.
    #[test]
    fn large_buffer_is_fully_filled() {
        const N: usize = 4096;
        let mut buf = [0u8; N];
        fill_from_urandom(&mut buf).expect("fill_from_urandom failed for large buffer");
        let non_zero = buf.iter().any(|&b| b != 0);
        assert!(non_zero, "large buffer appears to be all zeros");
    }
}
