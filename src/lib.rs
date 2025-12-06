// We don't need the standard library
#![no_std]

pub mod error;
mod urandom_core;

use core::fmt;

pub use error::Error;
pub use urandom_core::Error as UrandomError;
use urandom_core::fill_from_urandom;

/// Public, user-facing wrapper around the internal `fill_from_urandom` implementation.
///
/// This is the function that consumers of the crate are expected to call.
///
/// # Examples
///
/// ```
/// # use kiss_entropy::{fill, Error};
/// let mut buf = [0u8; 32];
/// fill(&mut buf)?;
/// # Ok::<(), Error>(())
/// ```
/// # Errors
/// Returns `Error` if:
/// - Failed to open /dev/urandom
/// - Failed to read from file descriptor
/// - Got incomplete read from /dev/urandom
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    Ok(fill_from_urandom(buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: zero-length buffers are allowed and should succeed without touching anything.
    #[test]
    fn zero_length_buffer_ok() {
        let mut buf: [u8; 0] = [];
        let result = fill(&mut buf);
        assert!(result.is_ok());
    }

    /// Basic test: a non-empty buffer should be filled successfully.
    #[test]
    fn fills_non_empty_buffer() {
        let mut buf = [0u8; 32];
        let result = fill(&mut buf);
        assert!(result.is_ok());

        // It's *possible* (but astronomically unlikely) that all bytes are 0.
        // This is a cheap sanity check rather than a statistical test.
        let all_zero = buf.iter().all(|&b| b == 0);
        assert!(
            !all_zero,
            "Buffer still all zeros after fill(); extremely unlikely unless urandom is broken."
        );
    }

    /// Two successive fills should almost certainly produce different output.
    ///
    /// This is not a proof of randomness, but it helps catch egregious bugs
    /// (like always writing the same pattern, or failing to increment state).
    #[test]
    fn two_fills_differ_most_of_the_time() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        fill(&mut a).expect("first fill failed");
        fill(&mut b).expect("second fill failed");

        // Probability of 256 bits colliding is 2^-256; acceptable risk for a test.
        // If this ever triggers in practice, it's a strong hint that something
        // is wrong in the implementation or environment.
        assert_ne!(a, b, "Two fill calls produced identical 32-byte outputs; suspicious.")
    }
}
