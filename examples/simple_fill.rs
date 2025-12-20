//! Demonstrates filling a byte buffer with entropy using `kiss_entropy::fill`.
//!
//! This example repeatedly fills a fixed-size buffer with fresh entropy and prints the result to
//! standard output. Each invocation of `fill` overwrites the entire buffer.
//!
//! # Purpose
//!
//! The example is intended to show:
//!
//! - How to allocate and pass a mutable byte buffer
//! - How to handle the `Result` returned by `fill`
//! - That successive calls yield different entropy values
//!
//! # Notes
//!
//! - The printed output is for demonstration only; dumping entropy to stdout is **not** appropriate
//! for real cryptographic applications.
//! - In production code, callers should (must?) propagate or handle errors rather than asserting
//! success.
//! - This example uses `std` but the library is fully `#![no_std]`
//!
//! # Example
//!
//! Run this example with:
//!
//! ```bash
//! cargo run --example fill_buffer
//! ```
//!
//! The output will display four different 32-byte buffers.
//!
//! ```shell
//!
//! ```

use kiss_entropy::fill;

fn main() {
    let mut buffer = [0u8; 32];
    for _ in 0..4 {
        let result = fill(&mut buffer);
        assert!(result.is_ok());
        println!("Buffer: {:?}", buffer);
    }
}
