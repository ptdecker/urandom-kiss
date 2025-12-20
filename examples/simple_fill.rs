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
//! cargo run --example simple_fill
//! ```
//!
//! The output will display four different 32-byte buffers.
//!
//! ```shell
//! [97, 34, 62, 117, 76, 69, 16, 178]
//! [18, 33, 146, 246, 31, 154, 171, 67]
//! [112, 174, 93, 87, 15, 10, 191, 99]
//! [233, 193, 148, 84, 178, 231, 176, 251]
//! ```

use kiss_entropy::fill;

fn main() {
    let mut buffer = [0u8; 8];
    for _ in 0..4 {
        let result = fill(&mut buffer);
        assert!(result.is_ok());
        println!("{:?}", buffer);
    }
}
