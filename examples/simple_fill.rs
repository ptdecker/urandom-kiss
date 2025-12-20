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
//!Buffer: [217, 146, 45, 51, 49, 216, 91, 89, 211, 45, 154, 241, 255, 145, 81, 250, 214, 113, 186, 237, 179, 242, 188, 39, 67, 190, 59, 159, 61, 113, 39, 52]
// Buffer: [204, 235, 216, 122, 247, 145, 98, 20, 203, 116, 101, 179, 205, 39, 130, 255, 245, 62, 201, 95, 71, 62, 181, 219, 13, 29, 141, 42, 21, 115, 244, 13]
// Buffer: [104, 234, 217, 30, 133, 65, 182, 94, 245, 3, 148, 236, 161, 170, 124, 163, 230, 153, 195, 117, 168, 154, 172, 207, 138, 238, 90, 169, 131, 155, 105, 185]
// Buffer: [148, 71, 180, 4, 244, 252, 120, 116, 153, 212, 38, 212, 82, 250, 212, 54, 201, 80, 83, 156, 226, 164, 215, 154, 123, 195, 14, 8, 142, 23, 233, 166]
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
