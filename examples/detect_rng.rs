//! Demonstrates detecting random number generator type using `kiss_entropy::detect_rng`.
//!
//! foo
//!
//! # Purpose
//!
//! The example is intended to show:
//!
//! - bar
//!
//! # Notes
//!
//! - bazz
//!
//! # Example
//!
//! Run this example with:
//!
//! ```shell
//! cargo run --features=detect_rng --example detect_rng
//! ```
//!
//! ```shell
//! macOS kernel random number generator (hardware-backed, source not exposed)
//! ```

use kiss_entropy::detect_rng;

fn main() {
    match detect_rng() {
        | Some(rng_type) => println!("{}", rng_type),
        | None => println!("No random number generator detected"),
    }
}
