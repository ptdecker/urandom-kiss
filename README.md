# kiss-entropy

A zero-dependency Rust wrapper for Linux and macOS /dev/urandom, exposing raw entropy reads, FIPS
mode detection, and kernel RNG environment queries. Designed for simplicity, portability, and
no_std-compatible builds.

## Badges

[![crates.io](https://img.shields.io/crates/v/kiss-entropy.svg)](https://crates.io/crates/kiss-entropy)
[![docs.rs](https://img.shields.io/docsrs/kiss-entropy)](https://docs.rs/kiss-entropy)
[![CI](https://github.com/ptdecker/kiss-entropy/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ptdecker/kiss-entropy/actions/workflows/rust.yml)

---

## Overview

`kiss-entropy` provides a tiny, no_std-friendly interface for reading secure random bytes directly
from `/dev/urandom` and related system sources on Unix-like systems. It is designed for developers
who want a predictable, minimal abstraction without pulling in a full RNG framework or any
third-party dependencies.

The crate also includes optional helpers for detecting whether the system is running in FIPS mode
and for identifying the type of RNG environment exposed by the OS. These utilities are especially
useful for security-sensitive applications that need visibility into the underlying system behavior.

Use this crate when you want a straightforward, low-complexity wrapper around the kernel’s
randomness facilities without involving `rand`, `getrandom`, or higher-level libraries.

---

## Quick Start

### Cargo.toml

```toml
[dependencies]
kiss-entropy = "0.1"
```

### Minimal Example

See [simple_fill.rs](examples/simple_fill.rs) for a simple example of using the library to fill a
buffer with random bytes.

```shell
cargo run --example simple_fill
```

If you enable optional features, you can also check FIPS mode or probe the RNG type:

```rust
use kiss_entropy::{is_fips_mode, detect_rng_type};

fn main() {
    println!("FIPS enabled: {}", is_fips_mode());
    println!("RNG type: {:?}", detect_rng_type());
}
```

---

## Features

- **`fips`** — Enable detection of FIPS mode (via `/proc/sys/crypto/fips_enabled`).
- **`detect-rng`** — Identify the system's RNG type using sysfs/procfs and CPU feature flags.

---

## MSRV & Platform Support

- **Minimum Supported Rust Version:** 1.85
- **Tested on:**
    - Linux (x86_64, aarch64)
    - macOS (x86_64, aarch64/ARM64)
    - BSD variants are expected to work but not yet CI-tested
- Windows is **not supported**, as `/dev/urandom` does not exist there.

---

## Roadmap / Status

**Status:** Early alpha.

The core `/dev/urandom` wrapper is stable and minimal by design, but supporting modules (FIPS
detection, RNG-type introspection) may evolve as more platforms are tested. Future improvements may
include:

- More detailed RNG environment probing
- Better macOS/BSD detection paths
- Optional WASI stub behavior

Breaking changes may still occur while the crate is in 0.x versions.

---

## Contributing

Contributions, issue reports, and suggestions are welcome and encouraged. Please open a GitHub 
issue or submit a pull request if you’d like to help improve the crate.

---

## License

Licensed under the MIT License. See `LICENSE-MIT` for details.
