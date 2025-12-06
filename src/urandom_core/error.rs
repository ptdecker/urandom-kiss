use super::fmt;

/// Errors that can occur when reading from /dev/urandom
#[derive(Debug, Copy, Clone)]
pub enum Error {
    /// Failed to open /dev/urandom
    OpenFailed,
    /// Failed to read from the file descriptor
    ReadFailed,
    /// Incomplete read from /dev/urandom
    ShortRead,
    /// The calculated offset is out of range of the buffer. This is an internal error that should
    /// never happen but included here so it can be handled as an error instead of a panic.
    OffsetOutOfRange,
    /// Adding the number of bytes returned from urandom to our current buffer offset would cause
    /// the offset to overflow its range. This is an internal error that should never happen but
    /// included here so it can be handled as an error instead of a panic.
    OffsetOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::OpenFailed => f.write_str("Could not open /dev/urandom"),
            | Self::ReadFailed => f.write_str("Could not read /dev/urandom"),
            | Self::ShortRead => f.write_str("/dev/urandom returned too few bytes"),
            | Self::OffsetOutOfRange => f.write_str("Internal error: buffer offset out of range"),
            | Self::OffsetOverflow => f.write_str("The offset overflowed"),
        }
    }
}

impl core::error::Error for Error {}
