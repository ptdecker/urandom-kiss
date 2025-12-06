//! Public Error type for crate

use super::{UrandomError, fmt};

/// Public error type for this crate.
///
/// Currently, there's only one variant, which wraps the internal [`UrandomError`].
#[derive(Debug)]
pub enum Error {
    Urandom(UrandomError),
}

impl From<UrandomError> for Error {
    fn from(err: UrandomError) -> Self {
        Self::Urandom(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Urandom(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            | Self::Urandom(inner) => Some(inner),
        }
    }
}
