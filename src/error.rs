use std::{array::TryFromSliceError, string::FromUtf8Error};

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(Err)))]
pub enum PassManagerErr {
    #[snafu(display("couldn't find data dir for current os"))]
    DataDir,

    #[snafu(display("slice is empty, cannot split"))]
    Split,

    Git {
        err: git2::Error,
    },

    Io {
        err: std::io::Error,
    },

    Dialoguer {
        err: dialoguer::Error,
    },

    Argon2 {
        err: argon2::Error,
    },

    Aes {
        err: aes_gcm::Error,
    },

    Rkyv {
        err: String,
    },

    TryFrom {
        err: TryFromSliceError,
    },

    Utf8 {
        err: FromUtf8Error,
    },

    Clipboard {
        err: Box<dyn std::error::Error>,
    },

    Command {
        fd: String,
    },

    Url {
        err: url::ParseError,
    },

    Host,
}

pub type Result<T, E = PassManagerErr> = std::result::Result<T, E>;

macro_rules! impl_from_source {
    ($var:ident, $source:path) => {
        impl From<$source> for PassManagerErr {
            fn from(value: $source) -> Self {
                Self::$var { err: value }
            }
        }
    };
}

impl_from_source!(Io, std::io::Error);
impl_from_source!(Git, git2::Error);
impl_from_source!(Dialoguer, dialoguer::Error);
impl_from_source!(Argon2, argon2::Error);
impl_from_source!(Rkyv, String);
impl_from_source!(Aes, aes_gcm::Error);
impl_from_source!(TryFrom, TryFromSliceError);
impl_from_source!(Utf8, FromUtf8Error);
impl_from_source!(Clipboard, Box<dyn std::error::Error>);
impl_from_source!(Url, url::ParseError);
