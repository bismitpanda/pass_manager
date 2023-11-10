use std::{array::TryFromSliceError, string::FromUtf8Error};

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(Err)))]
pub enum PassManagerErr {
    #[snafu(display("couldn't find data dir for current os"))]
    DataDir,

    #[snafu(display("slice is empty, cannot split"))]
    Split,

    #[snafu(display("git error: {err}"))]
    Git { err: git2::Error },

    #[snafu(display("io error: {err}"))]
    Io { err: std::io::Error },

    #[snafu(display("dialoguer error: {err}"))]
    Dialoguer { err: dialoguer::Error },

    #[snafu(display("argon2 error: {err}"))]
    Argon2 { err: argon2::Error },

    #[snafu(display("invalid password"))]
    Aes { err: aes_gcm::Error },

    #[snafu(display("rkyv error: {err}"))]
    Rkyv { err: String },

    #[snafu(display("try_from error: {err}"))]
    TryFrom { err: TryFromSliceError },

    #[snafu(display("couldn't convert slice to string. error: {err}"))]
    Utf8 { err: FromUtf8Error },

    #[snafu(display("clipboard error: {err}"))]
    Clipboard { err: Box<dyn std::error::Error> },

    #[snafu(display("could not acquire {fd} of command"))]
    Command { fd: String },

    #[snafu(display("invalid url: {err}"))]
    Url { err: url::ParseError },

    #[snafu(display("invalid url: no host found"))]
    Host,

    #[snafu(display("git error: commit message is not valid utf-8"))]
    InvalidCommitMessage,
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
