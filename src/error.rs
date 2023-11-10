use std::{array::TryFromSliceError, string::FromUtf8Error};

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(Err)))]
pub enum PassManagerErr {
    #[snafu(display("couldn't find data dir for current os"))]
    DataDir,

    #[snafu(display("slice is empty, cannot split"))]
    Split,

    #[snafu(display("git error: {source}"), context(false))]
    Git { source: git2::Error },

    #[snafu(display("io error: {source}"), context(false))]
    Io { source: std::io::Error },

    #[snafu(display("fs error [path: {path}]: {source}"))]
    Fs {
        source: std::io::Error,
        path: String,
    },

    #[snafu(display("dialoguer error: {source}"), context(false))]
    Dialoguer { source: dialoguer::Error },

    #[snafu(display("argon2 error: {err}"))]
    Argon2 { err: argon2::Error },

    #[snafu(display("invalid password"))]
    Aes { err: aes_gcm::Error },

    #[snafu(display("rkyv error: {err}"))]
    Rkyv { err: String },

    #[snafu(display("try_from error: {source}"), context(false))]
    TryFrom { source: TryFromSliceError },

    #[snafu(
        display("couldn't convert slice to string. error: {source}"),
        context(false)
    )]
    Utf8 { source: FromUtf8Error },

    #[snafu(display("clipboard error: {source}"), context(false))]
    Clipboard { source: Box<dyn std::error::Error> },

    #[snafu(display("could not acquire {fd} of command"))]
    Command { fd: String },

    #[snafu(display("invalid url: {source}"), context(false))]
    Url { source: url::ParseError },

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

impl_from_source!(Argon2, argon2::Error);
impl_from_source!(Aes, aes_gcm::Error);
impl_from_source!(Rkyv, String);
