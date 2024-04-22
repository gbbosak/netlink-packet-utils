// SPDX-License-Identifier: MIT

use crate::nla;
use anyhow::anyhow;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Encode error occurred: {inner}")]
pub struct EncodeError {
    inner: anyhow::Error,
}

impl From<&'static str> for EncodeError {
    fn from(msg: &'static str) -> Self {
        EncodeError {
            inner: anyhow!(msg),
        }
    }
}

impl From<String> for EncodeError {
    fn from(msg: String) -> Self {
        EncodeError {
            inner: anyhow!(msg),
        }
    }
}

impl From<anyhow::Error> for EncodeError {
    fn from(inner: anyhow::Error) -> EncodeError {
        EncodeError { inner }
    }
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("Invalid MAC address")]
    InvalidMACAddress,

    #[error("Invalid IPv6 address")]
    InvalidIPv6Address,

    #[error("Invalid string")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Invalid u8")]
    InvalidU8,

    #[error("Invalid u16")]
    InvalidU16,

    #[error("Invalid u32")]
    InvalidU32,

    #[error("Invalid u64")]
    InvalidU64,

    #[error("Invalid u128")]
    InvalidU128,

    #[error("Invalid i32")]
    InvalidI32,

    #[error("Invalid {name}: length {len} < {buffer_len}")]
    InvalidBufferLength {
        name: &'static str,
        len: usize,
        buffer_len: usize,
    },

    #[error(transparent)]
    InvalidNLABuffer(#[from] NLAError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<&'static str> for DecodeError {
    fn from(msg: &'static str) -> Self {
        DecodeError::Other(anyhow!(msg))
    }
}

impl From<String> for DecodeError {
    fn from(msg: String) -> Self {
        DecodeError::Other(anyhow!(msg))
    }
}

#[derive(Debug, Error)]
pub enum NLAError {
    #[error("buffer has length {buffer_len}, but an NLA header is {} bytes", nla::TYPE.end)]
    BufferTooSmall { buffer_len: usize },

    #[error("buffer has length: {buffer_len}, but the NLA is {nla_len} bytes")]
    LengthMismatch { buffer_len: usize, nla_len: u16 },

    #[error(
        "NLA has invalid length: {nla_len} (should be at least {} bytes", nla::TYPE.end
    )]
    InvalidLength { nla_len: u16 },
}
