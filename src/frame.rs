use crate::{ReasonCode, Result};
use std::io::{Read, Write};

pub(crate) const MAX: usize = 16 * 1024;

pub(crate) fn write(value: &mut impl Write, body: &[u8]) -> Result<()> {
    if body.is_empty() || body.len() > MAX {
        return Err(ReasonCode::ContractRejected.into());
    }
    let length = u32::try_from(body.len()).map_err(|_| ReasonCode::ContractRejected)?;
    value
        .write_all(&length.to_be_bytes())
        .and_then(|()| value.write_all(body))
        .and_then(|()| value.flush())
        .map_err(|_| ReasonCode::Unavailable.into())
}

pub(crate) fn read(value: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    value
        .read_exact(&mut prefix)
        .map_err(|_| ReasonCode::ResultUnknown)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ReasonCode::ResultUnknown)?;
    if length == 0 || length > MAX {
        return Err(ReasonCode::ResultUnknown.into());
    }
    let mut body = vec![0_u8; length];
    value
        .read_exact(&mut body)
        .map_err(|_| ReasonCode::ResultUnknown)?;
    let mut trailing = [0_u8; 1];
    if value.read(&mut trailing).ok() != Some(0) {
        return Err(ReasonCode::ResultUnknown.into());
    }
    Ok(body)
}
