use std::{
    thread,
    time::{Duration, Instant},
};

use crate::{ReasonCode, Result};

pub(crate) fn wait(child: &mut std::process::Child, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|_| ReasonCode::Unavailable)? {
            return if status.success() {
                Ok(())
            } else {
                Err(ReasonCode::Unavailable.into())
            };
        }
        if start.elapsed() >= timeout {
            terminate(child);
            return Err(ReasonCode::Timeout.into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

pub(crate) fn terminate(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
