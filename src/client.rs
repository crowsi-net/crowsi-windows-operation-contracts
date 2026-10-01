use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::{
    OPERATION_RESPONSE_SCHEMA, OperationOnlyRequest, OperationOnlyResponse, ReasonCode, Result,
    frame, validation,
};

pub struct HelperIdentity {
    file: File,
    device: u64,
    inode: u64,
}
impl HelperIdentity {
    /// Opens and verifies one immutable helper executable identity.
    ///
    /// # Errors
    /// Rejects non-absolute, linked, writable, non-executable, changed, or digest-mismatched files.
    pub fn new(path: impl Into<PathBuf>, digest: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let digest = digest.into();
        if !path.is_absolute() || !crate::client_process::valid_digest(&digest) {
            return Err(ReasonCode::HelperRejected.into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(path)
            .map_err(|_| ReasonCode::HelperRejected)?;
        let before = file.metadata().map_err(|_| ReasonCode::HelperRejected)?;
        if !before.is_file() || before.mode() & 0o111 == 0 || before.mode() & 0o022 != 0 {
            return Err(ReasonCode::HelperRejected.into());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ReasonCode::HelperRejected)?;
        let after = file.metadata().map_err(|_| ReasonCode::HelperRejected)?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || format!("sha256:{:x}", Sha256::digest(&bytes)) != digest
        {
            return Err(ReasonCode::HelperRejected.into());
        }
        fcntl(file.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
            .map_err(|_| ReasonCode::HelperRejected)?;
        Ok(Self {
            file,
            device: after.dev(),
            inode: after.ino(),
        })
    }
    fn path(&self) -> Result<String> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| ReasonCode::HelperRejected)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(ReasonCode::HelperRejected.into());
        }
        Ok(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

pub struct CustodyClient {
    helper: HelperIdentity,
    timeout: Duration,
}
impl CustodyClient {
    /// Creates a finite operation-only helper client.
    ///
    /// # Errors
    /// Rejects a zero or greater-than-thirty-second timeout.
    pub fn new(helper: HelperIdentity, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(ReasonCode::ContractRejected.into());
        }
        Ok(Self { helper, timeout })
    }
    /// Executes one closed operation-only request.
    ///
    /// # Errors
    /// Fails closed for invalid input, helper failure, timeout, or an invalid/secret response.
    pub fn execute_operation(
        &self,
        request: &OperationOnlyRequest,
    ) -> Result<OperationOnlyResponse> {
        let body = serde_json::to_vec(request).map_err(|_| ReasonCode::ContractRejected)?;
        validation::decode_operation_request(&body)?;
        let mut child = Command::new(self.helper.path()?)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ReasonCode::Unavailable)?;
        let mut input = child.stdin.take().ok_or(ReasonCode::Unavailable)?;
        let output = child.stdout.take().ok_or(ReasonCode::Unavailable)?;
        let reader = thread::spawn(move || frame::read(&mut std::io::BufReader::new(output)));
        if frame::write(&mut input, &body).is_err() {
            crate::client_process::terminate(&mut child);
            return Err(ReasonCode::Unavailable.into());
        }
        drop(input);
        crate::client_process::wait(&mut child, self.timeout)?;
        let wire = reader.join().map_err(|_| ReasonCode::ResultUnknown)??;
        let mut decoder = serde_json::Deserializer::from_slice(&wire);
        let response: OperationOnlyResponse =
            serde::Deserialize::deserialize(&mut decoder).map_err(|_| ReasonCode::ResultUnknown)?;
        decoder.end().map_err(|_| ReasonCode::ResultUnknown)?;
        let valid = response.schema == OPERATION_RESPONSE_SCHEMA
            && response.request_id == request.request_id
            && response.credential_id == request.credential_id
            && response.revision == request.expected_revision
            && !response.contains_secret_values
            && !response.secret_follows
            && validation::valid_result(&request.action, &response.result);
        if valid {
            Ok(response)
        } else {
            Err(ReasonCode::ResultUnknown.into())
        }
    }
}
