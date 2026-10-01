# Security boundary

This crate is the client-side contract for operation-only use of platform
custody. It does not implement Windows CNG custody, hold provider state, or
export credential material. A caller can request a signature over an exact
digest or a named provider operation over an exact input digest; there is no
generic get/read/export action.

The helper executable is opened with `O_NOFOLLOW`, checked as an executable
owner-controlled regular file, read and digest-verified, and identified by its
device/inode before use. Execution uses the already-open `/proc/self/fd/N`
identity, a cleared environment, bounded framing, and a finite timeout. A path
is not reopened after verification.

The Windows custody provider remains a separately released implementation. It
must verify the signed policy authorization and current iHAT device status,
bind the operation to its non-exportable key, and return only the closed result
shape. It must reject generic secret retrieval and any response claiming secret
values or an out-of-band secret body.

The PA authorization input contract accepts only target approval for a device transfer and only
an Ed25519 signature of the exact unsigned target-proof binding. It rejects old schemas, unknown
or trailing input, provider-operation intent, target/identity substitution, and proof-digest or
custody-revision drift. The PA implementation must additionally verify all signatures and trusted
time, select custody ID/revision/class from root-signed endpoint mapping, durably consume the
evidence once, and sign the complete `OperationOnlyRequest`; those runtime duties are not
implemented by this DTO crate.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
