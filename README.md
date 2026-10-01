# Crowsi Windows operation contracts

Closed operation-only DTOs plus a bounded, digest- and file-descriptor-pinned helper client.
This crate contains no Windows custody backend, secret retrieval API, provider implementation,
authority store, or cross-account identity.

The PA one-use input is the closed
`crowsi://policy-authority/operation-authorize-once-request/v2` document. It carries only the
signed selected-identity, Begin, Finish, and submission-current identity exchanges; bare identity
or FreshUV documents are not accepted. The chain binds one prepared target operation, exact
`TargetApprove`, an unsigned target-device proof binding, and only an Ed25519 `Sign` intent over
that binding's domain-separated SHA-256 digest. Custody ID and proof-key reference stay distinct.
