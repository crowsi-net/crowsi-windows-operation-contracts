# Using crowsi-windows-operation-contracts

Validate the narrow requests exchanged with a Windows helper process.

## Before you start

These contracts do not install a helper or implement a Windows custody backend.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Pin helper identity and operation limits.
- Represent permitted helper requests and results.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
