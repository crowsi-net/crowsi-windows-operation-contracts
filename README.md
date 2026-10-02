# crowsi-windows-operation-contracts

Validate the narrow requests exchanged with a Windows helper process.

## What you can do

- Pin helper identity and operation limits.
- Represent permitted helper requests and results.

## Current scope

These contracts do not install a helper or implement a Windows custody backend.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
