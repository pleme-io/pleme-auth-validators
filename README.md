# pleme-auth-validators

NIST 2025 compliant password and field validation for authentication

## Installation

```toml
[dependencies]
pleme-auth-validators = "0.1"
```

## Usage

```rust
use pleme_auth_validators::PasswordValidator;

let validator = PasswordValidator::nist2025();
let result = validator.validate("my-password-123");
assert!(result.is_ok());
```

## Development

This project uses [Nix](https://nixos.org/) for reproducible builds:

```bash
nix develop            # Dev shell with Rust toolchain
nix run .#check-all    # cargo fmt + clippy + test
nix run .#publish      # Publish to crates.io (--dry-run supported)
nix run .#regenerate   # Regenerate Cargo.nix
```

## License

MIT - see [LICENSE](LICENSE) for details.
