//! Password and field validation following NIST/OWASP 2025 standards
//!
//! # Features
//! - NIST SP 800-63B compliant password validation
//! - Multi-field error collection and aggregation
//! - Brazilian Portuguese error messages
//! - Common password checking
//! - Length-based security (no complexity requirements)
//!
//! # Example
//! ```rust
//! use pleme_auth_validators::{PasswordValidator, PasswordPolicyConfig};
//!
//! let config = PasswordPolicyConfig::default();
//! let validator = PasswordValidator::new(config);
//!
//! // Validate password
//! validator.validate("my_secure_passphrase")?;
//! ```

pub mod password;
pub mod field;

pub use password::{PasswordValidator, PasswordPolicyConfig, PasswordValidationError};
pub use field::FieldValidator;
