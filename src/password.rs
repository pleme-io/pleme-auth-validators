//! Password validation following NIST/OWASP 2025 standards
//!
//! Modern password policy (NIST SP 800-63B):
//! - Minimum 8 characters (for MFA-enabled systems)
//! - Maximum 64 characters (support passphrases)
//! - NO complexity requirements (uppercase, lowercase, numbers, special chars)
//! - Check against common weak passwords
//! - Allow ALL printable characters including spaces and Unicode

use serde::{Deserialize, Serialize};

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyConfig {
    /// Minimum password length (NIST recommends 8 for MFA-enabled systems)
    #[serde(default = "default_min_length")]
    pub min_length: usize,

    /// Password history count (prevent reuse of old passwords)
    #[serde(default = "default_history_count")]
    pub password_history_count: usize,

    /// Argon2 time cost (number of iterations)
    #[serde(default = "default_time_cost")]
    pub argon2_time_cost: u32,

    /// Argon2 memory cost (in KB)
    #[serde(default = "default_memory_cost")]
    pub argon2_memory_cost: u32,
}

fn default_min_length() -> usize { 8 }
fn default_history_count() -> usize { 5 }
fn default_time_cost() -> u32 { 3 }
fn default_memory_cost() -> u32 { 65536 }

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            password_history_count: 5,
            argon2_time_cost: 3,
            argon2_memory_cost: 65536,
        }
    }
}

/// Password validation error
#[derive(Debug, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("{0}")]
    TooWeak(String),

    #[error("{0}")]
    TooShort(String),

    #[error("{0}")]
    TooLong(String),

    #[error("{0}")]
    CommonPassword(String),
}

/// Password validator following NIST/OWASP 2025 standards
pub struct PasswordValidator {
    config: PasswordPolicyConfig,
}

impl PasswordValidator {
    /// Create a new password validator with the given configuration
    pub fn new(config: PasswordPolicyConfig) -> Self {
        Self { config }
    }

    /// Validate password strength against NIST/OWASP 2025 standards
    pub fn validate(&self, password: &str) -> Result<(), PasswordValidationError> {
        // Minimum length check
        if password.len() < self.config.min_length {
            return Err(PasswordValidationError::TooShort(
                format!("Opa, sua senha tá muito fraca! Precisa ter pelo menos {} caracteres, mano",
                    self.config.min_length)
            ));
        }

        // Maximum length check (NIST recommends 64 chars for passphrase support)
        if password.len() > 64 {
            return Err(PasswordValidationError::TooLong(
                "Calma lá! Senha muito grande, máximo de 64 caracteres".to_string()
            ));
        }

        // Check for common weak passwords (NIST requirement)
        if self.is_common_password(password) {
            return Err(PasswordValidationError::CommonPassword(
                "Eita! Essa senha é muito óbvia, parceiro. Bora criar uma senha mais única?".to_string()
            ));
        }

        Ok(())
    }

    /// Validate password as field error tuple (for FieldValidator compatibility)
    pub fn validate_as_field_error(&self, password: &str) -> Result<(), Vec<(&'static str, &'static str)>> {
        let mut errors = Vec::new();

        // Minimum length check
        if password.len() < self.config.min_length {
            errors.push(("password", "Sua senha tá fraca, precisa ter pelo menos 8 caracteres"));
        }

        // Maximum length check
        if password.len() > 64 {
            errors.push(("password", "Senha muito grande, máximo de 64 caracteres"));
        }

        // Check for common weak passwords
        if self.is_common_password(password) {
            errors.push(("password", "Essa senha é muito óbvia. Cria uma senha mais única, vai!"));
        }

        if !errors.is_empty() {
            Err(errors)
        } else {
            Ok(())
        }
    }

    /// Check if password is in common passwords list (NIST 2025 compliant)
    fn is_common_password(&self, password: &str) -> bool {
        let common_passwords = [
            "password", "12345678", "qwerty", "abc123", "monkey",
            "letmein", "trustno1", "dragon", "baseball", "iloveyou",
            "master", "sunshine", "ashley", "bailey", "shadow",
            "123123", "654321", "superman", "qazwsx", "michael",
            "football", "password1", "password123", "welcome",
            // Common Brazilian Portuguese passwords
            "senha123", "admin123", "brasil", "futebol",
        ];

        let lower_password = password.to_lowercase();

        // Check if password IS a common password or simple variation
        common_passwords.iter().any(|&p| {
            // Exact match
            if lower_password == p {
                true
            }
            // Common password + numbers/symbols at end
            else if let Some(suffix) = lower_password.strip_prefix(p) {
                !suffix.is_empty() && suffix.chars().all(|c| c.is_numeric() || !c.is_alphanumeric())
            }
            // Numbers/symbols + common password
            else if let Some(prefix) = lower_password.strip_suffix(p) {
                !prefix.is_empty() && prefix.chars().all(|c| c.is_numeric() || !c.is_alphanumeric())
            } else {
                false
            }
        })
    }
}
