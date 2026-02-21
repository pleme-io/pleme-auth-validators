//! Multi-field validation error collection and aggregation

/// Helper for collecting validation errors across multiple fields
///
/// # Example
/// ```rust
/// use pleme_auth_validators::FieldValidator;
///
/// let mut validator = FieldValidator::new();
/// validator.add_if(email.is_empty(), "email", "Email é obrigatório");
/// validator.add_if(password.len() < 8, "password", "Senha muito curta");
///
/// if !validator.is_empty() {
///     return Err(validator.into_errors());
/// }
/// ```
#[derive(Debug, Default)]
pub struct FieldValidator {
    errors: Vec<(String, String)>,
}

impl FieldValidator {
    /// Create a new field validator
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Add an error for a specific field
    pub fn add(&mut self, field: &str, message: &str) {
        self.errors.push((field.to_string(), message.to_string()));
    }

    /// Add an error conditionally
    pub fn add_if(&mut self, condition: bool, field: &str, message: &str) {
        if condition {
            self.add(field, message);
        }
    }

    /// Check if there are any errors
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get the number of errors
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Get errors as field tuples (for backward compatibility)
    pub fn into_errors(self) -> Vec<(String, String)> {
        self.errors
    }

    /// Get errors as static str tuples
    pub fn as_static_errors(&self) -> Vec<(&str, &str)> {
        self.errors.iter()
            .map(|(f, m)| (f.as_str(), m.as_str()))
            .collect()
    }
}

/// Create validation error from field tuples (helper function)
pub fn validation_from_fields(errors: Vec<(&str, &str)>) -> Vec<(String, String)> {
    errors.into_iter()
        .map(|(field, msg)| (field.to_string(), msg.to_string()))
        .collect()
}
