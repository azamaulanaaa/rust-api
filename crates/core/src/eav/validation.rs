//! Pure validation rules for entity-attribute-value (EAV) input.
//!
//! The rules check names and update input.
//! They do no I/O and hold no state.
//! The server and the client use the same rules.
//! The rules keep the messages of the former server helpers.

use std::fmt;

/// The largest size of an entity id or an attribute name, in bytes.
///
/// A name of 128 bytes is valid.
/// A name of 129 bytes is not valid.
pub const MAX_NAME_BYTES: usize = 128;

/// A reason that a name is not valid.
///
/// The message names the checked value, for example `entity id`.
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// The value has no bytes.
    Empty {
        /// The name of the checked value.
        kind: String,
    },
    /// The value has more bytes than [`MAX_NAME_BYTES`].
    TooLong {
        /// The name of the checked value.
        kind: String,
    },
    /// The value has a byte outside the allowed set.
    InvalidCharacter {
        /// The name of the checked value.
        kind: String,
    },
}

impl NameError {
    /// Returns the name of the checked value.
    pub fn kind(&self) -> &str {
        match self {
            Self::Empty { kind } | Self::TooLong { kind } | Self::InvalidCharacter { kind } => kind,
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self.kind();
        match self {
            Self::Empty { .. } => write!(f, "{kind} is empty"),
            Self::TooLong { .. } => {
                write!(f, "{kind} is longer than {MAX_NAME_BYTES} bytes")
            }
            Self::InvalidCharacter { .. } => write!(f, "{kind} has an invalid character"),
        }
    }
}

impl std::error::Error for NameError {}

/// A reason that an entity update input is not valid.
///
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// The entity id is not valid.
    Name(NameError),
    /// The patch holds no attribute changes.
    EmptyPatch,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(error) => error.fmt(f),
            Self::EmptyPatch => f.write_str("patch is empty"),
        }
    }
}

impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Name(error) => Some(error),
            Self::EmptyPatch => None,
        }
    }
}

/// Checks a name against the storage key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:` and `/`, so a value cannot inject a key.
pub fn validate_name(kind: &str, value: &str) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty {
            kind: kind.to_string(),
        });
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong {
            kind: kind.to_string(),
        });
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(NameError::InvalidCharacter {
            kind: kind.to_string(),
        });
    }
    Ok(())
}

/// Checks the id and the patch of one entity update.
///
/// The call rejects an invalid id and an empty patch.
/// `attribute_count` is the number of entries in the patch map.
/// It includes entries that remove an attribute.
pub fn validate_update_input(id: &str, attribute_count: usize) -> Result<(), UpdateError> {
    validate_name("entity id", id).map_err(UpdateError::Name)?;
    if attribute_count == 0 {
        return Err(UpdateError::EmptyPatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name with the allowed characters is valid.
    #[test]
    fn an_allowed_name_is_valid() {
        assert_eq!(validate_name("entity id", "task_1-a"), Ok(()));
    }

    /// A name at the byte limit is valid.
    #[test]
    fn a_name_at_the_maximum_length_is_valid() {
        let value = "a".repeat(MAX_NAME_BYTES);
        assert_eq!(validate_name("entity id", &value), Ok(()));
    }

    /// An empty name is not valid.
    #[test]
    fn an_empty_name_is_not_valid() {
        let error = validate_name("entity id", "").expect_err("the name is empty");
        assert_eq!(
            error,
            NameError::Empty {
                kind: "entity id".to_string()
            }
        );
        assert_eq!(error.to_string(), "entity id is empty");
        assert_eq!(error.kind(), "entity id");
    }

    /// A name one byte above the limit is not valid.
    #[test]
    fn a_name_above_the_maximum_length_is_not_valid() {
        let value = "a".repeat(MAX_NAME_BYTES + 1);
        let error = validate_name("attribute name", &value).expect_err("the name is too long");
        assert_eq!(error.to_string(), "attribute name is longer than 128 bytes");
    }

    /// An uppercase byte is not allowed.
    #[test]
    fn an_uppercase_name_is_not_valid() {
        let error = validate_name("entity id", "Task").expect_err("uppercase is not allowed");
        assert_eq!(error.to_string(), "entity id has an invalid character");
    }

    /// A colon and a slash are not allowed.
    #[test]
    fn a_name_with_a_key_separator_is_not_valid() {
        for value in ["a:b", "a/b"] {
            let error = validate_name("schema id", value).expect_err("the name has a separator");
            assert_eq!(error.to_string(), "schema id has an invalid character");
        }
    }

    /// An update with no attribute change is not valid.
    #[test]
    fn an_update_without_attributes_is_not_valid() {
        let error = validate_update_input("e1", 0).expect_err("the patch is empty");
        assert_eq!(error, UpdateError::EmptyPatch);
        assert_eq!(error.to_string(), "patch is empty");
    }

    /// An update with one attribute change is valid.
    #[test]
    fn an_update_with_one_attribute_is_valid() {
        assert_eq!(validate_update_input("e1", 1), Ok(()));
    }

    /// An update checks the entity id first.
    #[test]
    fn an_update_with_an_invalid_id_is_not_valid() {
        let error = validate_update_input("", 1).expect_err("the id is empty");
        assert_eq!(
            error,
            UpdateError::Name(NameError::Empty {
                kind: "entity id".to_string()
            })
        );
        assert_eq!(error.to_string(), "entity id is empty");
        assert!(std::error::Error::source(&error).is_some());
    }
}
