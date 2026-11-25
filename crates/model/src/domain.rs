//! Domain values that the server and the client share.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The lifecycle state of one job.
///
/// The wire form is a snake_case string. The stored queue status is a
/// different type. Do not expose the stored status on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The job waits for a worker.
    Queued,
    /// A worker holds the job.
    Leased,
    /// The job finished well.
    Succeeded,
    /// The job failed and will not retry.
    Failed,
    /// The job used every attempt.
    Dead,
}

impl JobState {
    /// Returns `true` when the job has no further work.
    ///
    /// The terminal states are [`JobState::Succeeded`],
    /// [`JobState::Failed`], and [`JobState::Dead`]. A client stops its
    /// poll or event stream in a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Dead)
    }
}

/// The kind of one write command.
///
/// The value is a stable command name. The type keeps a wire value from
/// becoming an unchecked `String`. The parse rules are an allowlist: the
/// value is 1 to 64 ASCII bytes of lowercase letters, digits, `.`, `-`, and
/// `_`. The server keeps the second allowlist of kinds that have a handler.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "openapi",
    schema(
        value_type = String,
        min_length = 1,
        max_length = 64,
        pattern = "^[a-z0-9._-]{1,64}$"
    )
)]
#[serde(try_from = "String", into = "String")]
pub struct CommandKind(String);

impl CommandKind {
    /// The maximum length of a command kind in bytes.
    pub const MAX_LEN: usize = 64;

    /// Parses one command kind.
    ///
    /// The function returns [`CommandKindError`] when the value is empty,
    /// is longer than [`CommandKind::MAX_LEN`], or holds a byte outside the
    /// allowlist.
    pub fn parse(value: impl Into<String>) -> Result<Self, CommandKindError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CommandKindError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(CommandKindError::TooLong);
        }
        let valid = value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        });
        if !valid {
            return Err(CommandKindError::InvalidByte);
        }
        Ok(Self(value))
    }

    /// Returns the command kind as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for CommandKind {
    type Error = CommandKindError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl std::str::FromStr for CommandKind {
    type Err = CommandKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl From<CommandKind> for String {
    fn from(kind: CommandKind) -> Self {
        kind.0
    }
}

/// The reason that a command kind is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandKindError {
    /// The value is empty.
    #[error("command kind is empty")]
    Empty,
    /// The value is longer than [`CommandKind::MAX_LEN`].
    #[error("command kind is longer than 64 bytes")]
    TooLong,
    /// The value holds a byte outside the allowlist.
    #[error("command kind has a byte outside the allowlist")]
    InvalidByte,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every job state uses its documented snake_case wire name.
    #[test]
    fn job_states_use_snake_case_on_the_wire() {
        let cases = [
            (JobState::Queued, "queued"),
            (JobState::Leased, "leased"),
            (JobState::Succeeded, "succeeded"),
            (JobState::Failed, "failed"),
            (JobState::Dead, "dead"),
        ];
        for (state, wire) in cases {
            let value = serde_json::to_value(state).expect("job state serializes");
            assert_eq!(value, serde_json::json!(wire));
            let back: JobState = serde_json::from_value(value).expect("job state parses");
            assert_eq!(back, state);
        }
    }

    /// Only the three final states are terminal.
    #[test]
    fn only_final_job_states_are_terminal() {
        assert!(!JobState::Queued.is_terminal());
        assert!(!JobState::Leased.is_terminal());
        assert!(JobState::Succeeded.is_terminal());
        assert!(JobState::Failed.is_terminal());
        assert!(JobState::Dead.is_terminal());
    }

    /// A valid command kind keeps its bytes and its display form.
    #[test]
    fn a_valid_command_kind_keeps_its_bytes() {
        let kind = CommandKind::parse("entity.create").expect("valid kind");
        assert_eq!(kind.as_str(), "entity.create");
        assert_eq!(kind.to_string(), "entity.create");
        assert_eq!(String::from(kind.clone()), "entity.create");

        let longest = "a".repeat(CommandKind::MAX_LEN);
        let kind = CommandKind::parse(longest.clone()).expect("maximum length is valid");
        assert_eq!(kind.as_str(), longest);
    }

    /// The parser applies the full allowlist.
    #[test]
    fn the_command_kind_parser_applies_the_allowlist() {
        assert_eq!(CommandKind::parse(""), Err(CommandKindError::Empty));
        assert_eq!(
            CommandKind::parse("a".repeat(CommandKind::MAX_LEN + 1)),
            Err(CommandKindError::TooLong)
        );
        for value in [
            "Entity.Create",
            "entity create",
            "entity/create",
            "entity:create",
        ] {
            assert_eq!(
                CommandKind::parse(value),
                Err(CommandKindError::InvalidByte),
                "{value}"
            );
        }
        assert!(CommandKind::parse("a.b-c_9").is_ok());
    }

    /// `FromStr` uses the command kind parser.
    #[test]
    fn command_kind_from_str_uses_the_parser() {
        let kind: CommandKind = "entity.create".parse().expect("the kind parses");
        assert_eq!(
            kind,
            CommandKind::parse("entity.create").expect("the kind parses")
        );

        let error = "Bad Kind"
            .parse::<CommandKind>()
            .expect_err("the kind must fail");
        assert_eq!(error, CommandKindError::InvalidByte);
    }

    /// Serde uses the parser and the string form of the type.
    #[test]
    fn command_kind_serde_round_trips() {
        let kind = CommandKind::parse("entity.update").expect("valid kind");
        let value = serde_json::to_value(&kind).expect("kind serializes");
        assert_eq!(value, serde_json::json!("entity.update"));
        let back: CommandKind = serde_json::from_value(value).expect("kind parses");
        assert_eq!(back, kind);

        let error = serde_json::from_value::<CommandKind>(serde_json::json!("Bad Kind"))
            .expect_err("an invalid kind must fail");
        assert!(error.to_string().contains("allowlist"), "{error}");
    }

    /// Every parser error names the rule that the value breaks.
    #[test]
    fn command_kind_errors_name_the_rule() {
        assert_eq!(CommandKindError::Empty.to_string(), "command kind is empty");
        assert_eq!(
            CommandKindError::TooLong.to_string(),
            "command kind is longer than 64 bytes"
        );
        assert_eq!(
            CommandKindError::InvalidByte.to_string(),
            "command kind has a byte outside the allowlist"
        );
    }
}
