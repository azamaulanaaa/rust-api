//! Pure entity-attribute-value (EAV) rules and search.
//!
//! A caller loads the entities into memory and passes a view.
//! The module does no I/O and holds no state.
//! The server and the WASM client call the same code.

pub mod search;
pub mod validation;

pub use search::{
    DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, QueryWindow, SearchEntity, SearchPage, SearchValue,
    WindowError, search_by_attribute,
};
pub use validation::{
    MAX_NAME_BYTES, NameError, UpdateError, validate_name, validate_update_input,
};
