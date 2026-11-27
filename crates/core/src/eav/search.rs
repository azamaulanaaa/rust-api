//! Pure in-memory search over entity-attribute-value (EAV) entities.
//!
//! The caller passes a slice of entity views and a resolved page window.
//! The search filters by one indexed attribute and an exact value.
//! It sorts the matches by entity id and returns one page.
//! It does no I/O and it checks no authorization.
//! The caller loads only the data that the user may read.

use std::collections::BTreeSet;
use std::fmt;

/// The default size of an entity page.
pub const DEFAULT_PAGE_LIMIT: usize = 50;

/// The largest size of an entity page.
///
/// A page size of 200 is valid.
/// A page size of 201 is not valid.
pub const MAX_PAGE_LIMIT: usize = 200;

/// A reason that a page window is not valid.
///
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The page size is zero or above [`MAX_PAGE_LIMIT`].
    PageLimit,
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PageLimit => write!(f, "limit must be between 1 and {MAX_PAGE_LIMIT}"),
        }
    }
}

impl std::error::Error for WindowError {}

/// A checked page window for an entity query.
///
/// The limit is in the range 1 to [`MAX_PAGE_LIMIT`].
/// An empty cursor is the first page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryWindow {
    limit: usize,
    after: Option<String>,
}

impl QueryWindow {
    /// Resolves the page window from the optional request fields.
    ///
    /// A missing limit uses [`DEFAULT_PAGE_LIMIT`].
    /// A missing or empty cursor starts at the first page.
    pub fn resolve(limit: Option<usize>, after: Option<&str>) -> Result<Self, WindowError> {
        let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(WindowError::PageLimit);
        }
        let after = after.filter(|cursor| !cursor.is_empty()).map(str::to_owned);
        Ok(Self { limit, after })
    }

    /// Returns the page size.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the cursor id.
    ///
    /// `None` starts at the first page.
    pub fn after(&self) -> Option<&str> {
        self.after.as_deref()
    }
}

/// A value that an in-memory entity search compares.
///
/// The variants cover the shared attribute types that need no dependency.
/// A float compares with `PartialEq`, so two NaN values do not match.
#[derive(Debug, Clone, PartialEq)]
pub enum SearchValue {
    /// A UTF-8 string.
    String(String),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A 64-bit floating point number.
    Float(f64),
    /// A boolean.
    Boolean(bool),
    /// A Unix timestamp in seconds.
    Timestamp(i64),
    /// A reference to another entity id.
    EntityRef(String),
}

/// One entity in an in-memory replica view.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SearchEntity<'a> {
    /// The entity id.
    pub id: &'a str,
    /// The attribute name and value pairs that the search reads.
    pub attributes: &'a [(&'a str, SearchValue)],
}

/// One page of an in-memory entity search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPage<'a> {
    /// The matching entity ids, sorted by id.
    pub ids: Vec<&'a str>,
    /// The id for the next page when more matches remain.
    ///
    /// The value is the last id on this page.
    /// `None` means that the search is complete.
    pub next: Option<&'a str>,
}

/// Searches a slice of entities for one indexed attribute value.
///
/// The call keeps each entity with an exact attribute match.
/// It keeps only ids above the cursor id.
/// It removes duplicate ids.
/// It returns the first `window.limit()` ids in id order.
///
/// The call keeps at most `window.limit() + 1` ids in a sorted set while it
/// scans. It does not sort the full match set.
///
/// The caller must pass an attribute that the replica index covers.
/// This function cannot check the index.
pub fn search_by_attribute<'a>(
    entities: &'a [SearchEntity<'a>],
    attribute: &str,
    value: &SearchValue,
    window: &QueryWindow,
) -> SearchPage<'a> {
    let limit = window.limit();
    let cursor = window.after();
    let mut selected: BTreeSet<&'a str> = BTreeSet::new();
    for entity in entities {
        let matches = entity
            .attributes
            .iter()
            .any(|(name, candidate)| *name == attribute && candidate == value);
        if !matches || cursor.is_some_and(|after| entity.id <= after) {
            continue;
        }
        // A full buffer holds the smallest `limit + 1` ids. An id at or
        // above the largest id cannot join that set.
        if selected.len() > limit && selected.last().is_some_and(|last| entity.id >= *last) {
            continue;
        }
        selected.insert(entity.id);
        if selected.len() > limit.saturating_add(1) {
            selected.pop_last();
        }
    }
    let has_more = selected.len() > limit;
    let ids: Vec<&'a str> = selected.into_iter().take(limit).collect();
    let next = if has_more { ids.last().copied() } else { None };
    SearchPage { ids, next }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one string value.
    fn string(value: &str) -> SearchValue {
        SearchValue::String(value.to_string())
    }

    /// A missing limit uses the default page size.
    #[test]
    fn the_default_window_uses_the_default_limit() {
        let window = QueryWindow::resolve(None, None).expect("the default window is valid");

        assert_eq!(window.limit(), DEFAULT_PAGE_LIMIT);
        assert_eq!(window.after(), None);
    }

    /// A page size at the maximum is valid.
    #[test]
    fn a_window_at_the_maximum_limit_is_valid() {
        let window =
            QueryWindow::resolve(Some(MAX_PAGE_LIMIT), None).expect("the maximum is valid");

        assert_eq!(window.limit(), MAX_PAGE_LIMIT);
    }

    /// A zero page size is not valid.
    #[test]
    fn a_zero_limit_is_not_valid() {
        let error = QueryWindow::resolve(Some(0), None).expect_err("zero is not valid");

        assert_eq!(error, WindowError::PageLimit);
        assert_eq!(error.to_string(), "limit must be between 1 and 200");
    }

    /// A page size above the maximum is not valid.
    #[test]
    fn a_limit_above_the_maximum_is_not_valid() {
        let error =
            QueryWindow::resolve(Some(MAX_PAGE_LIMIT + 1), None).expect_err("the limit is high");

        assert_eq!(error, WindowError::PageLimit);
    }

    /// An empty cursor is the first page.
    #[test]
    fn an_empty_cursor_is_the_first_page() {
        let window = QueryWindow::resolve(None, Some("")).expect("the window is valid");

        assert_eq!(window.after(), None);
    }

    /// A non-empty cursor is kept.
    #[test]
    fn a_non_empty_cursor_is_kept() {
        let window = QueryWindow::resolve(None, Some("e1")).expect("the window is valid");

        assert_eq!(window.after(), Some("e1"));
    }

    /// The empty view returns an empty page.
    #[test]
    fn the_empty_view_returns_an_empty_page() {
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&[], "tag", &string("alpha"), &window);

        assert!(page.ids.is_empty());
        assert_eq!(page.next, None);
    }

    /// A matching attribute returns its entity id.
    #[test]
    fn a_matching_attribute_returns_its_entity() {
        let attributes = [("tag", string("alpha"))];
        let entities = [SearchEntity {
            id: "e1",
            attributes: &attributes,
        }];
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1"]);
        assert_eq!(page.next, None);
    }

    /// A different value does not match.
    #[test]
    fn a_different_value_does_not_match() {
        let attributes = [("tag", string("alpha"))];
        let entities = [SearchEntity {
            id: "e1",
            attributes: &attributes,
        }];
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("beta"), &window);

        assert!(page.ids.is_empty());
        assert_eq!(page.next, None);
    }

    /// A missing attribute does not match.
    #[test]
    fn a_missing_attribute_does_not_match() {
        let attributes = [("kind", string("alpha"))];
        let entities = [SearchEntity {
            id: "e1",
            attributes: &attributes,
        }];
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert!(page.ids.is_empty());
        assert_eq!(page.next, None);
    }

    /// A typed value matches exactly.
    #[test]
    fn an_integer_value_matches() {
        let attributes = [("count", SearchValue::Integer(7))];
        let entities = [SearchEntity {
            id: "e1",
            attributes: &attributes,
        }];
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&entities, "count", &SearchValue::Integer(7), &window);

        assert_eq!(page.ids, ["e1"]);
    }

    /// A full page reports the last id as the cursor.
    #[test]
    fn a_full_page_reports_the_last_id_as_the_cursor() {
        let first = [("tag", string("alpha"))];
        let entities = [
            SearchEntity {
                id: "e1",
                attributes: &first,
            },
            SearchEntity {
                id: "e2",
                attributes: &first,
            },
            SearchEntity {
                id: "e3",
                attributes: &first,
            },
        ];
        let window = QueryWindow::resolve(Some(2), None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1", "e2"]);
        assert_eq!(page.next, Some("e2"));

        let window = QueryWindow::resolve(Some(2), page.next).expect("the window is valid");
        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e3"]);
        assert_eq!(page.next, None);
    }

    /// A page that holds every match has no cursor.
    #[test]
    fn a_page_at_the_limit_has_no_cursor() {
        let attributes = [("tag", string("alpha"))];
        let entities = [
            SearchEntity {
                id: "e1",
                attributes: &attributes,
            },
            SearchEntity {
                id: "e2",
                attributes: &attributes,
            },
        ];
        let window = QueryWindow::resolve(Some(2), None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1", "e2"]);
        assert_eq!(page.next, None);
    }

    /// A cursor skips ids at or below it.
    #[test]
    fn a_cursor_skips_ids_at_or_below_it() {
        let attributes = [("tag", string("alpha"))];
        let entities = [
            SearchEntity {
                id: "e1",
                attributes: &attributes,
            },
            SearchEntity {
                id: "e2",
                attributes: &attributes,
            },
        ];
        let window = QueryWindow::resolve(None, Some("e1")).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e2"]);
        assert_eq!(page.next, None);
    }

    /// The result holds one copy of a repeated id.
    #[test]
    fn a_repeated_id_appears_one_time() {
        let first = [("tag", string("alpha"))];
        let second = [("tag", string("alpha"))];
        let entities = [
            SearchEntity {
                id: "e1",
                attributes: &first,
            },
            SearchEntity {
                id: "e1",
                attributes: &second,
            },
        ];
        let window = QueryWindow::resolve(None, None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1"]);
        assert_eq!(page.next, None);
    }

    /// Many matches with a small page return the first ids in id order.
    #[test]
    fn many_matches_with_a_small_page_return_the_first_ids() {
        let ids: Vec<String> = (1..=50).rev().map(|n| format!("e{n:02}")).collect();
        let attributes = [("tag", string("alpha"))];
        let entities: Vec<SearchEntity<'_>> = ids
            .iter()
            .map(|id| SearchEntity {
                id: id.as_str(),
                attributes: &attributes,
            })
            .collect();
        let window = QueryWindow::resolve(Some(3), None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e01", "e02", "e03"]);
        assert_eq!(page.next, Some("e03"));
    }

    /// A cursor in the middle returns the next ids in id order.
    #[test]
    fn a_cursor_in_the_middle_returns_the_next_ids() {
        let ids: Vec<String> = (1..=10).rev().map(|n| format!("e{n:02}")).collect();
        let attributes = [("tag", string("alpha"))];
        let entities: Vec<SearchEntity<'_>> = ids
            .iter()
            .map(|id| SearchEntity {
                id: id.as_str(),
                attributes: &attributes,
            })
            .collect();
        let window = QueryWindow::resolve(Some(3), Some("e04")).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e05", "e06", "e07"]);
        assert_eq!(page.next, Some("e07"));
    }

    /// Repeated ids do not use page slots or count as more matches.
    #[test]
    fn repeated_ids_do_not_use_page_slots() {
        let attributes = [("tag", string("alpha"))];
        let ids = ["e1", "e1", "e2", "e2", "e3", "e3", "e4"];
        let entities: Vec<SearchEntity<'_>> = ids
            .iter()
            .map(|id| SearchEntity {
                id,
                attributes: &attributes,
            })
            .collect();
        let window = QueryWindow::resolve(Some(2), None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1", "e2"]);
        assert_eq!(page.next, Some("e2"));
    }

    /// A page larger than the match set has no cursor.
    #[test]
    fn a_page_larger_than_the_match_set_has_no_cursor() {
        let attributes = [("tag", string("alpha"))];
        let entities = [
            SearchEntity {
                id: "e1",
                attributes: &attributes,
            },
            SearchEntity {
                id: "e2",
                attributes: &attributes,
            },
            SearchEntity {
                id: "e3",
                attributes: &attributes,
            },
        ];
        let window = QueryWindow::resolve(Some(10), None).expect("the window is valid");

        let page = search_by_attribute(&entities, "tag", &string("alpha"), &window);

        assert_eq!(page.ids, ["e1", "e2", "e3"]);
        assert_eq!(page.next, None);
    }
}
