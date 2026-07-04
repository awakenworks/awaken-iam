//! Problem+JSON API error type.
//!
//! [`ApiError`] is the guard's wire error shape. Products convert an
//! [`Enforcement`](crate::Enforcement) to one at their HTTP boundary and render
//! it as a problem+JSON response (`Content-Type: application/problem+json`,
//! RFC 7807). The `to_ai_sdk` / `to_ag_ui` aliases are dialect shims: both
//! currently resolve to the same structure; a future dialect tweak is additive.

use serde::{Deserialize, Serialize};

/// Problem+JSON error (RFC 7807) returned at product HTTP boundaries when IAM
/// denies or requires approval for an action.
///
/// Construct via [`Enforcement::into_api_error`](crate::Enforcement::into_api_error)
/// rather than building this struct directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// A URI reference that identifies the problem type.
    pub r#type: String,
    /// Short, human-readable summary of the problem.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    pub detail: String,
}

impl ApiError {
    /// Render this error as a compact JSON string (the problem+JSON body).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"type":"{}","title":"{}","status":{},"detail":"{}"}}"#,
                self.r#type, self.title, self.status, self.detail
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_serializes_to_problem_json() {
        let err = ApiError {
            r#type: "https://iam.example/problems/forbidden".into(),
            title: "Forbidden".into(),
            status: 403,
            detail: "The principal does not hold a grant for this action.".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["status"], 403);
        assert_eq!(json["title"], "Forbidden");
        assert!(json["type"].as_str().unwrap().contains("forbidden"));
        assert!(!json.get("detail").unwrap().as_str().unwrap().is_empty());
    }

    #[test]
    fn to_json_produces_compact_string() {
        let err = ApiError {
            r#type: "https://iam.example/problems/forbidden".into(),
            title: "Forbidden".into(),
            status: 403,
            detail: "denied".into(),
        };
        let s = err.to_json();
        assert!(s.contains("403"));
        assert!(s.contains("Forbidden"));
    }
}
