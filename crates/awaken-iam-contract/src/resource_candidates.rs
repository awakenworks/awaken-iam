//! Scoped read candidates are positive supersets, never authorization decisions.
use crate::{
    AuthorizationAccess, AuthorizationOutcome, AuthorizationRequest, PrincipalRef,
    ResourceAuthorizationRequest,
};
use serde::{Deserialize, Serialize};

pub const RESOURCE_AUTHORIZATION_BATCH_MAX: usize = 256;
pub const RESOURCE_AUTHORIZATION_CHAIN_MAX: usize = 32;
pub const RESOURCE_CANDIDATE_NODE_MAX: usize = 1024;
pub const RESOURCE_CANDIDATE_VALUE_MAX: usize = 4096;

/// Personal consent is a distinct verified credential family. These new scoped
/// capabilities explicitly reject that mode; an ordinary principal chain cannot
/// substitute for consent or silently select a legacy endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAuthorizationMode {
    Scoped,
    PersonalDelegation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAuthorizationBatchRequest {
    pub mode: ResourceAuthorizationMode,
    /// Ordered questions from one verified caller/delegation chain, one
    /// Workspace and one namespace. Exact physical owner scopes stay per item.
    pub requests: Vec<ResourceAuthorizationRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAuthorizationBatchEvaluation {
    pub outcomes: Vec<AuthorizationOutcome>,
    /// The same native freshness domain as single/current PDP evaluations.
    /// A changing fence fails the entire batch without returning partial results.
    pub freshness: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCandidateRequest {
    pub mode: ResourceAuthorizationMode,
    /// Scope is the actual operation owner's Workspace/Project scope, not a
    /// presentation Project inferred from where a Resource happens to be read.
    pub request: AuthorizationRequest,
    pub resource_type: Option<String>,
    pub access: AuthorizationAccess,
}

/// No negation, product data, resource inventory, executable expression or
/// caller-supplied policy. Resource ids originate only in native binding limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceCandidatePredicate {
    All,
    None,
    OwnerIn {
        principals: Vec<PrincipalRef>,
    },
    ResponsibleIn {
        principals: Vec<PrincipalRef>,
    },
    GroupAny {
        groups: Vec<String>,
    },
    /// Match current identity OR an owner-proved immutable predecessor at the
    /// same physical scope. Ignoring predecessors would exclude native Allows.
    ResourceIdsOrPredecessors {
        resource_ids: Vec<String>,
    },
    And {
        predicates: Vec<Self>,
    },
    Or {
        predicates: Vec<Self>,
    },
}

impl<'de> Deserialize<'de> for ResourceCandidatePredicate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Internally tagged Serde unit variants discard extra fields even with
        // deny_unknown_fields. Empty *struct* variants close All/None without
        // changing the public enum or its established serialized shape.
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            All {},
            None {},
            OwnerIn {
                principals: Vec<PrincipalRef>,
            },
            ResponsibleIn {
                principals: Vec<PrincipalRef>,
            },
            GroupAny {
                groups: Vec<String>,
            },
            ResourceIdsOrPredecessors {
                resource_ids: Vec<String>,
            },
            And {
                predicates: Vec<ResourceCandidatePredicate>,
            },
            Or {
                predicates: Vec<ResourceCandidatePredicate>,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::All {} => Self::All,
            Wire::None {} => Self::None,
            Wire::OwnerIn { principals } => Self::OwnerIn { principals },
            Wire::ResponsibleIn { principals } => Self::ResponsibleIn { principals },
            Wire::GroupAny { groups } => Self::GroupAny { groups },
            Wire::ResourceIdsOrPredecessors { resource_ids } => {
                Self::ResourceIdsOrPredecessors { resource_ids }
            }
            Wire::And { predicates } => Self::And { predicates },
            Wire::Or { predicates } => Self::Or { predicates },
        })
    }
}

impl ResourceCandidatePredicate {
    /// Bounded wire validation, independent of product facts and PDP decisions.
    pub fn within_limits(&self) -> bool {
        let mut pending = vec![self];
        let (mut nodes, mut values) = (0usize, 0usize);
        while let Some(predicate) = pending.pop() {
            nodes += 1;
            if nodes > RESOURCE_CANDIDATE_NODE_MAX {
                return false;
            }
            let count = match predicate {
                Self::OwnerIn { principals } | Self::ResponsibleIn { principals } => {
                    if principals.len() > RESOURCE_CANDIDATE_VALUE_MAX
                        || principals.iter().any(|principal| {
                            let value = match principal {
                                PrincipalRef::Account { account_id } => &account_id.0,
                                PrincipalRef::Service { service_id } => service_id,
                                PrincipalRef::ApiToken { token_id } => token_id,
                            };
                            value.len() > 512 || value.chars().any(char::is_control)
                        })
                    {
                        return false;
                    }
                    principals.len()
                }
                Self::GroupAny { groups: items }
                | Self::ResourceIdsOrPredecessors {
                    resource_ids: items,
                } => {
                    if items.len() > RESOURCE_CANDIDATE_VALUE_MAX
                        || items
                            .iter()
                            .any(|value| value.len() > 512 || value.chars().any(char::is_control))
                    {
                        return false;
                    }
                    items.len()
                }
                Self::And { predicates } | Self::Or { predicates } => {
                    if nodes
                        .saturating_add(pending.len())
                        .saturating_add(predicates.len())
                        > RESOURCE_CANDIDATE_NODE_MAX
                    {
                        return false;
                    }
                    pending.extend(predicates);
                    0
                }
                Self::All | Self::None => 0,
            };
            values = values.saturating_add(count);
            if values > RESOURCE_CANDIDATE_VALUE_MAX {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCandidateReason {
    DenyDeferred,
    ApprovalDeferred,
    ExpiryDeferred,
    ComplexGrantConstraint,
    PlanBudgetExceeded,
    NativeCeilingsDeferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCandidatePlan {
    pub predicate: ResourceCandidatePredicate,
    pub broadening_reasons: Vec<ResourceCandidateReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCandidateEvaluation {
    pub plan: ResourceCandidatePlan,
    pub freshness: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_predicates_refuse_unknown_operators_and_limits_bound_nested_payloads() {
        assert!(
            serde_json::from_str::<ResourceCandidatePredicate>(
                r#"{"kind":"not","predicate":{"kind":"all"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<ResourceCandidatePredicate>(
                r#"{"kind":"all","execute":"private-policy"}"#
            )
            .is_err()
        );
        for invalid in [
            r#"{"kind":"none","execute":"private-policy"}"#,
            r#"{"kind":"and","predicates":[{"kind":"all","execute":"private-policy"}]}"#,
            r#"{"kind":"or","predicates":[{"kind":"none","execute":"private-policy"}]}"#,
        ] {
            assert!(serde_json::from_str::<ResourceCandidatePredicate>(invalid).is_err());
        }
        for predicate in [
            ResourceCandidatePredicate::All,
            ResourceCandidatePredicate::None,
            ResourceCandidatePredicate::And {
                predicates: vec![
                    ResourceCandidatePredicate::All,
                    ResourceCandidatePredicate::None,
                ],
            },
        ] {
            let encoded = serde_json::to_value(&predicate).unwrap();
            assert_eq!(
                serde_json::from_value::<ResourceCandidatePredicate>(encoded).unwrap(),
                predicate
            );
        }
        let within = ResourceCandidatePredicate::ResourceIdsOrPredecessors {
            resource_ids: vec!["one".into(); RESOURCE_CANDIDATE_VALUE_MAX],
        };
        assert!(within.within_limits());
        let excessive = ResourceCandidatePredicate::And {
            predicates: vec![within.clone(), within],
        };
        assert!(!excessive.within_limits());
        assert!(
            !ResourceCandidatePredicate::Or {
                predicates: vec![ResourceCandidatePredicate::None; RESOURCE_CANDIDATE_NODE_MAX]
            }
            .within_limits()
        );
    }
}
