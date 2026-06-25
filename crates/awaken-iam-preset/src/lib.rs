//! Anthropic Claude-platform policy presets for Awaken IAM.
//!
//! The kernel in [`awaken_iam_core`] is product-neutral: it evaluates whatever
//! [`PolicySet`](awaken_iam_core::PolicySet) of grants, roles, and resource
//! models a deployment installs, and never names a tenant. This crate is the
//! companion **policy data** — the specific role catalog and consumer
//! namespaces of the Anthropic Claude platform, expressed as plain data the
//! core mechanism consumes.
//!
//! Keeping these here rather than in the kernel is the policy/mechanism split
//! (ADR-0002 #3): a different deployment ships a different preset crate (or
//! builds its catalog inline) without touching the engine, and the engine has
//! no built-in knowledge of any one product's roles.
//!
//! - [`role_catalog`] — the seeded named-role catalog (`admin`, `developer`,
//!   the workspace roles, …), the awaken-runtime preset roles, and their
//!   [`seed_named_roles`] / [`seed_runtime_roles`] loaders.
//! - [`consumers`] — the [`managed_agents`], [`oversight`], and
//!   [`awaken_runtime`] consumer namespace declarations from ADR-0008
//!   decision 8.

mod consumers;
mod role_catalog;

pub use consumers::{
    AWAKEN_RUNTIME_NAMESPACES, MANAGED_AGENTS_NAMESPACES, OVERSIGHT_NAMESPACES, awaken_runtime,
    managed_agents, oversight,
};
pub use role_catalog::{
    ANTHROPIC_ROLE_IDS, AWAKEN_RUNTIME_ROLE_IDS, ROLE_NAMESPACES, named_role_catalog,
    runtime_role_catalog, seed_named_roles, seed_runtime_roles,
};
