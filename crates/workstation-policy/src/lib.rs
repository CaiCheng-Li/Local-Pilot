//! Local Pilot policy layer: path canonicalization, protected resources,
//! command classification, the filesystem broker and the central evaluator.

pub mod attribution;
pub mod broker;
pub mod classify;
pub mod command;
pub mod evaluator;
pub mod protected;
pub mod winfs;
pub mod winpath;

pub use classify::{CacheArea, PathClass, Roots};
pub use evaluator::{
    ApprovalRequirement, Decision, EntryPoint, FsAccess, GitFacts, PolicyContext, PolicyEngine,
    Risk, SessionScope,
};
pub use winpath::{Canonical, ExpandEnv};
