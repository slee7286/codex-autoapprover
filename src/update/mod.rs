//! Distribution-update building blocks.
//!
//! M1-T1 intentionally stops at descriptive release-manifest parsing. Network
//! fetching, TUF verification, selection, state, and activation belong to
//! later roadmap milestones.

// The schema is an intentional interface seam for later updater milestones;
// runtime fetching and selection do not consume it until those milestones land.
#[allow(dead_code)]
pub(crate) mod manifest;
