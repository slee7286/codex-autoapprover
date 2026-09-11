//! Distribution-update building blocks.
//!
//! M1-T1 intentionally stops at descriptive release-manifest parsing. M1-T3
//! adds only the type boundary that keeps parsed metadata separate from a
//! future TUF-authenticated value. Network fetching, real TUF verification,
//! state, and activation belong to later roadmap milestones.

// The schema is an intentional interface seam for later updater milestones;
// runtime fetching and selection do not consume it until those milestones land.
#[allow(dead_code)]
pub(crate) mod manifest;

// The production verifier is intentionally deferred to M5-T2; this module has
// no production constructor and exposes only a test-only synthetic seam.
#[allow(dead_code)]
pub(crate) mod verify;

// State storage and check coordination are local-only primitives. They do not
// perform network checks, TUF verification, installation, prompting, or hook
// authorization.
#[allow(dead_code)]
pub(crate) mod state;

// Session outcomes are fixed-category local observations. They are not
// compatibility registry entries and cannot arm or authorize a hook.
pub(crate) mod outcome;

// Selection is a pure interface seam for later startup-check work; it is not
// called by the existing launcher until the subsequent updater milestones.
#[allow(dead_code)]
pub(crate) mod selection;
